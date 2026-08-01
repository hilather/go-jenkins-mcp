package jenkins

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Default transport timeouts and pool sizes (NET-002).
const (
	defaultMaxIdleConns        = 100
	defaultMaxIdleConnsPerHost = 10
	defaultIdleConnTimeout     = 90 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultResponseHeaderTO    = 30 * time.Second
	defaultExpectContinueTO    = 1 * time.Second
	defaultDialTimeout         = 10 * time.Second
	defaultKeepAlive           = 30 * time.Second
	defaultAPIClientTimeout    = 30 * time.Second
	defaultLogsClientTimeout   = 60 * time.Second
)

// EnvDiagInsecureTLS must be exactly "1" for DiagnosticInsecureTLS to take effect
// (NET-004). Profiles must never silently disable certificate verification.
const EnvDiagInsecureTLS = "JENKINS_MCP_DIAG_INSECURE_TLS"

// TransportConfig configures the shared enterprise http.Transport (NET-002 / NET-004).
//
// One Transport is shared by the API and logs http.Clients for connection reuse.
// Context cancellation is honored via DialContext and request context.
//
// Gzip: AcceptGzip is opt-in (default false). When false, DisableCompression is
// set so net/http does not transparently advertise or decode gzip — progressive
// log wire accounting (PERF-001) and compression-bomb resistance stay explicit.
// When true, requests advertise Accept-Encoding: gzip and responses are decoded
// with separate wire vs decoded byte counters (see ByteCounters).
//
// TLS/proxy (NET-004): system trust store by default; optional custom CA, proxy,
// proxy bypass, and client certificates (file path references only — never inline
// private keys in profile JSON). InsecureSkipVerify is never a production default.
type TransportConfig struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	DialTimeout           time.Duration
	KeepAlive             time.Duration
	// ForceAttemptHTTP2 enables HTTP/2 dial preference (Go default is true when
	// TLS is used; explicit for enterprise tuning/tests).
	ForceAttemptHTTP2 bool
	// AcceptGzip advertises gzip and measures decode. Default false (documented
	// residual: enable only after controller/proxy interoperability checks).
	AcceptGzip bool
	// APIClientTimeout is http.Client.Timeout for JSON/API calls (0 disables;
	// prefer request context deadlines in production).
	APIClientTimeout time.Duration
	// LogsClientTimeout is http.Client.Timeout for progressive log paths.
	LogsClientTimeout time.Duration
	// TLSMinVersion defaults to TLS 1.2 when zero.
	TLSMinVersion uint16
	// ByteCounters optional telemetry hook (never logs secrets).
	ByteCounters ByteCounters

	// --- NET-004: custom CA, proxy, mTLS, diagnostic insecure TLS ---

	// CABundlePath is an optional path to a PEM file of additional trusted CAs
	// (appended to the system pool). Empty = system trust only.
	CABundlePath string
	// CABundlePEM is optional PEM material of additional trusted CAs (tests /
	// programmatic callers). Appended after the system pool (and path, if set).
	// Never persist PEM private keys here; this is CA cert material only.
	CABundlePEM []byte
	// ProxyURL is an optional HTTP(S)/SOCKS5 proxy. Empty uses process environment
	// (HTTPS_PROXY / HTTP_PROXY / NO_PROXY). Values "direct" or "none" disable
	// proxying even when environment variables are set.
	ProxyURL string
	// NoProxy is a NO_PROXY-style host list (exact host, domain suffix, or "*").
	// Applied with an explicit ProxyURL, or as an extra bypass when using env proxy.
	NoProxy []string
	// ClientCertFile / ClientKeyFile are PEM path references for optional mTLS.
	// Private key material is loaded from disk only and never logged.
	ClientCertFile string
	ClientKeyFile  string
	// DiagnosticInsecureTLS requests TLS InsecureSkipVerify. Defaults false.
	// Effectively honored only when process env JENKINS_MCP_DIAG_INSECURE_TLS=1
	// (see ApplyInsecureTLSGate). Loudly logged when active. Never a silent
	// production or profile-persisted default.
	DiagnosticInsecureTLS bool
	// Logger receives loud warnings (diagnostic insecure TLS). nil → log.Printf.
	Logger interface {
		Printf(format string, v ...any)
	}
}

// DefaultTransportConfig returns production defaults for NET-002 / NET-004.
// TLS verification is always on; no custom CA/proxy/mTLS; diagnostic insecure off.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseHeaderTO,
		ExpectContinueTimeout: defaultExpectContinueTO,
		DialTimeout:           defaultDialTimeout,
		KeepAlive:             defaultKeepAlive,
		ForceAttemptHTTP2:     true,
		AcceptGzip:            false,
		APIClientTimeout:      defaultAPIClientTimeout,
		LogsClientTimeout:     defaultLogsClientTimeout,
		TLSMinVersion:         tls.VersionTLS12,
		DiagnosticInsecureTLS: false,
	}
}

// ByteCounters records encoded wire vs decoded response bytes (NET-002).
// Implementations must be safe for concurrent use and must not retain body content.
type ByteCounters interface {
	AddWireBytes(n int64)
	AddDecodedBytes(n int64)
}

// NopByteCounters discards counters (default).
type NopByteCounters struct{}

func (NopByteCounters) AddWireBytes(int64)    {}
func (NopByteCounters) AddDecodedBytes(int64) {}

// AtomicByteCounters is a simple process-local counter for tests and OBS wiring.
type AtomicByteCounters struct {
	Wire    atomic.Int64
	Decoded atomic.Int64
}

func (c *AtomicByteCounters) AddWireBytes(n int64) {
	if c != nil && n > 0 {
		c.Wire.Add(n)
	}
}

func (c *AtomicByteCounters) AddDecodedBytes(n int64) {
	if c != nil && n > 0 {
		c.Decoded.Add(n)
	}
}

// HTTPClients holds API and logs clients that share one Transport (NET-002).
type HTTPClients struct {
	API       *http.Client
	Logs      *http.Client
	Transport *http.Transport
	// AcceptGzip mirrors TransportConfig.AcceptGzip for request decoration.
	AcceptGzip bool
	Counters   ByteCounters
}

// NewHTTPClients builds enterprise-tuned http.Clients sharing one Transport.
func NewHTTPClients(cfg TransportConfig) (*HTTPClients, error) {
	cfg = normalizeTransportConfig(cfg)
	tr, err := NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	counters := cfg.ByteCounters
	if counters == nil {
		counters = NopByteCounters{}
	}
	return &HTTPClients{
		API: &http.Client{
			Transport: tr,
			Timeout:   cfg.APIClientTimeout,
		},
		Logs: &http.Client{
			Transport: tr,
			Timeout:   cfg.LogsClientTimeout,
		},
		Transport:  tr,
		AcceptGzip: cfg.AcceptGzip,
		Counters:   counters,
	}, nil
}

// NewTransport constructs a pooled http.Transport with explicit timeouts,
// TLS trust, proxy, and optional mTLS (NET-002 / NET-004).
func NewTransport(cfg TransportConfig) (*http.Transport, error) {
	cfg = normalizeTransportConfig(cfg)
	cfg = ApplyInsecureTLSGate(cfg, os.Getenv)

	tlsCfg, err := BuildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	proxyFn, err := buildProxyFunc(cfg)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: cfg.KeepAlive,
	}
	return &http.Transport{
		Proxy: proxyFn,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:     cfg.ForceAttemptHTTP2,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   cfg.TLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: cfg.ExpectContinueTimeout,
		// Always disable transparent gzip so Accept-Encoding / decode are explicit
		// (wire vs decoded counters; progressive log control).
		DisableCompression: true,
		TLSClientConfig:    tlsCfg,
	}, nil
}

// ApplyInsecureTLSGate clears DiagnosticInsecureTLS unless getenv(EnvDiagInsecureTLS)
// is exactly "1". Use when merging profile/CLI so a profile cannot silently disable
// verification. getenv nil defaults to os.Getenv.
func ApplyInsecureTLSGate(cfg TransportConfig, getenv func(string) string) TransportConfig {
	if !cfg.DiagnosticInsecureTLS {
		return cfg
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	if getenv(EnvDiagInsecureTLS) != "1" {
		cfg.DiagnosticInsecureTLS = false
	}
	return cfg
}

// BuildTLSConfig builds a tls.Config from system roots plus optional custom CA
// and client certificates (NET-004). Does not honor DiagnosticInsecureTLS unless
// the caller already passed ApplyInsecureTLSGate (NewTransport does both).
func BuildTLSConfig(cfg TransportConfig) (*tls.Config, error) {
	minVer := cfg.TLSMinVersion
	if minVer == 0 {
		minVer = tls.VersionTLS12
	}

	rootCAs, err := systemCertPool()
	if err != nil {
		return nil, err
	}

	if path := strings.TrimSpace(cfg.CABundlePath); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read CA bundle %q: %w", path, err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA bundle %q contains no valid certificates", path)
		}
	}
	if len(cfg.CABundlePEM) > 0 {
		if !rootCAs.AppendCertsFromPEM(cfg.CABundlePEM) {
			return nil, errors.New("CABundlePEM contains no valid certificates")
		}
	}

	tlsCfg := &tls.Config{
		MinVersion: minVer,
		RootCAs:    rootCAs,
	}

	certFile := strings.TrimSpace(cfg.ClientCertFile)
	keyFile := strings.TrimSpace(cfg.ClientKeyFile)
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("client mTLS requires both ClientCertFile and ClientKeyFile")
		}
		// LoadX509KeyPair reads PEM from disk; error text must not include key bytes.
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load mTLS client certificate (cert=%q): %w", certFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.DiagnosticInsecureTLS {
		tlsCfg.InsecureSkipVerify = true
		printf := log.Printf
		if cfg.Logger != nil {
			printf = cfg.Logger.Printf
		}
		printf("WARNING: DiagnosticInsecureTLS enabled (env %s=1) — TLS certificate verification is DISABLED. "+
			"Use only for short-lived local diagnosis; never enable as a production or profile default. "+
			"Fix the certificate chain / CA bundle instead of leaving verification off.",
			EnvDiagInsecureTLS)
	}

	return tlsCfg, nil
}

func systemCertPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		// Some environments lack a system store; start empty and require explicit CA.
		pool = x509.NewCertPool()
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	return pool, nil
}

// buildProxyFunc returns the Proxy function for http.Transport (NET-004).
func buildProxyFunc(cfg TransportConfig) (func(*http.Request) (*url.URL, error), error) {
	raw := strings.TrimSpace(cfg.ProxyURL)
	noProxy := normalizeNoProxy(cfg.NoProxy)

	// Explicit disable: ignore environment proxies.
	if strings.EqualFold(raw, "direct") || strings.EqualFold(raw, "none") {
		return func(*http.Request) (*url.URL, error) { return nil, nil }, nil
	}

	if raw == "" {
		if len(noProxy) == 0 {
			return http.ProxyFromEnvironment, nil
		}
		// Env proxy + profile NoProxy extra bypass.
		envProxy := http.ProxyFromEnvironment
		return func(req *http.Request) (*url.URL, error) {
			if req != nil && req.URL != nil && hostMatchesNoProxy(req.URL.Host, noProxy) {
				return nil, nil
			}
			return envProxy(req)
		}, nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return nil, fmt.Errorf("proxy URL scheme must be http, https, or socks5 (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("proxy URL must include a host")
	}
	// Do not log proxy userinfo (may contain credentials).
	proxyURL := u
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		if hostMatchesNoProxy(req.URL.Host, noProxy) {
			return nil, nil
		}
		return proxyURL, nil
	}, nil
}

func normalizeNoProxy(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		// Allow comma-separated entries inside a single slice element.
		for _, p := range strings.Split(e, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// hostMatchesNoProxy implements a small NO_PROXY-style matcher (host, .suffix, *).
func hostMatchesNoProxy(hostport string, noProxy []string) bool {
	if len(noProxy) == 0 {
		return false
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Strip IPv6 brackets if present without port.
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	for _, p := range noProxy {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		if strings.HasPrefix(p, ".") {
			// ".example.com" matches example.com and foo.example.com
			suffix := p
			bare := strings.TrimPrefix(p, ".")
			if host == bare || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

// FormatTLSError returns an operator-facing explanation of a TLS failure without
// suggesting permanent verification disablement (NET-004 acceptance).
func FormatTLSError(err error) string {
	if err == nil {
		return ""
	}
	// Walk the chain for well-known x509 errors.
	var (
		unknownAuth x509.UnknownAuthorityError
		hostname    x509.HostnameError
		invalid     x509.CertificateInvalidError
		sysRoots    x509.SystemRootsError
	)
	switch {
	case errors.As(err, &unknownAuth):
		return "TLS: certificate not signed by a trusted CA (system store or configured CA bundle). " +
			"Install/append the corporate CA with --ca-bundle or profile caBundlePath. " +
			"Do not disable certificate verification as a permanent fix."
	case errors.As(err, &hostname):
		return fmt.Sprintf("TLS: hostname mismatch for %q — ensure jenkinsURL host matches the certificate SAN/CN. "+
			"Do not disable certificate verification as a permanent fix.", hostname.Host)
	case errors.As(err, &invalid):
		return fmt.Sprintf("TLS: certificate invalid (%v). Check expiry, key usage, and chain order. "+
			"Do not disable certificate verification as a permanent fix.", invalid.Reason)
	case errors.As(err, &sysRoots):
		return "TLS: system certificate pool unavailable; provide an explicit CA bundle (--ca-bundle). " +
			"Do not disable certificate verification as a permanent fix."
	default:
		// Generic transport/TLS path.
		msg := err.Error()
		if strings.Contains(strings.ToLower(msg), "tls") || strings.Contains(strings.ToLower(msg), "x509") ||
			strings.Contains(strings.ToLower(msg), "certificate") {
			return "TLS handshake failed: " + msg + ". Verify the chain, hostname, and CA bundle. " +
				"Short-lived diagnosis only: JENKINS_MCP_DIAG_INSECURE_TLS=1 with an explicit diagnostic flag " +
				"(never a production or profile default)."
		}
		return msg
	}
}

func normalizeTransportConfig(cfg TransportConfig) TransportConfig {
	d := DefaultTransportConfig()
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = d.MaxIdleConns
	}
	if cfg.MaxIdleConnsPerHost <= 0 {
		cfg.MaxIdleConnsPerHost = d.MaxIdleConnsPerHost
	}
	if cfg.IdleConnTimeout <= 0 {
		cfg.IdleConnTimeout = d.IdleConnTimeout
	}
	if cfg.TLSHandshakeTimeout <= 0 {
		cfg.TLSHandshakeTimeout = d.TLSHandshakeTimeout
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = d.ResponseHeaderTimeout
	}
	if cfg.ExpectContinueTimeout <= 0 {
		cfg.ExpectContinueTimeout = d.ExpectContinueTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = d.DialTimeout
	}
	if cfg.KeepAlive <= 0 {
		cfg.KeepAlive = d.KeepAlive
	}
	// Timeouts of 0 on clients are allowed (caller uses context only). Negative → default.
	if cfg.APIClientTimeout < 0 {
		cfg.APIClientTimeout = d.APIClientTimeout
	}
	if cfg.LogsClientTimeout < 0 {
		cfg.LogsClientTimeout = d.LogsClientTimeout
	}
	if cfg.TLSMinVersion == 0 {
		cfg.TLSMinVersion = d.TLSMinVersion
	}
	return cfg
}

// countingReader counts bytes read via add.
type countingReader struct {
	r   io.Reader
	add func(int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.add != nil {
		c.add(int64(n))
	}
	return n, err
}

// wrapResponseBody applies optional gzip decode and byte counters (NET-002).
func wrapResponseBody(resp *http.Response, acceptGzip bool, counters ByteCounters) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	if counters == nil {
		counters = NopByteCounters{}
	}

	raw := resp.Body
	enc := resp.Header.Get("Content-Encoding")

	if acceptGzip && enc == "gzip" {
		wire := &countingReader{
			r: raw,
			add: func(n int64) {
				counters.AddWireBytes(n)
			},
		}
		gr, err := gzip.NewReader(wire)
		if err != nil {
			_ = raw.Close()
			return fmt.Errorf("gzip content-encoding: %w", err)
		}
		decoded := &countingReader{
			r: gr,
			add: func(n int64) {
				counters.AddDecodedBytes(n)
			},
		}
		resp.Body = &gzipReadCloser{r: decoded, gz: gr, raw: raw}
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Uncompressed = true
		return nil
	}

	// Identity encoding: wire bytes == decoded bytes.
	resp.Body = &countCloseReader{
		countingReader: countingReader{
			r: raw,
			add: func(n int64) {
				counters.AddWireBytes(n)
				counters.AddDecodedBytes(n)
			},
		},
		closer: raw,
	}
	return nil
}

type gzipReadCloser struct {
	r   io.Reader
	gz  *gzip.Reader
	raw io.Closer
}

func (g *gzipReadCloser) Read(p []byte) (int, error) {
	return g.r.Read(p)
}

func (g *gzipReadCloser) Close() error {
	err1 := g.gz.Close()
	err2 := g.raw.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

type countCloseReader struct {
	countingReader
	closer io.Closer
}

func (c *countCloseReader) Close() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}
