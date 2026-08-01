package jenkins

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// certMaterial holds generated PEMs for TLS tests (NET-004).
type certMaterial struct {
	CACertPEM     []byte
	CAKeyPEM      []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	WrongCACert   []byte // different CA that does not sign the server
}

func generateTestCerts(t *testing.T, serverHosts []string) certMaterial {
	t.Helper()
	now := time.Now().Add(-time.Hour)

	// Root CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong CA (unrelated)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "wrong-ca"},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	wrongDER, err := x509.CreateCertificate(rand.Reader, wrongTmpl, wrongTmpl, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatal(err)
	}

	// Server cert
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range serverHosts {
		if ip := net.ParseIP(h); ip != nil {
			srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, ip)
		} else {
			srvTmpl.DNSNames = append(srvTmpl.DNSNames, h)
		}
	}
	// Always include loopback for httptest.
	srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Client cert (mTLS)
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caTmpl, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return certMaterial{
		CACertPEM:     pemEncode("CERTIFICATE", caDER),
		CAKeyPEM:      pemEncodeEC(caKey),
		ServerCertPEM: pemEncode("CERTIFICATE", srvDER),
		ServerKeyPEM:  pemEncodeEC(srvKey),
		ClientCertPEM: pemEncode("CERTIFICATE", cliDER),
		ClientKeyPEM:  pemEncodeEC(cliKey),
		WrongCACert:   pemEncode("CERTIFICATE", wrongDER),
	}
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func pemEncodeEC(key *ecdsa.PrivateKey) []byte {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

func writePEMPair(t *testing.T, dir, certName, keyName string, certPEM, keyPEM []byte) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, certName)
	keyPath = filepath.Join(dir, keyName)
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func startTLSServer(t *testing.T, mats certMaterial, requireClient bool) *httptest.Server {
	t.Helper()
	srvCert, err := tls.X509KeyPair(mats.ServerCertPEM, mats.ServerKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		MinVersion:   tls.VersionTLS12,
	}
	if requireClient {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(mats.CACertPEM) {
			t.Fatal("append client CA")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestCustomCA_TrustsServer(t *testing.T) {
	mats := generateTestCerts(t, nil)
	srv := startTLSServer(t, mats, false)

	cfg := DefaultTransportConfig()
	cfg.CABundlePEM = mats.CACertPEM
	cfg.APIClientTimeout = 5 * time.Second
	// httptest uses random cert by default on StartTLS; we set our own via TLS field.
	// Client still sees 127.0.0.1 with our cert SANs.
	hc, err := NewHTTPClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.API.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("expected trust with custom CA: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestCustomCA_WrongCAFails(t *testing.T) {
	mats := generateTestCerts(t, nil)
	srv := startTLSServer(t, mats, false)

	cfg := DefaultTransportConfig()
	cfg.CABundlePEM = mats.WrongCACert
	cfg.APIClientTimeout = 5 * time.Second
	hc, err := NewHTTPClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hc.API.Get(srv.URL + "/")
	if err == nil {
		t.Fatal("expected TLS failure with wrong CA")
	}
	msg := FormatTLSError(err)
	if msg == "" {
		t.Fatal("FormatTLSError empty")
	}
	if strings.Contains(strings.ToLower(msg), "insecure-skip") && !strings.Contains(msg, "Do not disable") {
		t.Fatalf("should not promote permanent skip: %s", msg)
	}
	if !strings.Contains(msg, "Do not disable certificate verification") &&
		!strings.Contains(msg, "Do not disable") {
		// FormatTLSError always steers away from permanent disablement for x509 errors.
		if !strings.Contains(strings.ToLower(msg), "trusted ca") &&
			!strings.Contains(strings.ToLower(msg), "certificate") {
			t.Fatalf("unexpected diagnostic: %s", msg)
		}
	}
	// Regression: never suggest leaving verification permanently off as the fix.
	if strings.Contains(strings.ToLower(msg), "set insecure") {
		t.Fatalf("bad suggestion: %s", msg)
	}
}

func TestCustomCA_FromFilePath(t *testing.T) {
	mats := generateTestCerts(t, nil)
	srv := startTLSServer(t, mats, false)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, mats.CACertPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultTransportConfig()
	cfg.CABundlePath = caPath
	hc, err := NewHTTPClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.API.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestMTLS_RequiresClientCert(t *testing.T) {
	mats := generateTestCerts(t, nil)
	srv := startTLSServer(t, mats, true)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, mats.CACertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writePEMPair(t, dir, "client.crt", "client.key", mats.ClientCertPEM, mats.ClientKeyPEM)

	// Without client cert → fail.
	cfgFail := DefaultTransportConfig()
	cfgFail.CABundlePath = caPath
	hcFail, err := NewHTTPClients(cfgFail)
	if err != nil {
		t.Fatal(err)
	}
	_, err = hcFail.API.Get(srv.URL + "/")
	if err == nil {
		t.Fatal("expected failure without client cert")
	}

	// With client cert → success.
	cfgOK := DefaultTransportConfig()
	cfgOK.CABundlePath = caPath
	cfgOK.ClientCertFile = certPath
	cfgOK.ClientKeyFile = keyPath
	hcOK, err := NewHTTPClients(cfgOK)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hcOK.API.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("mTLS client should succeed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`ok`)) {
		t.Fatalf("body %s", body)
	}
}

func TestMTLS_MissingKeyFileErrors(t *testing.T) {
	cfg := DefaultTransportConfig()
	cfg.ClientCertFile = "/tmp/no-such-cert.pem"
	// key missing
	_, err := NewHTTPClients(cfg)
	if err == nil {
		t.Fatal("expected error for incomplete mTLS pair")
	}
	if !strings.Contains(err.Error(), "ClientCertFile") && !strings.Contains(err.Error(), "ClientKeyFile") {
		t.Fatalf("error should mention mTLS pair: %v", err)
	}
}

// Regression: mTLS load failures must never include private key PEM bytes.
func TestMTLS_ErrorDoesNotLeakKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	const canary = "CANARY_PRIVATE_KEY_MATERIAL_mtls_must_not_leak_xyz"
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	// Invalid cert PEM; key file contains the canary so a naive dump would leak it.
	if err := os.WriteFile(certPath, []byte("not-a-pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(canary+"\n-----BEGIN EC PRIVATE KEY-----\n"+canary+"\n-----END EC PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultTransportConfig()
	cfg.ClientCertFile = certPath
	cfg.ClientKeyFile = keyPath
	_, err := NewHTTPClients(cfg)
	if err == nil {
		t.Fatal("expected load failure")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("private key canary leaked in error: %v", err)
	}
	// Path may appear; full key body must not.
	if strings.Contains(err.Error(), "BEGIN EC PRIVATE KEY") {
		t.Fatalf("PEM header leaked: %v", err)
	}
}

func TestProxyURL_UsedByTransport(t *testing.T) {
	// Destination server (plain HTTP).
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("dest-ok"))
	}))
	t.Cleanup(dest.Close)

	var sawProxy int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProxy++
		// Absolute-form request to proxy for HTTP.
		if r.Method == http.MethodConnect {
			// HTTPS not used in this test.
			http.Error(w, "no connect", 500)
			return
		}
		// Forward by serving a marker so we know proxy was hit.
		// For simplicity respond ourselves instead of full reverse-proxy.
		_, _ = w.Write([]byte("via-proxy"))
	}))
	t.Cleanup(proxy.Close)

	cfg := DefaultTransportConfig()
	cfg.ProxyURL = proxy.URL
	cfg.APIClientTimeout = 5 * time.Second
	hc, err := NewHTTPClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.API.Get(dest.URL + "/job/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "via-proxy" {
		t.Fatalf("body=%q sawProxy=%d", body, sawProxy)
	}
	if sawProxy < 1 {
		t.Fatal("proxy was not used")
	}
}

func TestProxy_NoProxyBypass(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	t.Cleanup(dest.Close)

	var sawProxy int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProxy++
		_, _ = w.Write([]byte("proxied"))
	}))
	t.Cleanup(proxy.Close)

	u, err := url.Parse(dest.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()

	cfg := DefaultTransportConfig()
	cfg.ProxyURL = proxy.URL
	cfg.NoProxy = []string{host}
	hc, err := NewHTTPClients(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.API.Get(dest.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "direct" {
		t.Fatalf("want direct bypass, got %q (proxy hits=%d)", body, sawProxy)
	}
	if sawProxy != 0 {
		t.Fatalf("proxy should not be hit, hits=%d", sawProxy)
	}
}

func TestProxy_DirectDisablesEnv(t *testing.T) {
	cfg := DefaultTransportConfig()
	cfg.ProxyURL = "direct"
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Proxy func should return nil (no proxy).
	u, err := tr.Proxy(&http.Request{URL: mustURL(t, "https://jenkins.example.com/api")})
	if err != nil {
		t.Fatal(err)
	}
	if u != nil {
		t.Fatalf("direct should disable proxy, got %v", u)
	}
}

func TestDiagnosticInsecureTLS_RequiresEnv(t *testing.T) {
	t.Setenv(EnvDiagInsecureTLS, "")
	cfg := DefaultTransportConfig()
	cfg.DiagnosticInsecureTLS = true
	gated := ApplyInsecureTLSGate(cfg, os.Getenv)
	if gated.DiagnosticInsecureTLS {
		t.Fatal("gate must clear DiagnosticInsecureTLS without env=1")
	}
	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("must not skip verify without env")
	}
}

func TestDiagnosticInsecureTLS_WithEnv(t *testing.T) {
	t.Setenv(EnvDiagInsecureTLS, "1")
	var logs bytes.Buffer
	cfg := DefaultTransportConfig()
	cfg.DiagnosticInsecureTLS = true
	cfg.Logger = logWriter{&logs}

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("want InsecureSkipVerify when env=1 and flag set")
	}
	if !strings.Contains(logs.String(), "WARNING") || !strings.Contains(logs.String(), "DISABLED") {
		t.Fatalf("expected loud warning, got %q", logs.String())
	}
}

type logWriter struct{ b *bytes.Buffer }

func (l logWriter) Printf(format string, v ...any) {
	fmt.Fprintf(l.b, format, v...)
}

func TestFormatTLSError_NoPermanentDisableSuggestion(t *testing.T) {
	// UnknownAuthorityError
	err := x509.UnknownAuthorityError{}
	msg := FormatTLSError(err)
	if !strings.Contains(msg, "Do not disable certificate verification") {
		t.Fatalf("msg=%s", msg)
	}
	if strings.Contains(strings.ToLower(msg), "insecure-skip-verify as default") {
		t.Fatal(msg)
	}
}

func TestHostMatchesNoProxy(t *testing.T) {
	cases := []struct {
		host string
		list []string
		want bool
	}{
		{"jenkins.example.com", []string{"jenkins.example.com"}, true},
		{"jenkins.example.com:443", []string{"jenkins.example.com"}, true},
		{"foo.example.com", []string{".example.com"}, true},
		{"example.com", []string{".example.com"}, true},
		{"other.com", []string{".example.com"}, false},
		{"anything", []string{"*"}, true},
		{"a.b.c", []string{"b.c"}, true},
		{"evilb.c", []string{"b.c"}, false}, // must not match without dot boundary — wait, HasSuffix(".b.c")?
	}
	for _, tc := range cases {
		got := hostMatchesNoProxy(tc.host, tc.list)
		if got != tc.want {
			t.Errorf("host=%q list=%v got %v want %v", tc.host, tc.list, got, tc.want)
		}
	}
}

func TestDefaultConfig_NoInsecure(t *testing.T) {
	cfg := DefaultTransportConfig()
	if cfg.DiagnosticInsecureTLS {
		t.Fatal("default DiagnosticInsecureTLS must be false")
	}
	if cfg.CABundlePath != "" || len(cfg.CABundlePEM) != 0 {
		t.Fatal("default must not set custom CA")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
