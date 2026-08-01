package mcpserver

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultMaxBodyBytes is the default request body cap for Streamable HTTP
// (4 MiB). Large tool results use MCP pagination / budgets; clients should not
// POST unbounded JSON-RPC bodies.
const DefaultMaxBodyBytes int64 = 4 << 20 // 4 MiB

// AbsoluteMaxBodyBytes is the process absolute fail-closed ceiling for the
// Streamable HTTP request body cap (Wave 44 Track C). Operators may raise
// --http-max-body-bytes / JENKINS_MCP_HTTP_MAX_BODY_BYTES above
// DefaultMaxBodyBytes, but never above this bound — multi-GB values are
// rejected at serve start (not clamped silently).
const AbsoluteMaxBodyBytes int64 = 16 << 20 // 16 MiB

// EnvHTTPMaxBodyBytes is the serve env for the Streamable HTTP request body
// cap (Wave 44 Track C). CLI --http-max-body-bytes overrides when set.
// Empty/0 → DefaultMaxBodyBytes. Invalid values and values above
// AbsoluteMaxBodyBytes fail closed at serve start.
const EnvHTTPMaxBodyBytes = "JENKINS_MCP_HTTP_MAX_BODY_BYTES"

// HeaderJenkinsMCPToken is an alternate client header for the optional shared
// secret (exact match). Prefer Authorization: Bearer when both are usable.
const HeaderJenkinsMCPToken = "X-Jenkins-MCP-Token"

// HTTPConfig configures Streamable HTTP serve protections (FND-006 / KD-008).
//
// MCP Streamable HTTP constraints we enforce here:
//   - Bind address must be loopback unless AllowNonLocal is set (CLI residual
//     flag --http-allow-non-local for tests / advanced operators).
//   - Request bodies are hard-capped (MaxBodyBytes).
//   - Host check: loopback-only by default (DNS rebinding defense). When
//     AllowNonLocal, the Host hostname must match AllowedHosts (case-insensitive,
//     port-normalized).
//   - Non-GET: when Origin is present it must be loopback or exact-match
//     AllowedOrigins — browser CSRF defense.
//   - Optional shared-secret gate (BearerToken): when non-empty, every request
//     must present Authorization: Bearer <token> or X-Jenkins-MCP-Token: <token>
//     with constant-time exact match (KD-008 lite). Transport gate only — not
//     multi-user / per-request identity (HOST-001). Prefer X-Jenkins-MCP-Token
//     for the shared secret when Authorization: Bearer carries a user access token.
//   - RequireToken (or AllowNonLocal) fails closed at serve start when
//     BearerToken is empty so operators can opt into a mandatory secret on
//     loopback; non-loopback always requires a secret, AllowedOrigins, and
//     AllowedHosts.
//   - RequireSubject (gateway / --http-require-subject, or AllowNonLocal): every
//     non-health request must establish RequestIdentity from a trusted source
//     (lab header when LabIdentity, or IdentityResolver e.g. JWT). Shared secret
//     alone never satisfies subject requirements (HOST-001).
//   - When RequireSubject is on, Mcp-Session-Id (when present) is bound to the
//     first request's IdentityFingerprint; mid-session subject change → 401.
//
// Residual: empty BearerToken on loopback without RequireToken still leaves the
// socket open to any local process (KD-008 pilot residual, non-gateway only).
// Production multi-user JWT/OIDC validation is partial (lab header + resolver
// hook foundation; continuous JWKS rotation under load residual HOST-001 /
// HOST-014). Prefer stdio for pilot (ADR 0002).
type HTTPConfig struct {
	// Addr is the listen address (e.g. "127.0.0.1:8765", "localhost:0").
	Addr string

	// AllowNonLocal permits binding to non-loopback interfaces.
	// Default false: reject 0.0.0.0, ::, LAN IPs, hostnames that are not loopback.
	// Wire as --http-allow-non-local in the CLI (tests / residual advanced use).
	// When true, BearerToken, AllowedOrigins, and AllowedHosts are always
	// required (fail closed). Also implies RequireSubject (HOST-001: non-local
	// cannot be anonymous multi-user).
	AllowNonLocal bool

	// MaxBodyBytes caps the HTTP request body. Zero uses DefaultMaxBodyBytes.
	// Negative disables the cap (not recommended; tests only).
	// Operator path: ResolveHTTPMaxBodyBytes → positive value ≤ AbsoluteMaxBodyBytes.
	MaxBodyBytes int64

	// AllowedOrigins, when non-empty, is an exact-match allow list for the
	// Origin header on non-GET requests. When empty (default), only loopback
	// origins (http(s)://localhost, 127.0.0.1, ::1) and missing Origin are
	// accepted on non-GET. Required non-empty when AllowNonLocal.
	AllowedOrigins []string

	// AllowedHosts is an exact-match allow list for the Host header hostname
	// (case-insensitive; optional :port is stripped before compare). Used when
	// AllowNonLocal is true for DNS-rebinding defense on non-loopback binds.
	// Wire as --http-allowed-host (repeatable). Required non-empty when
	// AllowNonLocal; ignored for loopback-only mode (Host must still be loopback).
	AllowedHosts []string

	// BearerToken, when non-empty, requires every request (including GET SSE)
	// to present the shared secret via Authorization: Bearer <token> or
	// X-Jenkins-MCP-Token: <token>. Compared with crypto/subtle constant-time
	// equality. Never log or echo this value. Empty (default) skips the check
	// on loopback unless RequireToken is set (KD-008 residual).
	// Transport gate only — not policy.Subject / multi-user identity.
	BearerToken string

	// RequireToken, when true, fails ValidateHTTPConfig / RunHTTP if BearerToken
	// is empty. Wire as --http-require-token, JENKINS_MCP_HTTP_REQUIRE_TOKEN, or
	// JENKINS_MCP_HTTP_DENY_ANONYMOUS (alias; same path). AllowNonLocal implies
	// the same requirement even when this flag is false. Loopback default
	// remains optional token for pilot compatibility (KD-008 residual).
	RequireToken bool

	// RequireSubject, when true, requires a trusted RequestIdentity on every
	// non-health request (HOST-001). Wire as --gateway, --http-require-subject,
	// or JENKINS_MCP_HTTP_REQUIRE_SUBJECT. AllowNonLocal implies the same
	// requirement. Shared secret alone never satisfies this gate.
	RequireSubject bool

	// LabIdentity, when true, accepts X-Jenkins-MCP-Lab-Subject (and optional
	// lab claim headers) as a trusted subject source. Wire from
	// JENKINS_MCP_LAB_IDENTITY=1 only. Fail closed when false: lab headers are
	// ignored. Residual: production uses JWT validation only.
	LabIdentity bool

	// IdentityResolver optionally supplies RequestIdentity (e.g. JWT + JWKS).
	// Called after the shared-secret gate; lab headers are a fallback when the
	// resolver returns empty. Never log resolver inputs (tokens).
	IdentityResolver IdentityResolver

	// Logger receives start/stop messages. Default: log.Default().
	Logger *log.Logger

	// ShutdownTimeout bounds graceful shutdown after ctx cancel. Default 5s.
	ShutdownTimeout time.Duration
}

// DefaultHTTPConfig returns safe defaults (loopback-only, 4 MiB body).
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		MaxBodyBytes:    DefaultMaxBodyBytes,
		ShutdownTimeout: 5 * time.Second,
	}
}

// ResolveHTTPMaxBodyBytes resolves the Streamable HTTP request body cap
// (Wave 44 Track C).
//
// Precedence (later wins): DefaultMaxBodyBytes → envVal → flagVal.
// Empty / whitespace means unset at that layer. Positive integers are accepted.
// Zero (explicit "0") at the winning layer means DefaultMaxBodyBytes.
// Negative or non-integer values fail closed (error); never clamp silently.
// After resolve, n must be ≤ AbsoluteMaxBodyBytes; oversize values error with
// a non-secret message citing the absolute maximum (no secrets).
func ResolveHTTPMaxBodyBytes(flagVal, envVal string) (int64, error) {
	n := DefaultMaxBodyBytes
	if raw := strings.TrimSpace(envVal); raw != "" {
		v, err := parseHTTPMaxBodyBytesValue(raw, "env "+EnvHTTPMaxBodyBytes)
		if err != nil {
			return 0, err
		}
		n = v
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		v, err := parseHTTPMaxBodyBytesValue(raw, "flag --http-max-body-bytes")
		if err != nil {
			return 0, err
		}
		n = v
	}
	if n > AbsoluteMaxBodyBytes {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"http max body bytes exceeds absolute maximum bound ("+
				strconv.FormatInt(AbsoluteMaxBodyBytes, 10)+" bytes)")
	}
	return n, nil
}

func parseHTTPMaxBodyBytesValue(raw, source string) (int64, error) {
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid http max body bytes from "+source+" (positive integer bytes, or 0 for default): "+raw)
	}
	if v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"http max body bytes from "+source+" must not be negative")
	}
	if v == 0 {
		return DefaultMaxBodyBytes, nil
	}
	return v, nil
}

// ValidateHTTPConfig fails closed on unsafe HTTP serve configuration.
// AllowNonLocal requires non-empty AllowedOrigins and AllowedHosts so browser
// Origin and Host are never "any host" by default (Wave 16 / Wave 35), and
// always requires a non-empty BearerToken (non-loopback without a shared secret
// is too open). RequireToken (CLI/env) forces the same secret check on loopback.
func ValidateHTTPConfig(cfg HTTPConfig) error {
	if err := ValidateListenAddr(cfg.Addr, cfg.AllowNonLocal); err != nil {
		return err
	}
	return validateHTTPHandlerPolicy(cfg)
}

// HTTPTokenRequired reports whether a non-empty BearerToken is mandatory for cfg
// (RequireToken flag/env or AllowNonLocal). Never logs token values.
func HTTPTokenRequired(cfg HTTPConfig) bool {
	return cfg.RequireToken || cfg.AllowNonLocal
}

// HTTPSubjectRequired reports whether a trusted RequestIdentity is mandatory for
// cfg (RequireSubject flag/env/gateway or AllowNonLocal). Never logs tokens.
// HOST-001: shared secret does not satisfy this requirement.
func HTTPSubjectRequired(cfg HTTPConfig) bool {
	return cfg.RequireSubject || cfg.AllowNonLocal
}

// validateHTTPTokenRequirement fails closed when a secret is mandatory but empty.
func validateHTTPTokenRequirement(cfg HTTPConfig) error {
	if !HTTPTokenRequired(cfg) {
		return nil
	}
	if strings.TrimSpace(cfg.BearerToken) != "" {
		return nil
	}
	if cfg.AllowNonLocal {
		return apperr.New(apperr.CodeInvalidArgument,
			"http-allow-non-local requires a shared secret (--http-token-env or --http-token-file); fail closed")
	}
	return apperr.New(apperr.CodeInvalidArgument,
		"http-require-token requires a non-empty shared secret (--http-token-env or --http-token-file)")
}

// ValidateListenAddr reports whether addr is safe to bind given AllowNonLocal.
// Empty host (":port") is treated as all-interfaces and rejected unless allowed.
func ValidateListenAddr(addr string, allowNonLocal bool) error {
	if strings.TrimSpace(addr) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "http listen address is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Allow bare ":port" via JoinHostPort style already covered; other forms fail.
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("invalid http listen address %q: %v", addr, err))
	}
	if port == "" {
		return apperr.New(apperr.CodeInvalidArgument, "http listen address missing port")
	}
	if allowNonLocal {
		return nil
	}
	if isLoopbackHost(host) {
		return nil
	}
	return apperr.New(apperr.CodeInvalidArgument,
		fmt.Sprintf("http listen address %q is not loopback; bind 127.0.0.1/localhost or pass --http-allow-non-local (not for production)", addr))
}

// isLoopbackHost reports whether host is empty-as-invalid, localhost, or a
// loopback IP. Empty host means "all interfaces" for Listen and is NOT loopback.
func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false // ":port" → all interfaces
	}
	// Strip zone id for IPv6 (e.g. fe80::1%lo0) — loopback rarely has zones.
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	lower := strings.ToLower(h)
	if lower == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		// Non-IP hostname that is not "localhost" — fail closed (no DNS for bind check).
		return false
	}
	return ip.IsLoopback()
}

// NewHTTPHandler wraps mcp.NewStreamableHTTPHandler with body and origin/host
// protections. Does not start a listener; use RunHTTP or http.Server.
// Enforces token/origin fail-closed rules (RequireToken / non-local + secret)
// without requiring a listen address (handler unit tests omit Addr).
func NewHTTPHandler(server *mcp.Server, cfg HTTPConfig) (http.Handler, error) {
	if server == nil {
		return nil, apperr.New(apperr.CodeInternal, "mcp server is nil")
	}
	if err := validateHTTPHandlerPolicy(cfg); err != nil {
		return nil, err
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	inner := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return server
	}, nil)
	requireSubject := HTTPSubjectRequired(cfg)
	h := &protectHandler{
		inner:            inner,
		maxBody:          maxBody,
		allowNonLocal:    cfg.AllowNonLocal,
		allowedOrigins:   append([]string(nil), cfg.AllowedOrigins...),
		allowedHosts:     append([]string(nil), cfg.AllowedHosts...),
		bearerToken:      cfg.BearerToken,
		requireSubject:   requireSubject,
		labIdentity:      cfg.LabIdentity,
		identityResolver: cfg.IdentityResolver,
	}
	// HOST-001: session→fingerprint table only when subject is required
	// (gateway / non-local / --http-require-subject). Pilot loopback without
	// require-subject skips mid-session bind (KD-008 residual).
	if requireSubject {
		h.sessionBind = newSessionIdentityTable(DefaultMaxSessionIdentityBinds)
	}
	return h, nil
}

// validateHTTPHandlerPolicy is ValidateHTTPConfig without listen-address checks
// (NewHTTPHandler / httptest may omit Addr).
func validateHTTPHandlerPolicy(cfg HTTPConfig) error {
	// Defense-in-depth: AbsoluteMaxBodyBytes applies even if a library caller
	// sets MaxBodyBytes without going through ResolveHTTPMaxBodyBytes.
	// Zero means default (allowed); negative still disables the cap (tests-only residual).
	if cfg.MaxBodyBytes > AbsoluteMaxBodyBytes {
		return apperr.New(apperr.CodeInvalidArgument,
			"http MaxBodyBytes exceeds absolute max "+strconv.FormatInt(AbsoluteMaxBodyBytes, 10)+" bytes (fail closed)")
	}
	if cfg.AllowNonLocal {
		if len(cfg.AllowedOrigins) == 0 {
			return apperr.New(apperr.CodeInvalidArgument,
				"http-allow-non-local requires at least one --http-allowed-origin (fail closed; residual advanced use only)")
		}
		for i, o := range cfg.AllowedOrigins {
			o = strings.TrimSpace(o)
			if o == "" {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("http allowed origin #%d is empty", i+1))
			}
			if u, err := url.Parse(o); err != nil || u.Scheme == "" || u.Host == "" {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("http allowed origin %q is not an absolute http(s) origin", o))
			} else if u.Scheme != "http" && u.Scheme != "https" {
				return apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("http allowed origin %q must use http or https", o))
			}
		}
		if len(cfg.AllowedHosts) == 0 {
			return apperr.New(apperr.CodeInvalidArgument,
				"http-allow-non-local requires at least one --http-allowed-host (fail closed; DNS rebinding defense)")
		}
		for i, h := range cfg.AllowedHosts {
			if err := validateAllowedHostEntry(h, i+1); err != nil {
				return err
			}
		}
	}
	return validateHTTPTokenRequirement(cfg)
}

// validateAllowedHostEntry checks one AllowedHosts entry (hostname or IP,
// optional :port). Rejects empty values and URL-like forms with a scheme.
func validateAllowedHostEntry(entry string, index int) error {
	h := strings.TrimSpace(entry)
	if h == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("http allowed host #%d is empty", index))
	}
	if strings.Contains(h, "://") {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("http allowed host %q must be a hostname or IP (optional :port), not a URL", entry))
	}
	// Normalize via hostname extract; reject if nothing usable remains.
	name := hostnameFromHostHeader(h)
	if name == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("http allowed host %q has empty hostname", entry))
	}
	return nil
}

// RunHTTP listens on cfg.Addr and serves Streamable HTTP until ctx is cancelled
// or the listener fails. Enforces ValidateHTTPConfig before Listen.
func RunHTTP(ctx context.Context, server *mcp.Server, cfg HTTPConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ValidateHTTPConfig(cfg); err != nil {
		return err
	}
	handler, err := NewHTTPHandler(server, cfg)
	if err != nil {
		return err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	shutdownTO := cfg.ShutdownTimeout
	if shutdownTO <= 0 {
		shutdownTO = 5 * time.Second
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "http listen failed", err)
	}
	// Double-check actual bound address is still loopback when required
	// (e.g. if OS resolved a surprising interface).
	if !cfg.AllowNonLocal {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.IP != nil && !ta.IP.IsLoopback() {
			_ = ln.Close()
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("refusing non-loopback listen address %s; pass --http-allow-non-local", ln.Addr().String()))
		}
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout covers headers + body; body is also MaxBytesReader-capped.
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		// IdleTimeout for keep-alive between MCP POSTs.
		IdleTimeout: 120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		// Never log BearerToken or access-token values — only bools.
		logger.Printf("Starting MCP HTTP server on %s (loopback_enforced=%v max_body=%d http_token_required=%v http_token_configured=%v http_subject_required=%v lab_identity=%v)",
			ln.Addr().String(), !cfg.AllowNonLocal, effectiveMaxBody(cfg),
			HTTPTokenRequired(cfg), cfg.BearerToken != "",
			HTTPSubjectRequired(cfg), cfg.LabIdentity)
		errCh <- srv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTO)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		err := <-errCh
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return apperr.Wrap(apperr.CodeInternal, "http server error", err)
	case err := <-errCh:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return apperr.Wrap(apperr.CodeInternal, "http server error", err)
	}
}

func effectiveMaxBody(cfg HTTPConfig) int64 {
	if cfg.MaxBodyBytes == 0 {
		return DefaultMaxBodyBytes
	}
	return cfg.MaxBodyBytes
}

// protectHandler applies optional shared-secret, subject identity, body size,
// Host, and Origin checks around the SDK handler (HOST-001 + KD-008).
type protectHandler struct {
	inner            http.Handler
	maxBody          int64
	allowNonLocal    bool
	allowedOrigins   []string
	allowedHosts     []string
	bearerToken      string
	requireSubject   bool
	labIdentity      bool
	identityResolver IdentityResolver
	// sessionBind is non-nil when requireSubject: maps Mcp-Session-Id to
	// IdentityFingerprint (mid-session subject swap → 401).
	sessionBind *sessionIdentityTable
}

func (h *protectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Secret-free health/ready: no shared secret, no subject, no tool inventory.
	// Exact path only (HOST-001 / HOST-002 residual for broader probe matrix).
	if isHealthPath(r.URL.Path) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		writeHealthOK(w)
		return
	}

	// Optional shared-secret gate (KD-008 lite / transport only). Fail closed
	// with 401 and a generic body — never echo the expected token or compare
	// result details. Does not establish multi-user identity.
	if h.bearerToken != "" {
		if !requestHasValidToken(r, h.bearerToken) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="jenkins-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// HOST-001: per-request subject when require-subject / non-local.
	// Shared secret above is not sufficient. Identity is non-secret labels only.
	var reqID RequestIdentity
	if h.requireSubject || h.labIdentity || h.identityResolver != nil {
		id, err := resolveRequestIdentity(r, h.labIdentity, h.identityResolver)
		if err != nil {
			// Invalid credentials (e.g. bad JWT) — generic 401, never token text.
			unauthorizedIdentity(w)
			return
		}
		reqID = id
		if h.requireSubject && !reqID.Present() {
			unauthorizedIdentity(w)
			return
		}
		// Mid-session subject rebind: when RequireSubject and Mcp-Session-Id is
		// present, first Present identity establishes fingerprint; mismatch → 401.
		// Health paths never reach here. No session id (initialize) skips bind.
		if h.requireSubject && reqID.Present() && h.sessionBind != nil {
			sid := strings.TrimSpace(r.Header.Get(HeaderMCPSessionID))
			if sid != "" {
				if err := h.sessionBind.BindOrCheck(sid, IdentityFingerprint(reqID)); err != nil {
					unauthorizedIdentity(w)
					return
				}
			}
		}
		if reqID.Present() {
			r = r.WithContext(ContextWithIdentity(r.Context(), reqID))
		}
	}

	// Host check: when loopback-only, reject Host headers that point off-box
	// (DNS rebinding). When AllowNonLocal, Host hostname must match AllowedHosts.
	if err := checkRequestHost(r, h.allowNonLocal, h.allowedHosts); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Origin check for non-GET (POST/DELETE carry session/mutation semantics).
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if err := checkOrigin(r, h.allowedOrigins, h.allowNonLocal); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	// Body size limit (POST/PUT/PATCH). Prefer early Content-Length reject (413);
	// MaxBytesReader still caps chunked / lying clients when the body is read.
	if h.maxBody >= 0 && r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.ContentLength > h.maxBody {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, h.maxBody)
		}
	}

	h.inner.ServeHTTP(w, r)
}

// requestHasValidToken reports whether r presents the shared secret via
// Authorization: Bearer or X-Jenkins-MCP-Token (exact match, constant-time).
func requestHasValidToken(r *http.Request, want string) bool {
	if want == "" || r == nil {
		return want == ""
	}
	// Evaluate both candidate sources without early success return so
	// timing does not depend on which header matched first.
	authOK := subtle.ConstantTimeCompare(
		[]byte(bearerFromAuthorization(r.Header.Get("Authorization"))),
		[]byte(want),
	)
	hdrOK := subtle.ConstantTimeCompare(
		[]byte(r.Header.Get(HeaderJenkinsMCPToken)),
		[]byte(want),
	)
	return (authOK | hdrOK) == 1
}

// bearerFromAuthorization extracts the token from "Bearer <token>" (case-
// insensitive scheme). Returns empty when missing or malformed.
func bearerFromAuthorization(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) < len(prefix) {
		return ""
	}
	if !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func checkRequestHost(r *http.Request, allowNonLocal bool, allowedHosts []string) error {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("missing Host header")
	}
	// Host may be "name:port".
	h := hostnameFromHostHeader(host)
	if h == "" {
		return fmt.Errorf("missing Host name")
	}
	if allowNonLocal {
		// Fail closed: Host hostname must match AllowedHosts (case-insensitive,
		// port-normalized). ValidateHTTPConfig requires a non-empty list.
		if hostInAllowList(h, allowedHosts) {
			return nil
		}
		return fmt.Errorf("Host %q is not allowed", host)
	}
	if isLoopbackHost(h) {
		return nil
	}
	return fmt.Errorf("Host %q is not loopback", host)
}

// hostnameFromHostHeader returns the hostname part of a Host header value
// (strips optional :port and surrounding [] for IPv6). Empty when unusable.
func hostnameFromHostHeader(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port — use whole Host (common for default ports).
		h = host
	}
	// net.SplitHostPort leaves brackets off for [::1]:port; bare [::1] may keep them.
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	return strings.TrimSpace(h)
}

// hostInAllowList reports whether hostname matches any AllowedHosts entry
// (case-insensitive; both sides port-normalized).
func hostInAllowList(hostname string, allowed []string) bool {
	want := strings.ToLower(hostnameFromHostHeader(hostname))
	if want == "" {
		return false
	}
	for _, a := range allowed {
		if strings.ToLower(hostnameFromHostHeader(a)) == want {
			return true
		}
	}
	return false
}

func checkOrigin(r *http.Request, allowed []string, allowNonLocal bool) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		// Non-browser clients (curl, MCP SDK) often omit Origin — allow.
		return nil
	}
	if len(allowed) > 0 {
		for _, a := range allowed {
			if origin == a {
				return nil
			}
		}
		return fmt.Errorf("Origin not allowed")
	}
	// Empty allow list: only loopback origins. Never accept arbitrary https
	// Origins under AllowNonLocal (ValidateHTTPConfig requires allow list first).
	_ = allowNonLocal
	if isLoopbackOrigin(origin) {
		return nil
	}
	return fmt.Errorf("Origin %q is not a loopback origin", origin)
}

func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	h, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		h = u.Host
	}
	return isLoopbackHost(h)
}
