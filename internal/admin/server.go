package admin

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin/uiembed"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// DefaultAddr is the loopback bind for admin serve (ADR 0014).
const DefaultAddr = "127.0.0.1:8787"

// HTTP server timeouts for local admin serve (UI-008). Conservative values for
// a loopback operator console — not a public multi-tenant gateway.
const (
	// DefaultReadHeaderTimeout bounds time to read request headers.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultReadTimeout bounds full request read (headers + body).
	DefaultReadTimeout = 30 * time.Second
	// DefaultWriteTimeout bounds time to write the full response.
	DefaultWriteTimeout = 60 * time.Second
	// DefaultIdleTimeout bounds keep-alive idle connections.
	DefaultIdleTimeout = 120 * time.Second
)

// Config configures the local admin BFF HTTP server (UI-002 / UI-003 / UI-008).
type Config struct {
	// Addr is the listen address (default DefaultAddr).
	Addr string
	// AllowNonLocal permits non-loopback binds. When true, BearerToken is
	// required (fail closed). Wire as --admin-allow-non-local (residual).
	AllowNonLocal bool
	// BearerToken, when non-empty, requires every /admin/v1/* request to present
	// Authorization: Bearer or X-Jenkins-MCP-Admin-Token. Never log this value.
	BearerToken string
	// RequireToken fails ValidateConfig when BearerToken is empty.
	// Wire as --require-token. AllowNonLocal implies the same.
	RequireToken bool
	// Role is the admin console RBAC role for this process (UI-003).
	// Default viewer. Separate from MCP deny-only subjects. Wire as --admin-role.
	// Invalid values fail ValidateConfig / start.
	Role Role
	// AssetsDir, when set, serves SPA static files at GET / (FileServer).
	// Empty → ResolveAssets defaults: package path → dev dist → embed → placeholder.
	AssetsDir string
	// ProfileID is the optional default profile for /admin/v1/doctor.
	ProfileID string
	// Version / Commit / BuildTime / UIBuild are secret-free binary metadata.
	// UIBuild may be filled from asset stamp (UI_BUILD / embed) when empty.
	Version   string
	Commit    string
	BuildTime string
	UIBuild   string
	// Paths optional XDG paths (resolved when nil).
	Paths *config.Paths
	// LoadProfile optional override (tests). When nil, uses profile.Store.
	LoadProfile func(id string) (*profile.Profile, error)
	// ListProfiles optional override (tests / UI-007). When nil, uses profile.Store.List.
	ListProfiles func() ([]string, error)
	// Keyring for doctor credential presence (value never returned). Nil → Default().
	Keyring *keyring.Store
	// Logger receives start/stop messages. Default: log.Default().
	Logger *log.Logger
	// ShutdownTimeout bounds graceful shutdown after ctx cancel. Default 5s.
	ShutdownTimeout time.Duration
}

// DefaultConfig returns safe defaults (loopback 127.0.0.1:8787, role viewer).
func DefaultConfig() Config {
	return Config{
		Addr:            DefaultAddr,
		Role:            RoleViewer,
		ShutdownTimeout: 5 * time.Second,
	}
}

// TokenRequired reports whether a non-empty BearerToken is mandatory.
func TokenRequired(cfg Config) bool {
	return cfg.RequireToken || cfg.AllowNonLocal
}

// ValidateListenAddr reports whether addr is safe to bind given AllowNonLocal.
// Empty host (":port") is treated as all-interfaces and rejected unless allowed.
// Exported for unit tests (loopback validation).
func ValidateListenAddr(addr string, allowNonLocal bool) error {
	if strings.TrimSpace(addr) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "admin listen address is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("invalid admin listen address %q: %v", addr, err))
	}
	if port == "" {
		return apperr.New(apperr.CodeInvalidArgument, "admin listen address missing port")
	}
	if allowNonLocal {
		return nil
	}
	if isLoopbackHost(host) {
		return nil
	}
	return apperr.New(apperr.CodeInvalidArgument,
		fmt.Sprintf("admin listen address %q is not loopback; bind 127.0.0.1/localhost or pass --admin-allow-non-local (not for production; requires token)", addr))
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false // ":port" → all interfaces
	}
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	lower := strings.ToLower(h)
	if lower == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// ValidateConfig fails closed on unsafe admin serve configuration.
func ValidateConfig(cfg Config) error {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		addr = DefaultAddr
	}
	if err := ValidateListenAddr(addr, cfg.AllowNonLocal); err != nil {
		return err
	}
	if TokenRequired(cfg) && strings.TrimSpace(cfg.BearerToken) == "" {
		if cfg.AllowNonLocal {
			return apperr.New(apperr.CodeInvalidArgument,
				"admin-allow-non-local requires a shared secret (--admin-token-env or --admin-token-file); fail closed")
		}
		return apperr.New(apperr.CodeInvalidArgument,
			"require-token requires a non-empty shared secret (--admin-token-env or --admin-token-file)")
	}
	// Role: empty → viewer; invalid → fail start.
	if _, err := ParseRole(string(cfg.Role)); err != nil {
		return err
	}
	if cfg.ProfileID != "" {
		if err := ValidateProfileID(cfg.ProfileID); err != nil {
			return err
		}
	}
	if d := strings.TrimSpace(cfg.AssetsDir); d != "" {
		st, err := os.Stat(d)
		if err != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "assets-dir", err)
		}
		if !st.IsDir() {
			return apperr.New(apperr.CodeInvalidArgument, "assets-dir must be a directory")
		}
	}
	return nil
}

// normalizeConfig applies defaults after ValidateConfig (role, addr).
func normalizeConfig(cfg Config) Config {
	if strings.TrimSpace(cfg.Addr) == "" {
		cfg.Addr = DefaultAddr
	}
	role, err := ParseRole(string(cfg.Role))
	if err != nil || role == "" {
		role = RoleViewer
	}
	cfg.Role = role
	return cfg
}

type server struct {
	cfg Config
}

// NewHandler builds the admin HTTP handler (API + optional SPA). Does not listen.
// Wraps with security headers (CSP, nosniff, …) on all responses (UI-008).
func NewHandler(cfg Config) (http.Handler, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	cfg = normalizeConfig(cfg)

	// Resolve SPA assets: explicit dir, package path, dev dist, or embed (UI-008).
	resolved := ResolveAssets(cfg.AssetsDir)
	if strings.TrimSpace(cfg.UIBuild) == "" && resolved.UIBuild != "" {
		cfg.UIBuild = resolved.UIBuild
	}

	s := &server{cfg: cfg}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /admin/v1/health", s.handleHealth)
	mux.HandleFunc("GET /admin/v1/version", s.handleVersion)
	mux.HandleFunc("GET /admin/v1/me", s.handleMe)
	// HOST-011 / HOST-009: secret-free gateway vault + mode matrix status (read-only).
	mux.HandleFunc("GET /admin/v1/gateway/vault", s.handleGatewayVault)
	mux.HandleFunc("GET /admin/v1/metrics", s.handleMetrics)
	// UI-007: profiles / cache / support-bundle / security self-check
	mux.HandleFunc("GET /admin/v1/profiles", s.handleProfilesList)
	mux.HandleFunc("GET /admin/v1/profiles/{id}", s.handleProfileGet)
	mux.HandleFunc("GET /admin/v1/profiles/{id}/cache", s.handleProfileCache)
	mux.HandleFunc("GET /admin/v1/profiles/{id}/security-selfcheck", s.handleSecuritySelfCheck)
	mux.HandleFunc("POST /admin/v1/profiles/{id}/cache/evict-plan", s.handleCacheEvictPlan)
	mux.HandleFunc("POST /admin/v1/profiles/{id}/cache/evict", s.handleCacheEvict)
	mux.HandleFunc("POST /admin/v1/profiles/{id}/support-bundle", s.handleSupportBundle)
	mux.HandleFunc("GET /admin/v1/profiles/{id}/policy/effective", s.handlePolicyEffective)
	// UI-004: pilot overlay read + controlled validate/apply (policy_write).
	mux.HandleFunc("GET /admin/v1/policy/overlay", s.handlePolicyOverlayGET)
	mux.HandleFunc("POST /admin/v1/policy/validate", s.handlePolicyValidate)
	mux.HandleFunc("POST /admin/v1/policy/apply", s.handlePolicyApply)
	mux.HandleFunc("GET /admin/v1/profiles/{id}/audit", s.handleAudit)
	mux.HandleFunc("GET /admin/v1/profiles/{id}/doctor", s.handleDoctorProfile)
	mux.HandleFunc("GET /admin/v1/doctor", s.handleDoctorDefault)

	// SPA: filesystem (flag/package/dev) → embed → built-in placeholder.
	switch {
	case resolved.Dir != "":
		// FileServer + SPA fallback so BrowserRouter deep links (e.g. /metrics)
		// return index.html instead of 404 (UI-001 / UI-008).
		mux.Handle("GET /", spaFileServer(resolved.Dir))
		mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(resolved.Dir, "assets")))))
	case resolved.UseEmbed:
		mux.Handle("GET /", spaFSServer(uiembed.FS()))
	default:
		mux.HandleFunc("GET /", s.handlePlaceholder)
	}

	// Outermost: security headers on every response (API + SPA).
	// Auth gate still applies to /admin/v1/* only.
	return securityHeaders(authMiddleware(cfg.BearerToken, cfg.Role, mux)), nil
}

// spaFileServer serves static files from root and falls back to index.html for
// client-side routes. Missing asset-like paths (with a file extension other
// than .html) still 404. API paths under /admin/v1 are never rewritten.
func spaFileServer(root string) http.Handler {
	root = filepath.Clean(root)
	dir := http.Dir(root)
	files := http.FileServer(dir)
	indexPath := filepath.Join(root, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := r.URL.Path
		if p == "" {
			p = "/"
		}
		// Never SPA-fallback the BFF API (registered separately, but defense-in-depth).
		if p == "/admin/v1" || strings.HasPrefix(p, "/admin/v1/") {
			http.NotFound(w, r)
			return
		}
		// Try real file relative to assets root.
		rel := strings.TrimPrefix(path.Clean("/"+p), "/")
		if rel == "" || rel == "." {
			files.ServeHTTP(w, r)
			return
		}
		if f, err := dir.Open(rel); err == nil {
			st, stErr := f.Stat()
			_ = f.Close()
			if stErr == nil && !st.IsDir() {
				files.ServeHTTP(w, r)
				return
			}
		}
		// Asset-like missing files: 404 (do not return SPA shell for .js/.css).
		base := filepath.Base(rel)
		if i := strings.LastIndex(base, "."); i > 0 {
			ext := strings.ToLower(base[i:])
			if ext != ".html" {
				http.NotFound(w, r)
				return
			}
		}
		// BrowserRouter client route → index.html
		if _, err := os.Stat(indexPath); err != nil {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, indexPath)
	})
}

func (s *server) handlePlaceholder(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>jenkins-mcp admin</title></head>
<body>
  <h1>jenkins-mcp admin BFF</h1>
  <p>API is at <code>/admin/v1/*</code> (UI-002). No SPA assets resolved (UI-008).</p>
  <p>Serve static UI with <code>--assets-dir</code>, package path
  <code>/usr/share/jenkins-mcp/admin-ui</code>, or <code>make admin-ui-embed</code>.</p>
  <ul>
    <li><a href="/admin/v1/health">/admin/v1/health</a></li>
    <li><a href="/admin/v1/version">/admin/v1/version</a></li>
    <li><a href="/admin/v1/me">/admin/v1/me</a></li>
    <li><a href="/admin/v1/metrics">/admin/v1/metrics</a></li>
  </ul>
</body>
</html>
`))
}

// Run listens on cfg.Addr until ctx is cancelled, then shuts down gracefully.
func Run(ctx context.Context, cfg Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	cfg = normalizeConfig(cfg)
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 5 * time.Second
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.Default()
	}

	// Pre-resolve assets so UIBuild is filled before NewHandler + start logs.
	resolved := ResolveAssets(cfg.AssetsDir)
	if strings.TrimSpace(cfg.UIBuild) == "" && resolved.UIBuild != "" {
		cfg.UIBuild = resolved.UIBuild
	}

	h, err := NewHandler(cfg)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "admin listen", err)
	}
	// Double-check loopback after bind when not AllowNonLocal.
	if !cfg.AllowNonLocal {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.IP != nil && !ta.IP.IsLoopback() {
			_ = ln.Close()
			return apperr.New(apperr.CodeInvalidArgument,
				"admin listener is not loopback after bind; refuse non-local residual without --admin-allow-non-local")
		}
	}

	// Timeouts: conservative local-admin bounds (UI-008). Never log headers (token).
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       DefaultReadTimeout,
		WriteTimeout:      DefaultWriteTimeout,
		IdleTimeout:       DefaultIdleTimeout,
	}

	// Residual honesty: warn when loopback without shared secret (ADR 0014 / UI-003).
	if strings.TrimSpace(cfg.BearerToken) == "" {
		lg.Printf("admin serve: residual — no admin token configured on loopback (pilot-only; prefer --admin-token-env or --require-token); role=%s still applied",
			cfg.Role)
	}
	// Never log the token value — only configured boolean, role, and assets source.
	lg.Printf("admin serve: listening on %s (role=%s token_required=%v token_configured=%v assets_source=%s ui_build=%q)",
		ln.Addr().String(), cfg.Role, TokenRequired(cfg), cfg.BearerToken != "", resolved.Source, cfg.UIBuild)

	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if err == nil || err == http.ErrServerClosed {
			errCh <- nil
			return
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		return <-errCh
	case err := <-errCh:
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "admin serve", err)
		}
		return nil
	}
}
