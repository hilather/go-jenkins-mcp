package authlab

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RSConfig configures the mock JWT resource server (HOST-013).
type RSConfig struct {
	// Issuer expected in tokens (exact after trailing-slash trim).
	Issuer string
	// Audience expected (default jenkins-api).
	Audience string
	// JWKS is static lab keys (preferred when co-located).
	JWKS *JWKS
	// JWKSURL optional remote JWKS (fetched lazily, cached).
	JWKSURL string
	// HTTPClient for JWKS fetch; nil → http.DefaultClient.
	HTTPClient *http.Client
	// Now optional clock.
	Now func() time.Time
}

// RSServer validates Bearer JWTs fail-closed (no Basic/anonymous fallthrough).
type RSServer struct {
	cfg RSConfig

	mu       sync.RWMutex
	cached   *JWKS
	cacheErr error
}

// NewRSServer builds a mock RS. Issuer and either JWKS or JWKSURL required.
func NewRSServer(cfg RSConfig) (*RSServer, error) {
	iss := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if iss == "" {
		return nil, errf("issuer required")
	}
	if cfg.JWKS == nil && strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, errf("jwks or jwks_url required")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		cfg.Audience = DefaultAudience
	}
	cfg.Issuer = iss
	return &RSServer{cfg: cfg, cached: cfg.JWKS}, nil
}

// Handler returns the HTTP mux for mock-rs.
func (s *RSServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/whoAmI", s.handleWhoAmI)
	mux.HandleFunc("GET /mcp-rs/check", s.handleWhoAmI)
	return mux
}

func (s *RSServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "mock-rs"})
}

func (s *RSServer) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")

	// Fail closed: Bearer scheme present (even invalid) → never Basic/anonymous.
	if HasBearerScheme(authz) {
		tok := ExtractBearer(authz)
		if tok == "" {
			writeUnauthorized(w, "invalid_token", "bearer token missing")
			return
		}
		jwks, err := s.jwks()
		if err != nil {
			writeUnauthorized(w, "invalid_token", "jwks unavailable")
			return
		}
		claims, err := ValidateAccessToken(tok, jwks, ValidateParams{
			Issuer:   s.cfg.Issuer,
			Audience: s.cfg.Audience,
			Now:      s.cfg.Now,
		})
		if err != nil {
			// Secret-free: do not echo token or detailed claim values that might leak.
			writeUnauthorized(w, "invalid_token", "token validation failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":  true,
			"sub": claims.Subject,
			// Mirror a tiny whoAmI-shaped label (no secrets).
			"authenticated": true,
			"lab_only":      true,
		})
		return
	}

	// No Bearer: OAuth-required routes do not fall through to Basic/anonymous.
	// Even if Authorization: Basic is present, return 401.
	if strings.TrimSpace(authz) != "" {
		writeUnauthorized(w, "invalid_request", "bearer required; basic not accepted on oauth routes")
		return
	}
	writeUnauthorized(w, "invalid_request", "authorization required")
}

func writeUnauthorized(w http.ResponseWriter, code, desc string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="oauth-lab", error="`+code+`"`)
	writeError(w, http.StatusUnauthorized, code, desc)
}

func (s *RSServer) jwks() (*JWKS, error) {
	s.mu.RLock()
	if s.cached != nil {
		j := s.cached
		s.mu.RUnlock()
		return j, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil {
		return s.cached, nil
	}
	if s.cfg.JWKS != nil {
		s.cached = s.cfg.JWKS
		return s.cached, nil
	}
	j, err := fetchJWKS(s.client(), s.cfg.JWKSURL)
	if err != nil {
		s.cacheErr = err
		return nil, err
	}
	s.cached = j
	return j, nil
}

func (s *RSServer) client() *http.Client {
	if s.cfg.HTTPClient != nil {
		return s.cfg.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func fetchJWKS(client *http.Client, rawURL string) (*JWKS, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errf("empty jwks url")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errf("invalid jwks url")
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errf("jwks http status")
	}
	var doc JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if len(doc.Keys) == 0 {
		return nil, errf("empty jwks")
	}
	return &doc, nil
}
