package authlab

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OIDCConfig configures the mock OIDC IdP (HOST-014).
type OIDCConfig struct {
	// Issuer is the public issuer URL advertised in discovery and embedded in JWTs.
	// Host tests use http://127.0.0.1:18081; must match mock-rs expected issuer.
	Issuer string
	// ListenAddr is informational only (handlers are pure); used in discovery URLs.
	// Key provides signing material.
	Key *LabKey
	// DefaultAudience for minted tokens when not overridden.
	DefaultAudience string
	// DefaultSubject for minted tokens.
	DefaultSubject string
	// Now optional clock.
	Now func() time.Time
}

// OIDCServer is a minimal OIDC discovery + JWKS + token mint IdP for labs.
type OIDCServer struct {
	cfg OIDCConfig
}

// NewOIDCServer builds a mock IdP. Issuer and Key are required.
func NewOIDCServer(cfg OIDCConfig) (*OIDCServer, error) {
	iss := strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if iss == "" {
		return nil, errf("issuer required")
	}
	if cfg.Key == nil || cfg.Key.Private == nil {
		return nil, errf("signing key required")
	}
	if strings.TrimSpace(cfg.DefaultAudience) == "" {
		cfg.DefaultAudience = DefaultAudience
	}
	if strings.TrimSpace(cfg.DefaultSubject) == "" {
		cfg.DefaultSubject = "lab-user"
	}
	cfg.Issuer = iss
	return &OIDCServer{cfg: cfg}, nil
}

// Handler returns the HTTP mux for mock-oidc.
func (s *OIDCServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /jwks", s.handleJWKS)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /token", s.handleToken) // convenience for negative tests
	return mux
}

func (s *OIDCServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "mock-oidc"})
}

func (s *OIDCServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"jwks_uri":                              iss + "/jwks",
		"token_endpoint":                        iss + "/token",
		"authorization_endpoint":                iss + "/authorize", // stub; not used by smoke
		"response_types_supported":              []string{"token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"grant_types_supported":                 []string{"client_credentials", "authorization_code"},
		"scopes_supported":                      []string{"openid", "profile"},
		// Lab residual: not production Entra / Conditional Access.
		"lab_only": true,
	})
}

func (s *OIDCServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	doc, err := s.cfg.Key.JWKS()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "jwks unavailable")
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *OIDCServer) handleToken(w http.ResponseWriter, r *http.Request) {
	// Bound body, then parse form (must parse before discard).
	// Never log form values that might look like secrets.
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	_ = r.ParseForm()

	aud := firstNonEmpty(
		r.FormValue("audience"),
		r.FormValue("resource"),
		r.URL.Query().Get("aud"),
		r.URL.Query().Get("audience"),
		s.cfg.DefaultAudience,
	)
	sub := firstNonEmpty(
		r.FormValue("subject"),
		r.FormValue("sub"),
		r.URL.Query().Get("sub"),
		s.cfg.DefaultSubject,
	)
	iss := firstNonEmpty(
		r.FormValue("iss"),
		r.URL.Query().Get("iss"),
		s.cfg.Issuer,
	)

	// exp_offset seconds (signed): negative → expired token for fail-closed tests.
	var expOffset time.Duration
	if raw := firstNonEmpty(r.FormValue("exp_offset"), r.URL.Query().Get("exp_offset")); raw != "" {
		sec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "exp_offset must be integer seconds")
			return
		}
		expOffset = time.Duration(sec) * time.Second
	}
	// expires_in override (positive seconds from now).
	ttl := DefaultTTL
	if raw := firstNonEmpty(r.FormValue("expires_in"), r.URL.Query().Get("expires_in")); raw != "" {
		sec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || sec <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "expires_in must be positive integer")
			return
		}
		ttl = time.Duration(sec) * time.Second
	}

	// Scenario shortcuts for negative tests.
	switch strings.ToLower(strings.TrimSpace(firstNonEmpty(r.FormValue("scenario"), r.URL.Query().Get("scenario")))) {
	case "wrong_audience", "wrong-aud":
		aud = "https://graph.microsoft.com"
	case "expired":
		expOffset = -2 * time.Hour
	case "foreign_iss", "wrong_iss":
		iss = "https://foreign-idp.example.invalid/lab"
	}

	tok, err := s.cfg.Key.MintAccessToken(MintParams{
		Issuer:    iss,
		Subject:   sub,
		Audience:  aud,
		TTL:       ttl,
		ExpOffset: expOffset,
		Now:       s.cfg.Now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "mint failed")
		return
	}

	expiresIn := int(ttl.Seconds())
	if expOffset != 0 {
		// Still report a nominal expires_in for clients; token exp is already set.
		if expOffset > 0 {
			expiresIn = int(expOffset.Seconds())
		} else {
			expiresIn = 0
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
		"audience":     aud,
		// Secret-free labels only — never echo client_secret.
		"lab_only": true,
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func errf(msg string) error {
	return &labError{msg: msg}
}

type labError struct{ msg string }

func (e *labError) Error() string { return "authlab: " + e.msg }

// AbsoluteIssuerURL normalizes a base URL for issuer advertising.
func AbsoluteIssuerURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", errf("empty issuer")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errf("issuer must be absolute http(s) URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errf("issuer scheme must be http or https")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
