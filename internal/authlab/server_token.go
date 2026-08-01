package authlab

import (
	"net/http"
	"strings"
	"time"
)

// TokenConfig configures the mock AgentCore / token-exchange peer (HOST-015).
type TokenConfig struct {
	// Issuer embedded when minting JWT access tokens (same lab IdP issuer).
	Issuer string
	// DefaultAudience Jenkins API audience.
	DefaultAudience string
	// Key signs lab JWTs (same key material as mock-oidc).
	Key *LabKey
	// Now optional clock.
	Now func() time.Time
}

// TokenServer simulates AgentCore/Entra token exchange / OBO responses.
// Response shape is compatible with gateway.HTTPTokenFetcher JSON fields.
// Note: HTTPTokenFetcher requires https token URLs in production code; lab
// smoke uses curl over loopback HTTP. TLS residual documented in oauth-lab README.
type TokenServer struct {
	cfg TokenConfig
}

// NewTokenServer builds the mock token peer.
func NewTokenServer(cfg TokenConfig) (*TokenServer, error) {
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
	cfg.Issuer = iss
	return &TokenServer{cfg: cfg}, nil
}

// Handler returns the HTTP mux for mock-token.
func (s *TokenServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /oauth2/token", s.handleToken)
	mux.HandleFunc("GET /token", s.handleToken) // scenario query convenience
	return mux
}

func (s *TokenServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "mock-token"})
}

func (s *TokenServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	}
	_ = r.ParseForm()

	scenario := strings.ToLower(strings.TrimSpace(firstNonEmpty(
		r.URL.Query().Get("scenario"),
		r.FormValue("scenario"),
	)))

	// Fail closed scenarios — never mint shared SA tokens.
	switch scenario {
	case "error", "server_error":
		writeError(w, http.StatusInternalServerError, "server_error", "lab simulated failure")
		return
	case "consent", "consent_required":
		// 403 with authorization_url metadata only (no tokens). Compatible with
		// gateway.HTTPTokenFetcher consent path (401/403 + consent fields).
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":             "consent_required",
			"authorization_url": "http://127.0.0.1:18083/lab-consent",
			"session_id":        "lab-consent-session",
			"provider":          "mock-agentcore",
		})
		return
	case "oauth_error":
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_grant",
		})
		return
	}

	aud := firstNonEmpty(
		r.FormValue("audience"),
		r.FormValue("resource"),
		r.URL.Query().Get("audience"),
		s.cfg.DefaultAudience,
	)
	sub := firstNonEmpty(
		r.FormValue("subject"),
		r.FormValue("sub"),
		r.URL.Query().Get("sub"),
		"lab-gateway-user",
	)

	switch scenario {
	case "wrong_audience", "wrong-aud":
		aud = "https://graph.microsoft.com"
	case "expired":
		tok, err := s.cfg.Key.MintAccessToken(MintParams{
			Issuer:    s.cfg.Issuer,
			Subject:   sub,
			Audience:  aud,
			ExpOffset: -2 * time.Hour,
			Now:       s.cfg.Now,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "mint failed")
			return
		}
		// Return token + audience label; callers must still validate exp.
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":      tok,
			"token_type":        "Bearer",
			"expires_in":        0,
			"audience":          aud,
			"jenkins_principal": sub,
			"lab_only":          true,
		})
		return
	}

	tok, err := s.cfg.Key.MintAccessToken(MintParams{
		Issuer:   s.cfg.Issuer,
		Subject:  sub,
		Audience: aud,
		TTL:      5 * time.Minute,
		Now:      s.cfg.Now,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "mint failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      tok,
		"token_type":        "Bearer",
		"expires_in":        300,
		"audience":          aud,
		"jenkins_principal": sub,
		"lab_only":          true,
	})
}
