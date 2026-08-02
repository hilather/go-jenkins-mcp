package gateway_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// OAUTH-010 offline Mode C prototype matrix (no live Entra Done claim).
// Groups Live=false, Live=true nil Fetcher, authorization_code ConsentRequired,
// token_exchange Bearer + wrong audience, and HTTPTokenFetcher mock AS paths.
// Production AgentCore / Entra 3LO+OBO pin remains residual (GWY-003).
// Opt-in lab: make live-oauth-* HOST-015 mock-token peer (not default make test).
func TestOAUTH010_ModeC_OfflinePrototypeMatrix(t *testing.T) {
	t.Parallel()
	const canary = "OAUTH010_modeC_canary_never_log_xyz789"
	caller := gateway.Caller{
		Subject:    "oauth010-user",
		Tenant:     "t1",
		WorkloadID: "wl1",
		ProfileID:  contracts.ProfileID("corp"),
	}

	t.Run("live_false_not_configured", func(t *testing.T) {
		t.Parallel()
		cfg := validCfg()
		cfg.Mode = gateway.ModeTokenExchange
		p, err := gateway.NewAgentCoreProvider(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Even with a Fetcher that would succeed, Live=false must fail closed.
		p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
			return gateway.Credential{AccessToken: canary}, nil
		})
		if p.Live {
			t.Fatal("default Live must be false")
		}
		cred, err := p.Obtain(context.Background(), caller)
		if err == nil || cred.AccessToken != "" {
			t.Fatalf("Live=false must not_configured without token: cred=%v err=%v", cred, err)
		}
		if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
			t.Fatalf("code %v", apperr.CodeOf(err))
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "not configured") && !strings.Contains(low, "not_configured") {
			t.Fatalf("want not_configured wording: %v", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("canary in Live=false error")
		}
		if p.Status(context.Background()).Ready {
			t.Fatal("Ready must be false when Live=false")
		}
	})

	t.Run("live_true_nil_fetcher_fail_closed", func(t *testing.T) {
		t.Parallel()
		p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
		if err != nil {
			t.Fatal(err)
		}
		p.Live = true
		p.Fetcher = nil
		cred, err := p.Obtain(context.Background(), caller)
		if err == nil || cred.AccessToken != "" {
			t.Fatalf("Live=true without Fetcher must fail closed: cred=%v err=%v", cred, err)
		}
		if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
			t.Fatalf("code %v", apperr.CodeOf(err))
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "tokenfetcher") && !strings.Contains(low, "fetcher") {
			t.Fatalf("want Fetcher wording: %v", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("canary in nil-fetcher error")
		}
		st := p.Status(context.Background())
		if st.Ready {
			t.Fatalf("Ready must be false without Fetcher: %+v", st)
		}
	})

	t.Run("authorization_code_consent_metadata_only", func(t *testing.T) {
		t.Parallel()
		cfg := validCfg()
		cfg.Mode = gateway.ModeAuthorizationCode
		p, err := gateway.NewAgentCoreProvider(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		p.Live = true
		authURL := "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=public&state=oauth010"
		sessionID := "sess-oauth010-authcode"
		p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
			if gateway.NormalizeMode(cfg.Mode) != gateway.ModeAuthorizationCode {
				return gateway.Credential{}, fmt.Errorf("unexpected mode %s", cfg.Mode)
			}
			return gateway.Credential{}, gateway.NewConsentRequired(gateway.ConsentInfo{
				AuthorizationURL: authURL,
				SessionID:        sessionID,
				Provider:         "agentcore",
			})
		})
		cred, err := p.Obtain(context.Background(), caller)
		if err == nil || cred.AccessToken != "" {
			t.Fatalf("authorization_code consent must fail closed without token: cred=%v err=%v", cred, err)
		}
		cr, ok := gateway.AsConsentRequired(err)
		if !ok || cr == nil {
			t.Fatalf("want ConsentRequired got %T %v", err, err)
		}
		if !cr.Info.Valid() {
			t.Fatalf("consent info invalid: %+v", cr.Info)
		}
		if cr.Info.AuthorizationURL != authURL || cr.Info.SessionID != sessionID {
			t.Fatalf("consent metadata mismatch: %+v", cr.Info)
		}
		// Progressive helpers expose URL + session only.
		if cr.ConsentAuthorizationURL() != authURL || cr.ConsentSessionID() != sessionID {
			t.Fatalf("progressive helpers: url=%q sid=%q", cr.ConsentAuthorizationURL(), cr.ConsentSessionID())
		}
		blob := err.Error() + " " + cr.Info.String() + " " + fmt.Sprint(cr.Info.StatusMap())
		for _, bad := range []string{canary, "access_token=", "refresh_token=", "client_secret="} {
			if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
				t.Fatalf("consent surface contained %q", bad)
			}
		}
	})

	t.Run("token_exchange_bearer_jenkins_audience", func(t *testing.T) {
		t.Parallel()
		cfg := validCfg()
		cfg.Mode = gateway.ModeTokenExchange
		cache := gateway.NewMemoryTokenCache(time.Hour)
		p, err := gateway.NewAgentCoreProvider(cfg, cache)
		if err != nil {
			t.Fatal(err)
		}
		p.Live = true
		wantTok := canary + "-obo"
		p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
			if gateway.NormalizeMode(cfg.Mode) != gateway.ModeTokenExchange {
				return gateway.Credential{}, fmt.Errorf("unexpected mode %s", cfg.Mode)
			}
			return gateway.Credential{
				AccessToken:      wantTok,
				ExpiresAt:        time.Now().Add(time.Hour),
				JenkinsPrincipal: "jp-" + c.Subject,
				Mode:             gateway.ModeTokenExchange,
			}, nil
		})
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, caller)
		if err != nil {
			t.Fatal(err)
		}
		if ha.Scheme != gateway.HTTPAuthSchemeBearer || ha.Username != "" {
			t.Fatalf("token_exchange must be Bearer: %+v", ha)
		}
		if ha.Token != wantTok {
			t.Fatal("token material mismatch")
		}
		if strings.Contains(ha.String(), canary) {
			t.Fatal("HTTPAuth.String leaked canary")
		}
		// Cache hit: second Obtain does not re-fetch.
		var calls atomic.Int32
		p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
			calls.Add(1)
			return gateway.Credential{AccessToken: canary + "-should-not-run"}, nil
		})
		ha2, err := gateway.ObtainHTTPAuth(context.Background(), p, caller)
		if err != nil {
			t.Fatal(err)
		}
		if ha2.Token != wantTok || calls.Load() != 0 {
			t.Fatalf("cache hit broken: token=%q calls=%d", ha2.Token, calls.Load())
		}
	})

	t.Run("token_exchange_wrong_audience_fail", func(t *testing.T) {
		t.Parallel()
		cfg := validCfg()
		cfg.Mode = gateway.ModeOBO // alias → token_exchange
		p, err := gateway.NewAgentCoreProvider(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		p.Live = true
		p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
			// Same residual shape as HTTPTokenFetcher wrong-audience path.
			return gateway.Credential{}, apperr.New(apperr.CodeAuthentication,
				"token audience does not match configured Jenkins API resource")
		})
		cred, err := p.Obtain(context.Background(), caller)
		if err == nil || cred.AccessToken != "" {
			t.Fatalf("wrong audience must fail closed: cred=%v err=%v", cred, err)
		}
		if apperr.CodeOf(err) != apperr.CodeAuthentication {
			t.Fatalf("code %v", apperr.CodeOf(err))
		}
		if !strings.Contains(strings.ToLower(err.Error()), "audience") {
			t.Fatalf("audience wording: %v", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("canary in wrong-audience error")
		}
	})

	t.Run("http_token_fetcher_mock_as", func(t *testing.T) {
		t.Parallel()
		// HTTPS mock AS — same contract as TestHTTPTokenFetcher_* suite
		// (grouped under OAUTH-010 for prototype matrix evidence).
		m := startOAUTH010MockAS(t, canary)
		cfg := validCfg()
		cfg.Mode = gateway.ModeTokenExchange
		cfg.TokenEndpoint = m.server.URL + "/oauth2/v2.0/token"
		fetcher := gateway.NewHTTPTokenFetcher(m.tlsClient())

		// Success Bearer + Jenkins audience.
		cred, err := fetcher.FetchJenkinsCredential(context.Background(), caller, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if cred.AccessToken != canary {
			t.Fatal("token mismatch")
		}
		if cred.JenkinsPrincipal != "alice" {
			t.Fatalf("principal %q", cred.JenkinsPrincipal)
		}
		if gateway.NormalizeMode(cred.Mode) != gateway.ModeTokenExchange {
			t.Fatalf("mode %s", cred.Mode)
		}
		if strings.Contains(cred.String(), canary) {
			t.Fatal("Credential.String leaked canary")
		}

		// Wrong audience fail closed.
		m.audience = "api://graph.microsoft.com"
		_, err = fetcher.FetchJenkinsCredential(context.Background(), caller, cfg)
		if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
			t.Fatalf("want audience fail: %v", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("canary in HTTPTokenFetcher wrong-audience error")
		}
		m.audience = "api://jenkins-api"

		// ConsentRequired metadata only (authorization_code residual shape).
		m.consentURL = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=oauth010"
		m.consentSession = "sess-oauth010-http"
		cfg.Mode = gateway.ModeAuthorizationCode
		_, err = fetcher.FetchJenkinsCredential(context.Background(), caller, cfg)
		cr, ok := gateway.AsConsentRequired(err)
		if !ok || cr == nil || !cr.Info.Valid() {
			t.Fatalf("want ConsentRequired: %v", err)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("canary in HTTPTokenFetcher consent error")
		}
	})

	t.Run("mode_matrix_residual_oauth010", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{
			gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
		}
		mx, err := gateway.ModeMatrixFromEnviron(func(k string) string { return env[k] })
		if err != nil {
			t.Fatal(err)
		}
		if mx.Primary != gateway.CredentialModeAgentCore {
			t.Fatalf("primary %s", mx.Primary)
		}
		if mx.Residual == "" || !strings.Contains(mx.Residual, "OAUTH-010") {
			t.Fatalf("Mode C residual must note OAUTH-010 live pin: %q", mx.Residual)
		}
		if !strings.Contains(strings.ToLower(mx.Residual), "live") &&
			!strings.Contains(strings.ToLower(mx.Residual), "entra") &&
			!strings.Contains(strings.ToLower(mx.Residual), "agentcore") {
			t.Fatalf("residual must be honest about live AgentCore/Entra: %q", mx.Residual)
		}
	})
}

// oauth010MockAS is a test-only HTTPS token endpoint for the OAUTH-010 suite
// (mirrors http_fetcher_test mockAS; kept local so the named suite is self-contained).
type oauth010MockAS struct {
	server         *httptest.Server
	accessToken    string
	audience       string
	consentURL     string
	consentSession string
}

func startOAUTH010MockAS(t *testing.T, accessToken string) *oauth010MockAS {
	t.Helper()
	m := &oauth010MockAS{
		accessToken: accessToken,
		audience:    "api://jenkins-api",
	}
	m.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		if m.consentURL != "" && m.consentSession != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "consent_required",
				"authorization_url": m.consentURL,
				"session_id":        m.consentSession,
				"provider":          "agentcore",
			})
			return
		}
		resp := map[string]any{
			"access_token":      m.accessToken,
			"token_type":        "Bearer",
			"expires_in":        3600,
			"jenkins_principal": "alice",
			"audience":          m.audience,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *oauth010MockAS) tlsClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test mock only
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
