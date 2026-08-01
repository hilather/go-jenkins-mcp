package gateway_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// mockAS is a test-only HTTPS token endpoint simulating AgentCore/AS responses.
type mockAS struct {
	server *httptest.Server
	calls  atomic.Int32

	// Behavior knobs
	accessToken      string
	expiresIn        int
	audience         string // when set, returned in JSON (wrong-audience tests)
	jenkinsPrincipal string
	status           int
	consentURL       string
	consentSession   string
	oauthError       string
	bodyOverride     []byte
}

func startMockAS(t *testing.T) *mockAS {
	t.Helper()
	m := &mockAS{
		accessToken:      canaryAccessToken,
		expiresIn:        3600,
		audience:         "api://jenkins-api",
		jenkinsPrincipal: "alice",
		status:           http.StatusOK,
	}
	m.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.calls.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		// Bound body read (never log).
		_, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()

		if len(m.bodyOverride) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(m.status)
			_, _ = w.Write(m.bodyOverride)
			return
		}

		// Consent path
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

		if m.oauthError != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": m.oauthError})
			return
		}

		resp := map[string]any{
			"access_token":      m.accessToken,
			"token_type":        "Bearer",
			"expires_in":        m.expiresIn,
			"jenkins_principal": m.jenkinsPrincipal,
		}
		if m.audience != "" {
			resp["audience"] = m.audience
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(m.status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockAS) tlsClient() *http.Client {
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

func cfgWithTokenEndpoint(tokenURL string) gateway.AgentCoreConfig {
	cfg := validCfg()
	cfg.TokenEndpoint = tokenURL
	// AS base must stay Entra-shaped (not Jenkins); token URL is the mock.
	return cfg
}

func TestHTTPTokenFetcher_SuccessAndCacheViaProvider(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	cfg := cfgWithTokenEndpoint(m.server.URL + "/oauth2/v2.0/token")
	fetcher := gateway.NewHTTPTokenFetcher(m.tlsClient())

	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = fetcher

	c1, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	if c1.AccessToken != canaryAccessToken {
		t.Fatal("token")
	}
	if c1.JenkinsPrincipal != "alice" {
		t.Fatalf("principal %q", c1.JenkinsPrincipal)
	}
	if m.calls.Load() != 1 {
		t.Fatalf("calls %d", m.calls.Load())
	}

	c2, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	if c2.AccessToken != canaryAccessToken {
		t.Fatal("cache")
	}
	if m.calls.Load() != 1 {
		t.Fatalf("mock called again on cache hit: %d", m.calls.Load())
	}
	if strings.Contains(c1.String(), canaryAccessToken) {
		t.Fatal("String leak")
	}
}

func TestHTTPTokenFetcher_WrongAudience(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	m.audience = "api://graph.microsoft.com" // residual wrong resource
	cfg := cfgWithTokenEndpoint(m.server.URL + "/token")
	f := gateway.NewHTTPTokenFetcher(m.tlsClient())
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	if err == nil {
		t.Fatal("expected audience fail")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary in error")
	}
}

func TestHTTPTokenFetcher_ConsentRequired(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	m.consentURL = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=x"
	m.consentSession = "sess-mock-1"
	cfg := cfgWithTokenEndpoint(m.server.URL + "/token")
	f := gateway.NewHTTPTokenFetcher(m.tlsClient())
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	cr, ok := gateway.AsConsentRequired(err)
	if !ok {
		t.Fatalf("want consent got %v", err)
	}
	if !cr.Info.Valid() {
		t.Fatalf("%+v", cr.Info)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary")
	}
}

func TestHTTPTokenFetcher_RejectHTTPScheme(t *testing.T) {
	t.Parallel()
	// Plain httptest is http — must be rejected by https-only check.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("must not be called")
	}))
	t.Cleanup(srv.Close)
	cfg := cfgWithTokenEndpoint(srv.URL + "/token")
	f := gateway.NewHTTPTokenFetcher(nil)
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("want https reject: %v", err)
	}
}

func TestHTTPTokenFetcher_MissingTokenEndpoint(t *testing.T) {
	t.Parallel()
	cfg := validCfg()
	cfg.TokenEndpoint = ""
	f := gateway.NewHTTPTokenFetcher(nil)
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPTokenFetcher_Cancel(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	cfg := cfgWithTokenEndpoint(m.server.URL + "/token")
	f := gateway.NewHTTPTokenFetcher(m.tlsClient())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.FetchJenkinsCredential(ctx, testCaller(), cfg)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPTokenFetcher_OAuthErrorNoTokenInMessage(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	m.oauthError = "invalid_grant"
	// Also try planting canary in error_description via body override.
	m.bodyOverride = []byte(`{"error":"invalid_grant","error_description":"token=` + canaryAccessToken + `"}`)
	m.status = http.StatusBadRequest
	cfg := cfgWithTokenEndpoint(m.server.URL + "/token")
	f := gateway.NewHTTPTokenFetcher(m.tlsClient())
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatalf("canary leaked: %v", err)
	}
}

func TestHTTPTokenFetcher_RelativeTokenEndpoint(t *testing.T) {
	t.Parallel()
	// Relative path requires AS base to form absolute URL; AS base is https://login...
	// which is not our mock — so we only assert resolve + https of AS base path fails
	// network (not_found style) OR we set TokenEndpoint absolute.
	// Absolute is the supported mock path; relative under Entra would call real host —
	// reject by ensuring relative resolves to https and request fails without leak.
	cfg := validCfg()
	cfg.TokenEndpoint = "/oauth2/v2.0/token"
	f := gateway.NewHTTPTokenFetcher(&http.Client{
		Timeout: 2 * time.Second,
		// No real network to Entra in CI ideally; short timeout.
		Transport: &http.Transport{
			// Force fail without dialing Entra if possible — use bogus dial via proxy.
			Proxy: func(*http.Request) (*url.URL, error) {
				return nil, context.Canceled
			},
		},
	})
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	if err == nil {
		t.Fatal("expected failure (no real Entra)")
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary")
	}
}

func TestHTTPTokenFetcher_NoRedirects(t *testing.T) {
	t.Parallel()
	// First hop HTTPS redirects — client must not follow.
	var hops atomic.Int32
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": canaryAccessToken,
			"expires_in":   60,
			"audience":     "api://jenkins-api",
		})
	}))
	t.Cleanup(final.Close)

	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, final.URL+"/token", http.StatusFound)
	}))
	t.Cleanup(redir.Close)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Default would follow; HTTPTokenFetcher injects no-redirect when Client is nil.
		// When Client is provided, operator owns redirect policy — default New uses no redirect.
	}
	// Use NewHTTPTokenFetcher(nil) pattern via explicit no-redirect client matching production.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	cfg := cfgWithTokenEndpoint(redir.URL + "/token")
	f := gateway.NewHTTPTokenFetcher(client)
	_, err := f.FetchJenkinsCredential(context.Background(), testCaller(), cfg)
	// Redirect response is not 200 JSON with token → fail closed.
	if err == nil {
		t.Fatal("expected fail on redirect")
	}
	if hops.Load() != 1 {
		t.Fatalf("followed redirect: hops=%d", hops.Load())
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary")
	}
}
