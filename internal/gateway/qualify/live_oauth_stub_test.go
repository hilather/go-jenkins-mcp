//go:build live_oauth

package qualify_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// Opt-in residual pin against testdata/oauth-lab (HOST-012…015).
//
//	make live-oauth-up
//	go test -tags=live_oauth ./internal/gateway/qualify/ -count=1
//	make live-oauth-down
//
// Skips when the lab is not reachable so accidental -tags=live_oauth without
// compose does not fail CI. Default `go test` / `make test` never include this
// file (build tag).
//
// What this suite proves when the lab is up:
//   - mock-token / mock-oidc / mock-rs healthz reachability
//   - production HTTPTokenFetcher rejects plain http:// lab URLs (https residual)
//   - Mode C AgentCore Live Obtain via HTTPTokenFetcher against mock-token shape
//     (TLS test shim → HTTP lab peer; not production Entra / AgentCore vault)
//   - success, wrong audience, consent metadata, server-error fail-closed; canary
//     token never in errors/String/Status
//
// Not a production Entra / AgentCore pin — see docs/gateway/qualification.md §7
// and testdata/oauth-lab/README.md residuals.

func TestLiveOAuth_LabReachableOrSkip(t *testing.T) {
	base := labTokenBase()
	requireHealthz(t, base+"/healthz", "oauth-lab mock-token (HOST-015)")
	t.Logf("oauth-lab mock-token healthy at %s (residual live pin only; not Entra)", base+"/healthz")
}

func TestLiveOAuth_MockOIDCHealthOrSkip(t *testing.T) {
	host := envOr("OAUTH_HOST_BIND", "127.0.0.1")
	port := envOr("OAUTH_OIDC_PORT", "18081")
	health := "http://" + host + ":" + port + "/healthz"
	requireHealthz(t, health, "oauth-lab mock-oidc")
	t.Logf("oauth-lab mock-oidc healthy at %s", health)
}

func TestLiveOAuth_MockRSHealthOrSkip(t *testing.T) {
	host := envOr("OAUTH_HOST_BIND", "127.0.0.1")
	port := envOr("OAUTH_RS_PORT", "18082")
	health := "http://" + host + ":" + port + "/healthz"
	requireHealthz(t, health, "oauth-lab mock-rs")
	t.Logf("oauth-lab mock-rs healthy at %s (not jwt-auth-filter production pin)", health)
}

// TestLiveOAuth_HTTPTokenFetcher_HTTPURLRejected proves production
// HTTPTokenFetcher remains https-only when pointed at the raw lab HTTP peer.
// Lab residual: mock-token is loopback HTTP; TLS termination is not provided by
// compose (see oauth-lab README).
func TestLiveOAuth_HTTPTokenFetcher_HTTPURLRejected(t *testing.T) {
	base := labTokenBase()
	requireHealthz(t, base+"/healthz", "oauth-lab mock-token")

	cfg := labAgentCoreCfg(base + "/token")
	f := gateway.NewHTTPTokenFetcher(&http.Client{Timeout: 5 * time.Second})
	_, err := f.FetchJenkinsCredential(context.Background(), labCaller(), cfg)
	if err == nil {
		t.Fatal("HTTPTokenFetcher must reject http:// lab token URL")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("want https residual reject, got: %v", err)
	}
	t.Log("HTTPTokenFetcher https-only pin holds against raw lab HTTP (TLS residual)")
}

// TestLiveOAuth_ModeC_ObtainSuccess exercises AgentCore Live Obtain +
// HTTPTokenFetcher against mock-token through a local TLS reverse proxy.
// The lab peer itself stays plain HTTP; the shim satisfies the production
// https-only contract without claiming Entra Done.
func TestLiveOAuth_ModeC_ObtainSuccess(t *testing.T) {
	base := labTokenBase()
	requireHealthz(t, base+"/healthz", "oauth-lab mock-token")

	proxy := startLabTLSProxy(t, base)
	cfg := labAgentCoreCfg(proxy.URL + "/token")
	client := labTLSClient()
	fetcher := gateway.NewHTTPTokenFetcher(client)

	// Direct fetcher path (HTTPTokenFetcher shape vs lab JSON).
	cred, err := fetcher.FetchJenkinsCredential(context.Background(), labCaller(), cfg)
	if err != nil {
		t.Fatalf("HTTPTokenFetcher against lab (via TLS shim): %v", err)
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		t.Fatal("empty access_token from lab")
	}
	token := cred.AccessToken
	if cred.JenkinsPrincipal == "" {
		t.Fatal("expected jenkins_principal from mock-token")
	}
	assertNoTokenLeak(t, token, cred.String())

	// AgentCore Live Obtain + Bearer HTTP auth shape + cache hit.
	cache := gateway.NewMemoryTokenCache(time.Hour)
	p, err := gateway.NewAgentCoreProvider(cfg, cache)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = fetcher

	auth, err := gateway.ObtainHTTPAuth(context.Background(), p, labCaller())
	if err != nil {
		assertNoTokenLeak(t, token, err.Error())
		t.Fatalf("AgentCore Live Obtain: %v", err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBearer || auth.Username != "" {
		t.Fatalf("Mode C must be Bearer without username: %+v", auth)
	}
	if auth.Token == "" {
		t.Fatal("empty Bearer token")
	}
	assertNoTokenLeak(t, auth.Token, auth.String(), p.Status(context.Background()).ErrorMessageSafe)

	// Cache hit: second Obtain must not fail and must not re-expose secrets.
	auth2, err := gateway.ObtainHTTPAuth(context.Background(), p, labCaller())
	if err != nil {
		assertNoTokenLeak(t, auth.Token, err.Error())
		t.Fatalf("cache hit Obtain: %v", err)
	}
	if auth2.Token != auth.Token {
		t.Fatal("cache hit returned different token material")
	}
	assertNoTokenLeak(t, auth.Token, auth2.String())

	st := p.Status(context.Background())
	if !st.Ready {
		t.Fatalf("Live+Fetcher Status should be Ready: %+v", st)
	}
	t.Logf("Mode C Obtain success via TLS shim→mock-token principal=%q (not Entra; TLS residual)", cred.JenkinsPrincipal)
}

// TestLiveOAuth_ModeC_WrongAudienceFailClosed posts against mock-token
// scenario=wrong_audience; HTTPTokenFetcher must fail closed without token.
func TestLiveOAuth_ModeC_WrongAudienceFailClosed(t *testing.T) {
	base := labTokenBase()
	requireHealthz(t, base+"/healthz", "oauth-lab mock-token")

	proxy := startLabTLSProxy(t, base)
	// Query scenario is preserved through the TLS shim.
	cfg := labAgentCoreCfg(proxy.URL + "/token?scenario=wrong_audience")
	f := gateway.NewHTTPTokenFetcher(labTLSClient())

	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = f

	cred, err := p.Obtain(context.Background(), labCaller())
	if err == nil || cred.AccessToken != "" {
		t.Fatalf("wrong audience must fail closed without token: cred=%v err=%v", cred, err)
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v want authentication: %v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Fatalf("want audience wording: %v", err)
	}
	// Never embed raw token material (lab may still mint a JWT body).
	if strings.Contains(err.Error(), "eyJ") {
		t.Fatalf("JWT-looking material in error: %v", err)
	}
	t.Log("wrong_audience lab fixture fail-closed via HTTPTokenFetcher (not Entra)")
}

// TestLiveOAuth_ModeC_ConsentMetadataOnly posts scenario=consent; surfaces
// authorization_url + session only (no access/refresh tokens).
func TestLiveOAuth_ModeC_ConsentMetadataOnly(t *testing.T) {
	base := labTokenBase()
	requireHealthz(t, base+"/healthz", "oauth-lab mock-token")

	proxy := startLabTLSProxy(t, base)
	cfg := labAgentCoreCfg(proxy.URL + "/token?scenario=consent")
	// Consent fixture is more natural for authorization_code flow mode.
	cfg.Mode = gateway.ModeAuthorizationCode
	f := gateway.NewHTTPTokenFetcher(labTLSClient())

	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = f

	cred, err := p.Obtain(context.Background(), labCaller())
	if err == nil || cred.AccessToken != "" {
		t.Fatalf("consent path must fail closed without token: cred=%v err=%v", cred, err)
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil {
		t.Fatalf("want ConsentRequired got %T %v", err, err)
	}
	if !cr.Info.Valid() {
		t.Fatalf("consent info invalid: %+v", cr.Info)
	}
	blob := err.Error() + " " + cr.Info.String() + " " + cr.Info.AuthorizationURL + " " + cr.Info.SessionID
	for _, bad := range []string{"access_token=", "refresh_token=", "client_secret=", "eyJ"} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
			t.Fatalf("consent surface contained %q", bad)
		}
	}
	t.Logf("consent metadata only auth_url_len=%d session=%q (not Entra 3LO browser)",
		len(cr.Info.AuthorizationURL), cr.Info.SessionID)
}

// TestLiveOAuth_ModeC_ServerErrorFailClosed posts scenario=error (500).
func TestLiveOAuth_ModeC_ServerErrorFailClosed(t *testing.T) {
	base := labTokenBase()
	requireHealthz(t, base+"/healthz", "oauth-lab mock-token")

	proxy := startLabTLSProxy(t, base)
	cfg := labAgentCoreCfg(proxy.URL + "/token?scenario=error")
	f := gateway.NewHTTPTokenFetcher(labTLSClient())

	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = f

	cred, err := p.Obtain(context.Background(), labCaller())
	if err == nil || cred.AccessToken != "" {
		t.Fatalf("server_error must fail closed without token: cred=%v err=%v", cred, err)
	}
	code := apperr.CodeOf(err)
	if code != apperr.CodeUpstreamProtocol && code != apperr.CodeAuthentication {
		t.Fatalf("code %v want upstream/authentication: %v", code, err)
	}
	if strings.Contains(err.Error(), "eyJ") {
		t.Fatalf("token-looking material in error: %v", err)
	}
	t.Log("mock-token server_error fail-closed (not Entra outage pin)")
}

// --- helpers ---

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func labTokenBase() string {
	base := strings.TrimSpace(os.Getenv("OAUTH_LAB_TOKEN_URL"))
	if base == "" {
		host := envOr("OAUTH_HOST_BIND", "127.0.0.1")
		base = "http://" + host + ":" + envOr("OAUTH_TOKEN_PORT", "18083")
	}
	return strings.TrimRight(base, "/")
}

func labAudience() string {
	// Must match LAB_AUDIENCE in make live-oauth-up / oauth-lab compose.
	return envOr("LAB_AUDIENCE", "jenkins-api")
}

func labCaller() gateway.Caller {
	return gateway.Caller{
		Subject:    "live-oauth-user",
		Tenant:     "lab-tenant",
		WorkloadID: "lab-wl",
		ProfileID:  contracts.ProfileID("lab-corp"),
	}
}

func labAgentCoreCfg(tokenURL string) gateway.AgentCoreConfig {
	// AS base is Entra-shaped (never Jenkins). Token endpoint is the TLS shim
	// absolute URL → mock-token HTTP peer (HOST-015 residual).
	return gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/lab-tenant/v2.0",
		TokenEndpoint:              tokenURL,
		Audience:                   labAudience(),
		ClientID:                   "lab-public-client",
		Mode:                       gateway.ModeTokenExchange,
		JenkinsBaseURL:             "https://jenkins.example.com",
	}
}

func requireHealthz(t *testing.T, health, label string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(health)
	if err != nil {
		t.Skipf("%s not up (%s): %v — run: make live-oauth-up", label, health, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("%s healthz status %d at %s — run: make live-oauth-up", label, resp.StatusCode, health)
	}
}

// startLabTLSProxy forwards HTTPS requests from HTTPTokenFetcher to the plain
// HTTP oauth-lab mock-token peer. Test-only residual: production labs should
// terminate TLS at a real AS; compose remains loopback HTTP.
func startLabTLSProxy(t *testing.T, labBase string) *httptest.Server {
	t.Helper()
	labBase = strings.TrimRight(labBase, "/")
	upstream := &http.Client{Timeout: 10 * time.Second}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := labBase + r.URL.Path
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, gateway.MaxTokenFetchBodyBytes+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadGateway)
			return
		}
		_ = r.Body.Close()
		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "build upstream", http.StatusBadGateway)
			return
		}
		// Forward content negotiation only — never attach secrets.
		if ct := r.Header.Get("Content-Type"); ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		if ac := r.Header.Get("Accept"); ac != "" {
			req.Header.Set("Accept", ac)
		}
		resp, err := upstream.Do(req)
		if err != nil {
			http.Error(w, "upstream", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, gateway.MaxTokenFetchBodyBytes+1))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func labTLSClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test TLS shim only
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func assertNoTokenLeak(t *testing.T, token string, surfaces ...string) {
	t.Helper()
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	for _, s := range surfaces {
		if s == "" {
			continue
		}
		if strings.Contains(s, token) {
			t.Fatalf("token material leaked into surface %q", truncateForLog(s, 80))
		}
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
