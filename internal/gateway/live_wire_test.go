package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// GWY-001: EnableLiveHTTPFetcher requires token endpoint (fail closed).
func TestEnableLiveHTTPFetcher_RequiresTokenEndpoint(t *testing.T) {
	t.Parallel()
	cfg := validCfg()
	cfg.TokenEndpoint = ""
	p, err := gateway.NewAgentCoreProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Live || p.Fetcher != nil {
		t.Fatal("default must be Live=false Fetcher=nil")
	}
	err = gateway.EnableLiveHTTPFetcher(p, cfg)
	if err == nil {
		t.Fatal("expected fail closed without token endpoint")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "token endpoint") && !strings.Contains(low, "not_configured") {
		t.Fatalf("want token endpoint / not_configured message: %v", err)
	}
	// Must not partially enable Live.
	if p.Live || p.Fetcher != nil {
		t.Fatal("failed Enable must leave Live=false Fetcher=nil")
	}
	if p.Status(context.Background()).Ready {
		t.Fatal("must not be Ready after failed Enable")
	}
}

// GWY-001: EnableLiveHTTPFetcher with token endpoint sets Live + Fetcher; Ready.
func TestEnableLiveHTTPFetcher_SuccessReady(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	cfg := cfgWithTokenEndpoint(m.server.URL + "/oauth2/v2.0/token")
	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.EnableLiveHTTPFetcherWithClient(p, cfg, m.tlsClient()); err != nil {
		t.Fatal(err)
	}
	if !p.Live || p.Fetcher == nil {
		t.Fatal("Live+Fetcher required after Enable")
	}
	st := p.Status(context.Background())
	if !st.Ready || !st.Configured {
		t.Fatalf("status Ready=%v Configured=%v msg=%s", st.Ready, st.Configured, st.ErrorMessageSafe)
	}
	// Obtain against mock AS (integration of Enable + HTTPTokenFetcher).
	cred, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessToken != canaryAccessToken {
		t.Fatal("token")
	}
	if strings.Contains(cred.String(), canaryAccessToken) {
		t.Fatal("canary in String")
	}
}

// GWY-001: nil provider fails closed.
func TestEnableLiveHTTPFetcher_NilProvider(t *testing.T) {
	t.Parallel()
	err := gateway.EnableLiveHTTPFetcher(nil, validCfg())
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("got %v", err)
	}
}

// GWY-001: absolute http:// token endpoint rejected (https-only).
func TestEnableLiveHTTPFetcher_RejectHTTPTokenURL(t *testing.T) {
	t.Parallel()
	cfg := validCfg()
	cfg.TokenEndpoint = "http://login.example.com/token"
	p, err := gateway.NewAgentCoreProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = gateway.EnableLiveHTTPFetcher(p, cfg)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Fatalf("want https reject: %v", err)
	}
	if p.Live {
		t.Fatal("must not set Live on reject")
	}
}

// GWY-001: LiveEnabledFromEnviron + ApplyLiveHTTPFetcherFromEnviron wiring.
func TestApplyLiveHTTPFetcherFromEnviron(t *testing.T) {
	t.Parallel()
	cfg := validCfg()
	cfg.TokenEndpoint = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
	p, err := gateway.NewAgentCoreProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Live env off → no-op.
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if gateway.LiveEnabledFromEnviron(getenv) {
		t.Fatal("default Live off")
	}
	if err := gateway.ApplyLiveHTTPFetcherFromEnviron(p, cfg, getenv); err != nil {
		t.Fatal(err)
	}
	if p.Live {
		t.Fatal("Live must stay false when env off")
	}

	// Live=1 without token endpoint → fail (use cfg with empty token).
	env[gateway.EnvGatewayLive] = "1"
	cfgNoTok := validCfg()
	cfgNoTok.TokenEndpoint = ""
	p2, err := gateway.NewAgentCoreProvider(cfgNoTok, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = gateway.ApplyLiveHTTPFetcherFromEnviron(p2, cfgNoTok, getenv)
	if err == nil {
		t.Fatal("Live=1 without token endpoint must fail")
	}

	// Live=1 with token → Ready.
	if err := gateway.ApplyLiveHTTPFetcherFromEnviron(p, cfg, getenv); err != nil {
		t.Fatal(err)
	}
	if !p.Live || p.Fetcher == nil || !p.Status(context.Background()).Ready {
		t.Fatalf("want Ready after Live=1: live=%v fetcher=%v st=%+v", p.Live, p.Fetcher != nil, p.Status(context.Background()))
	}
}

// GWY-001: CredentialProviderFromEnviron Mode C + Live opt-in.
func TestCredentialProviderFromEnviron_ModeCLiveWire(t *testing.T) {
	t.Parallel()
	// Default Mode C: Live=false.
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
		gateway.EnvAgentCoreASURL:        "https://login.microsoftonline.com/t/v2.0",
		gateway.EnvAgentCoreAudience:     "api://jenkins-api",
		gateway.EnvAgentCoreClientID:     "cid",
	}
	getenv := func(k string) string { return env[k] }
	p, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if p.Status(context.Background()).Ready {
		t.Fatal("default Mode C must not be Ready")
	}

	// Live=1 without token endpoint → start error.
	env[gateway.EnvGatewayLive] = "1"
	_, err = gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil {
		t.Fatal("Live=1 without token endpoint must fail start")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "token endpoint") && !strings.Contains(low, "not_configured") {
		t.Fatalf("want token endpoint / not_configured message: %v", err)
	}

	// Live=1 + token endpoint → Ready.
	env[gateway.EnvAgentCoreTokenEndpoint] = "https://login.microsoftonline.com/t/oauth2/v2.0/token"
	p, err = gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatal(err)
	}
	st := p.Status(context.Background())
	if !st.Ready {
		t.Fatalf("want Ready: %+v", st)
	}
	ac, ok := p.(*gateway.AgentCoreProvider)
	if !ok || ac == nil || !ac.Live || ac.Fetcher == nil {
		t.Fatalf("want AgentCoreProvider Live+Fetcher, got %T live=%v", p, ok && ac != nil && ac.Live)
	}
}

// GWY-001: Live=1 on Mode A / B fails closed (no silent cross-mode).
func TestCredentialProviderFromEnviron_LiveOnlyModeC(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAPITokenVault),
		gateway.EnvGatewayVaultPath:      tmp + "/vault.json",
		gateway.EnvGatewayLive:           "1",
	}
	getenv := func(k string) string { return env[k] }
	_, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "mode c") &&
		!strings.Contains(strings.ToLower(err.Error()), "agentcore") {
		t.Fatalf("Mode A + Live must fail: %v", err)
	}

	env[gateway.EnvGatewayCredentialMode] = string(gateway.CredentialModeJWTRSBearer)
	_, err = gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil {
		t.Fatal("Mode B + Live must fail")
	}
}

// GWY-001: ApplyLive on non-AgentCore provider fails when Live=1.
func TestApplyLiveHTTPFetcherFromEnviron_WrongProvider(t *testing.T) {
	t.Parallel()
	v := gateway.NewMemoryAPITokenVault()
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{gateway.EnvGatewayLive: "true"}
	getenv := func(k string) string { return env[k] }
	err = gateway.ApplyLiveHTTPFetcherFromEnviron(p, validCfg(), getenv)
	if err == nil {
		t.Fatal("expected error for Mode A provider")
	}
}
