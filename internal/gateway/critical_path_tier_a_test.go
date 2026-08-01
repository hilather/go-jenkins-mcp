package gateway_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// Tier A JWT/OAuth critical path (docs/roadmap/server-tier-a-jwt-oauth-critical-path.md).
// These tests drive real shipped entry points — not re-implementations.
// Production live pins (Entra, jwt-auth-filter, AgentCore) remain residual;
// residual-status must never flip mode_*_live_*_qualified=true offline.

const (
	critPathCanaryA = "crit-path-modeA-token-never-log-xyz"
	critPathCanaryB = "crit-path-modeB-jwt-never-log-xyz"
	critPathCanaryC = "crit-path-modeC-access-never-log-xyz"
)

func critCaller(subject string) gateway.Caller {
	return gateway.Caller{
		Subject:    subject,
		Tenant:     "crit-tenant",
		ProfileID:  "corp",
		WorkloadID: "wl",
	}
}

// TestCriticalPath_S0_S4_ModeMatrixFailClosed exercises HOST-011 independent
// enablement, no silent cross-mode fallthrough, LIVE legal only on Mode C,
// and Ready honesty for offline providers.
func TestCriticalPath_S0_S4_ModeMatrixFailClosed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("unknown_mode_no_agentcore_fallthrough", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{gateway.EnvGatewayCredentialMode: "not_a_mode"}
		_, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", func(k string) string { return env[k] })
		if err == nil {
			t.Fatal("unknown mode must fail start")
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("code %v: %v", apperr.CodeOf(err), err)
		}
	})

	t.Run("primary_not_in_enabled_fail_closed", func(t *testing.T) {
		t.Parallel()
		env := map[string]string{
			gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
			gateway.EnvGatewayEnabledModes:   "api_token_vault,jwt_rs_bearer",
		}
		_, err := gateway.ModeMatrixFromEnviron(func(k string) string { return env[k] })
		if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("want invalid_argument got %v", err)
		}
	})

	t.Run("live_env_rejected_on_mode_A_and_B", func(t *testing.T) {
		t.Parallel()
		for _, mode := range []gateway.CredentialMode{
			gateway.CredentialModeAPITokenVault,
			gateway.CredentialModeJWTRSBearer,
		} {
			env := map[string]string{
				gateway.EnvGatewayCredentialMode: string(mode),
				gateway.EnvGatewayLive:           "1",
			}
			if mode == gateway.CredentialModeAPITokenVault {
				env[gateway.EnvGatewayVaultPath] = filepath.Join(dir, "a.json")
			} else {
				env[gateway.EnvGatewayJWTVaultPath] = filepath.Join(dir, "b.json")
			}
			_, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", func(k string) string { return env[k] })
			if err == nil {
				t.Fatalf("%s + LIVE must fail closed", mode)
			}
		}
	})

	t.Run("mode_A_cross_subject_isolation_file_vault", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "vault.json")
		v, err := gateway.NewFileAPITokenVault(path)
		if err != nil {
			t.Fatal(err)
		}
		alice := critCaller("alice")
		bob := critCaller("bob")
		if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", critPathCanaryA); err != nil {
			t.Fatal(err)
		}
		if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", critPathCanaryA+"-bob"); err != nil {
			t.Fatal(err)
		}
		p, err := gateway.RequireAPITokenVaultSetup(v)
		if err != nil {
			t.Fatal(err)
		}
		// Missing subject must not return another subject's token.
		missing := critCaller("carol")
		cred, err := p.Obtain(context.Background(), missing)
		if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
			t.Fatalf("carol want not_found: %v", err)
		}
		if cred.AccessToken != "" {
			t.Fatal("must not return token for missing subject")
		}
		if strings.Contains(err.Error(), critPathCanaryA) {
			t.Fatal("canary leaked in not_found error")
		}
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, alice)
		if err != nil {
			t.Fatal(err)
		}
		if ha.Scheme != gateway.HTTPAuthSchemeBasic || ha.Username != "alice-j" || ha.Token != critPathCanaryA {
			t.Fatalf("alice auth %+v", ha)
		}
		if strings.Contains(ha.String(), critPathCanaryA) {
			t.Fatal("HTTPAuth.String leaked canary")
		}
		// Ready offline does not mean live GO.
		st := p.Status(context.Background())
		if !st.Ready {
			t.Fatalf("Mode A vault Ready expected: %+v", st)
		}
	})

	t.Run("mode_B_bearer_only_no_basic_fallthrough", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "jwt_vault.json")
		v, err := gateway.NewFileJWTVault(path)
		if err != nil {
			t.Fatal(err)
		}
		caller := critCaller("jwt-user")
		if err := v.Put(context.Background(), gateway.SubjectKey(caller), critPathCanaryB); err != nil {
			t.Fatal(err)
		}
		p, err := gateway.RequireJWTRSBearerSetup(v)
		if err != nil {
			t.Fatal(err)
		}
		if p.Mode() != gateway.ModeJWTRSBearer {
			t.Fatalf("mode %s", p.Mode())
		}
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, caller)
		if err != nil {
			t.Fatal(err)
		}
		if ha.Scheme != gateway.HTTPAuthSchemeBearer || ha.Username != "" {
			t.Fatalf("Mode B must be Bearer-only: %+v", ha)
		}
		if ha.Token != critPathCanaryB {
			t.Fatal("token mismatch")
		}
		// Empty vault subject → not Mode A Basic.
		other := critCaller("other")
		_, err = gateway.ObtainHTTPAuth(context.Background(), p, other)
		if err == nil {
			t.Fatal("empty subject must fail closed")
		}
		if apperr.CodeOf(err) != apperr.CodeNotFound && apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
			t.Fatalf("code %v: %v", apperr.CodeOf(err), err)
		}
	})

	t.Run("mode_C_reject_jenkins_as_as_and_live_mock_bearer", func(t *testing.T) {
		t.Parallel()
		// Jenkins must never be the authorization server.
		err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
			AuthorizationServerBaseURL: "https://jenkins.example.com/",
			Audience:                   "api://jenkins-api",
			JenkinsBaseURL:             "https://jenkins.example.com",
			Mode:                       gateway.ModeTokenExchange,
		})
		if err == nil {
			t.Fatal("Jenkins-as-AS must fail closed")
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "jenkins") && !strings.Contains(low, "authorization") {
			t.Fatalf("want Jenkins AS reject wording: %v", err)
		}

		// Live mock token peer → Bearer Obtain (no tokens in String/Status).
		m := startMockAS(t)
		cfg := cfgWithTokenEndpoint(m.server.URL + "/oauth2/v2.0/token")
		cfg.Mode = gateway.ModeTokenExchange
		p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(0))
		if err != nil {
			t.Fatal(err)
		}
		if p.Status(context.Background()).Ready {
			t.Fatal("Live=false must not be Ready")
		}
		if err := gateway.EnableLiveHTTPFetcherWithClient(p, cfg, m.tlsClient()); err != nil {
			t.Fatal(err)
		}
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, testCaller())
		if err != nil {
			t.Fatal(err)
		}
		if ha.Scheme != gateway.HTTPAuthSchemeBearer || ha.Username != "" {
			t.Fatalf("Mode C must be Bearer: %+v", ha)
		}
		if ha.Token != canaryAccessToken {
			t.Fatal("token from mock AS")
		}
		if strings.Contains(ha.String(), canaryAccessToken) {
			t.Fatal("canary leaked in HTTPAuth.String")
		}
		st := p.Status(context.Background())
		if strings.Contains(st.ErrorMessageSafe, canaryAccessToken) || strings.Contains(fmt.Sprintf("%+v", st), canaryAccessToken) {
			t.Fatal("canary leaked in Status")
		}
	})
}

// TestCriticalPath_ResidualStatusNeverLiveQualified proves the offline residual
// surface (BuildGatewayResidualStatus) never claims production live GO for A/B/C.
func TestCriticalPath_ResidualStatusNeverLiveQualified(t *testing.T) {
	t.Parallel()
	// Multi-enable all modes + multi-user + LIVE-ish env still offline false.
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAPITokenVault),
		gateway.EnvGatewayEnabledModes:   "api_token_vault,jwt_rs_bearer,agentcore_3lo_obo",
		gateway.EnvGatewayMultiUser:      "1",
		gateway.EnvGatewayLive:           "1",
		gateway.EnvAgentCoreASURL:        "https://login.microsoftonline.com/t/v2.0",
		gateway.EnvAgentCoreAudience:     "api://jenkins-api",
	}
	getenv := func(k string) string { return env[k] }
	st := diagnostics.BuildGatewayResidualStatus(getenv)
	if st == nil {
		t.Fatal("nil residual status")
	}
	for _, k := range []string{
		"mode_a_live_obtain_qualified",
		"mode_b_live_rs_qualified",
		"mode_c_live_agentcore_qualified",
	} {
		v, ok := st[k]
		if !ok {
			t.Fatalf("missing %s", k)
		}
		b, _ := v.(bool)
		if b {
			t.Fatalf("%s must be false offline (got true)", k)
		}
	}
	if ready, _ := st["gateway_ready"].(bool); ready {
		t.Fatal("gateway_ready must be false on residual CLI surface")
	}
	if ha, _ := st["ha_multi_replica"].(bool); ha {
		t.Fatal("ha_multi_replica must be false (HOST-008 Tier A)")
	}
	ids, _ := st["residual_ids"].([]string)
	need := map[string]bool{
		"oauth009_offline":       false,
		"oauth010_offline":       false,
		"multi_user_offline":     false,
		"host008_single_replica": false,
		"gateway_modes_live":     false,
	}
	for _, id := range ids {
		if _, ok := need[id]; ok {
			need[id] = true
		}
	}
	for id, ok := range need {
		if !ok {
			t.Fatalf("residual_ids missing %s (got %v)", id, ids)
		}
	}
	// Never dump secrets from residual map.
	blob := strings.ToLower(strings.Join(ids, " "))
	if strings.Contains(blob, critPathCanaryA) || strings.Contains(blob, "bearer ") {
		t.Fatal("residual ids must stay secret-free")
	}
}

// TestCriticalPath_HOST004_SubjectPartition proves vault + token-cache keys are
// isolated by tenant|subject|profile (HOST-004 foundation).
func TestCriticalPath_HOST004_SubjectPartition(t *testing.T) {
	t.Parallel()
	alice := gateway.Caller{Subject: "u1", Tenant: "t1", ProfileID: "p1"}
	// Same subject, different tenant → different key.
	otherTenant := gateway.Caller{Subject: "u1", Tenant: "t2", ProfileID: "p1"}
	if gateway.SubjectKey(alice) == gateway.SubjectKey(otherTenant) {
		t.Fatal("tenant must partition subject keys")
	}
	if alice.CacheKey() == otherTenant.CacheKey() {
		t.Fatal("Caller.CacheKey must include tenant")
	}
	cache := gateway.NewMemoryTokenCache(time.Hour)
	tok := gateway.CachedToken{
		AccessToken: critPathCanaryC,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	cache.Set(alice.CacheKey(), tok)
	if _, ok := cache.Get(otherTenant.CacheKey()); ok {
		t.Fatal("token cache must not cross tenant")
	}
	got, ok := cache.Get(alice.CacheKey())
	if !ok || got.AccessToken != critPathCanaryC {
		t.Fatalf("alice hit: ok=%v", ok)
	}
	if strings.Contains(got.String(), critPathCanaryC) {
		t.Fatal("CachedToken.String leaked canary")
	}
}
