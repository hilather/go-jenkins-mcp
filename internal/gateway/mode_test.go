package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

func TestModeEnabled(t *testing.T) {
	// Uses t.Setenv — not parallel.
	if !gateway.ModeEnabled(true, false) {
		t.Fatal("flag")
	}
	if !gateway.ModeEnabled(false, true) {
		t.Fatal("profile")
	}
	t.Setenv(gateway.EnvGatewayModeVar, "")
	if gateway.ModeEnabled(false, false) {
		t.Fatal("expected disabled")
	}
	t.Setenv(gateway.EnvGatewayModeVar, "1")
	if !gateway.ModeEnabled(false, false) {
		t.Fatal("env")
	}
}

func TestConfigFromEnviron(t *testing.T) {
	t.Setenv(gateway.EnvAgentCoreASURL, "https://login.microsoftonline.com/t/v2.0")
	t.Setenv(gateway.EnvAgentCoreAudience, "api://jenkins-api")
	t.Setenv(gateway.EnvAgentCoreClientID, "cid")
	t.Setenv(gateway.EnvAgentCoreMode, "token_exchange")
	cfg := gateway.ConfigFromEnviron("https://jenkins.example.com")
	if cfg.AuthorizationServerBaseURL == "" || cfg.Audience == "" {
		t.Fatalf("%+v", cfg)
	}
	if err := gateway.ValidateProviderConfig(cfg); err != nil {
		t.Fatal(err)
	}
}

// HOST-011 matrix: empty primary → default agentcore_3lo_obo path (document).
func TestCredentialModeFromEnviron_EmptyDefaultsAgentCore(t *testing.T) {
	t.Parallel()
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	m := gateway.CredentialModeFromEnviron(getenv)
	if m != gateway.CredentialModeAgentCore {
		t.Fatalf("empty default want agentcore_3lo_obo got %s", m)
	}
	strict, err := gateway.CredentialModeFromEnvironStrict(getenv)
	if err != nil {
		t.Fatal(err)
	}
	if strict != gateway.CredentialModeAgentCore {
		t.Fatalf("strict empty default %s", strict)
	}
}

// HOST-011: unknown mode → fail start (invalid_argument).
func TestCredentialProviderFromEnviron_InvalidMode(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: "not_a_real_mode",
	}
	getenv := func(k string) string { return env[k] }
	_, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "agentcore") &&
		!strings.Contains(err.Error(), "unsupported") {
		// Must not silently become AgentCore.
		t.Fatalf("invalid mode must not become agentcore: %v", err)
	}
}

func TestCredentialProviderFromEnviron_ModeA(t *testing.T) {
	// Not parallel: uses temp path via getenv map.
	dir := t.TempDir()
	path := dir + "/vault.json"
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAPITokenVault),
		gateway.EnvGatewayVaultPath:      path,
	}
	getenv := func(k string) string { return env[k] }
	p, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode() != gateway.ModeAPITokenVault {
		t.Fatalf("mode %s", p.Mode())
	}
	st := p.Status(context.Background())
	if !st.Ready {
		t.Fatalf("mode A should be Ready: %+v", st)
	}
	// Empty vault → not_found, not ambient SA.
	_, err = p.Obtain(context.Background(), gateway.Caller{
		Subject:   "s1",
		ProfileID: "corp",
	})
	if err == nil {
		t.Fatal("expected not_found")
	}
}

// HOST-011: jwt_rs_bearer → explicit residual/not_configured provider (not AgentCore silent).
func TestCredentialProviderFromEnviron_ModeBResidual(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeJWTRSBearer),
	}
	getenv := func(k string) string { return env[k] }
	p, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatalf("Mode B must return residual provider, not start error: %v", err)
	}
	if p.Mode() != gateway.ModeJWTRSBearer {
		t.Fatalf("want jwt_rs_bearer mode got %s (must not be AgentCore)", p.Mode())
	}
	// Not AgentCore authorization_code / token_exchange.
	if p.Mode() == gateway.ModeAuthorizationCode || p.Mode() == gateway.ModeTokenExchange {
		t.Fatal("Mode B must not silently use AgentCore mode labels")
	}
	st := p.Status(context.Background())
	if st.Ready || st.Configured {
		t.Fatalf("residual must not be ready: %+v", st)
	}
	if !strings.Contains(st.ErrorMessageSafe, "HOST-010") &&
		!strings.Contains(st.ErrorMessageSafe, "residual") {
		t.Fatalf("want residual wording in status: %+v", st)
	}
	_, err = p.Obtain(context.Background(), gateway.Caller{
		Subject:   "s1",
		ProfileID: "corp",
	})
	if err == nil {
		t.Fatal("expected residual Obtain fail")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "jwt_rs_bearer") ||
		!strings.Contains(err.Error(), "residual") {
		t.Fatalf("want clear residual message: %v", err)
	}
}

// HOST-011: agentcore_3lo_obo → AgentCore path (fail closed when AS incomplete).
func TestCredentialProviderFromEnviron_ModeCAgentCore(t *testing.T) {
	t.Parallel()
	// Incomplete AS → not_configured (agentcore path, not mode A).
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
	}
	getenv := func(k string) string { return env[k] }
	_, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil {
		t.Fatal("incomplete AgentCore should fail closed")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "agentcore") &&
		!strings.Contains(strings.ToLower(err.Error()), "not_configured") {
		t.Fatalf("want agentcore not_configured: %v", err)
	}

	// Complete AS → AgentCore provider (Live=false until Fetcher).
	env[gateway.EnvAgentCoreASURL] = "https://login.microsoftonline.com/t/v2.0"
	env[gateway.EnvAgentCoreAudience] = "api://jenkins-api"
	p, err := gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode() != gateway.ModeAuthorizationCode && p.Mode() != gateway.ModeTokenExchange {
		// Default empty AgentCore mode normalizes to authorization_code.
		if p.Mode() == gateway.ModeAPITokenVault || p.Mode() == gateway.ModeJWTRSBearer {
			t.Fatalf("Mode C must not be A/B: %s", p.Mode())
		}
	}
	st := p.Status(context.Background())
	if st.Ready {
		t.Fatalf("default AgentCore Live=false must not be Ready: %+v", st)
	}
}

// HOST-011 enabled-modes multi-enable scaffold.
func TestEnabledModesAndMatrix(t *testing.T) {
	t.Parallel()
	// Empty enabled → primary only.
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAPITokenVault),
	}
	getenv := func(k string) string { return env[k] }
	mx, err := gateway.ModeMatrixFromEnviron(getenv)
	if err != nil {
		t.Fatal(err)
	}
	if mx.Primary != gateway.CredentialModeAPITokenVault {
		t.Fatalf("primary %s", mx.Primary)
	}
	if len(mx.Enabled) != 1 || mx.Enabled[0] != gateway.CredentialModeAPITokenVault {
		t.Fatalf("enabled %+v", mx.Enabled)
	}

	// Explicit multi-enable with primary included.
	env[gateway.EnvGatewayEnabledModes] = "api_token_vault, jwt_rs_bearer"
	mx, err = gateway.ModeMatrixFromEnviron(getenv)
	if err != nil {
		t.Fatal(err)
	}
	if len(mx.Enabled) != 2 {
		t.Fatalf("enabled %+v", mx.Enabled)
	}
	if mx.Residual == "" {
		t.Fatal("Mode B in enabled list should note residual")
	}

	// Primary not in enabled → fail.
	env[gateway.EnvGatewayCredentialMode] = string(gateway.CredentialModeAgentCore)
	_, err = gateway.ModeMatrixFromEnviron(getenv)
	if err == nil {
		t.Fatal("primary not in enabled must fail")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}

	// Unknown in enabled list → fail.
	env[gateway.EnvGatewayCredentialMode] = string(gateway.CredentialModeAPITokenVault)
	env[gateway.EnvGatewayEnabledModes] = "api_token_vault,bogus_mode"
	_, err = gateway.ModeMatrixFromEnviron(getenv)
	if err == nil {
		t.Fatal("unknown enabled mode must fail")
	}
}

func TestParseCredentialMode(t *testing.T) {
	t.Parallel()
	m, err := gateway.ParseCredentialMode("mode_b")
	if err != nil || m != gateway.CredentialModeJWTRSBearer {
		t.Fatalf("got %s %v", m, err)
	}
	_, err = gateway.ParseCredentialMode("")
	if err == nil {
		t.Fatal("empty")
	}
	_, err = gateway.ParseCredentialMode("nope")
	if err == nil {
		t.Fatal("invalid")
	}
}

// HOST-011 offline matrix: Obtain → HTTP auth header shape per mode.
func TestHOST011_AuthHeaderShapeMatrix(t *testing.T) {
	t.Parallel()
	const canary = "host011-canary-token-never-log"

	t.Run("mode_A_basic", func(t *testing.T) {
		t.Parallel()
		auth, err := gateway.HTTPAuthFromCredential(gateway.Credential{
			AccessToken:      canary,
			JenkinsPrincipal: "alice",
			Mode:             gateway.ModeAPITokenVault,
		})
		if err != nil {
			t.Fatal(err)
		}
		if auth.Scheme != gateway.HTTPAuthSchemeBasic || auth.Username != "alice" || auth.Token != canary {
			t.Fatalf("%+v", auth)
		}
		if strings.Contains(auth.String(), canary) {
			t.Fatal("canary in String")
		}
	})

	t.Run("mode_B_jwt_bearer", func(t *testing.T) {
		t.Parallel()
		// JWT-shaped secret (three base64url segments) — still Bearer, never Basic.
		jwtShaped := "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhcGk6Ly9qZW5raW5zIn0.sig-" + canary
		auth, err := gateway.HTTPAuthFromCredential(gateway.Credential{
			AccessToken: jwtShaped,
			Mode:        gateway.ModeJWTRSBearer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if auth.Scheme != gateway.HTTPAuthSchemeBearer {
			t.Fatalf("Mode B must be bearer got %s", auth.Scheme)
		}
		if auth.Username != "" {
			t.Fatalf("Bearer must not set username: %+v", auth)
		}
		if auth.Token != jwtShaped {
			t.Fatal("token mismatch")
		}
		if strings.Contains(auth.String(), canary) || strings.Contains(auth.String(), jwtShaped) {
			t.Fatal("JWT canary in String")
		}
	})

	t.Run("mode_C_agentcore_bearer", func(t *testing.T) {
		t.Parallel()
		auth, err := gateway.HTTPAuthFromCredential(gateway.Credential{
			AccessToken: canary,
			Mode:        gateway.ModeTokenExchange,
		})
		if err != nil {
			t.Fatal(err)
		}
		if auth.Scheme != gateway.HTTPAuthSchemeBearer || auth.Username != "" {
			t.Fatalf("%+v", auth)
		}
	})

	// Cross-mode fail-closed: Mode B residual Obtain never returns Mode A vault token.
	t.Run("mode_B_no_cross_fallthrough", func(t *testing.T) {
		t.Parallel()
		p := gateway.NewResidualJWTRSProvider()
		cred, err := p.Obtain(context.Background(), gateway.Caller{
			Subject:   "s1",
			ProfileID: "corp",
		})
		if err == nil {
			t.Fatal("expected fail")
		}
		if cred.AccessToken != "" {
			t.Fatal("must not return any token")
		}
		if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
			t.Fatalf("code %v", apperr.CodeOf(err))
		}
	})
}

func TestVaultPathFromEnviron(t *testing.T) {
	env := map[string]string{"XDG_DATA_HOME": "/tmp/xdg-data"}
	getenv := func(k string) string { return env[k] }
	p := gateway.VaultPathFromEnviron(getenv)
	if p == "" || !strings.Contains(p, "apitoken_vault.json") {
		t.Fatalf("path %q", p)
	}
	env[gateway.EnvGatewayVaultPath] = "/custom/vault.json"
	if gateway.VaultPathFromEnviron(getenv) != "/custom/vault.json" {
		t.Fatal("override")
	}
}
