package auth_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

// OAUTH-008: path levels match architecture decisions.
func TestCapabilityMatrixPathLevels(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		auth.PathAPIToken:          auth.CapLevelSupported,
		auth.PathExternalIdPBearer: auth.CapLevelConditional,
		auth.PathAgentCore3LOOBO:   auth.CapLevelResidual,
		auth.PathCustomJenkinsAS:   auth.CapLevelNoGoDefault,
		auth.PathJWTAuthFilter:     auth.CapLevelConditional,
	}
	for id, level := range want {
		got, ok := auth.CapabilityMatrixPathLevel[id]
		if !ok {
			t.Fatalf("missing path %q", id)
		}
		if got != level {
			t.Fatalf("%s: got %q want %q", id, got, level)
		}
	}
}

// OAUTH-008: no UI-login plugin is an API authorization server.
func TestPluginRoles_NoUILoginAsAPIAS(t *testing.T) {
	t.Parallel()
	uiLogin := []string{auth.PluginOICAuth, auth.PluginGitHubOAuth}
	for _, id := range uiLogin {
		if auth.PluginIsAPIAuthorizationServer(id) {
			t.Fatalf("%s must not be classified as API authorization server", id)
		}
		if auth.PluginRoleByID[id] != auth.PluginRoleBrowserSecurityRealm {
			t.Fatalf("%s role: %q", id, auth.PluginRoleByID[id])
		}
		if auth.PluginMCPAPIAuthSupported(id) {
			t.Fatalf("%s alone must not support MCP API auth", id)
		}
	}
	if auth.PluginRoleByID[auth.PluginOIDCProvider] != auth.PluginRoleOutboundWorkloadIssuer {
		t.Fatal("oidc-provider direction")
	}
	if auth.PluginRoleByID[auth.PluginOAuthCredentials] != auth.PluginRoleCredentialFramework {
		t.Fatal("oauth-credentials role")
	}
	if auth.PluginRoleByID[auth.PluginJWTAuthFilter] != auth.PluginRoleBearerResourceServer {
		t.Fatal("jwt-auth-filter is RS only")
	}
	if auth.PluginRoleByID[auth.PluginCoreAPIToken] != auth.PluginRoleScriptedBasicAPI {
		t.Fatal("core api token is scripted Basic, not bearer RS")
	}
	// Custom AS plugin is authorization_server role but default no-go path.
	if !auth.PluginIsAPIAuthorizationServer(auth.PluginCustomJenkinsAS) {
		t.Fatal("custom plugin role is AS (gated)")
	}
	if auth.CapabilityMatrixPathLevel[auth.PathCustomJenkinsAS] != auth.CapLevelNoGoDefault {
		t.Fatal("custom AS path must be no_go_default")
	}
}

// OAUTH-008 AC: only oic-auth → fall back to API token provider.
func TestFallbackWhenOnlyOICAuth(t *testing.T) {
	t.Parallel()
	if auth.FallbackAuthMethodWhenOnlyOICAuth != auth.MethodAPIToken {
		t.Fatalf("fallback: %q", auth.FallbackAuthMethodWhenOnlyOICAuth)
	}
	if auth.PluginMCPAPIAuthSupported(auth.PluginOICAuth) {
		t.Fatal("oic-auth must not claim MCP API auth")
	}
	if !auth.PluginMCPAPIAuthSupported(auth.PluginCoreAPIToken) {
		t.Fatal("core api token is supported")
	}
}

// Contract: matrix doc exists and mentions required path labels.
func TestCapabilityMatrixDocPresent(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docs", "auth", "oauth-capability-matrix.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("matrix doc missing: %v", err)
	}
	text := string(data)
	required := []string{
		"api_token",
		"External IdP",
		"AgentCore",
		"jwt-auth-filter",
		"oic-auth",
		"oidc-provider",
		"no-go",
		"ADR 0003",
	}
	for _, s := range required {
		if !strings.Contains(text, s) {
			t.Errorf("matrix doc missing %q", s)
		}
	}
}
