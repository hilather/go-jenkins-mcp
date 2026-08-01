package auth

// OAUTH-008 — Jenkins OAuth capability matrix (machine-readable decisions).
//
// Source of truth for human prose: docs/auth/oauth-capability-matrix.md
// These named constants are contract-tested so docs and code cannot drift on
// the baseline supported / conditional / residual / no-go classifications.
//
// Stock Jenkins is never a native 3LO authorization server (ADR 0003).

// Auth path support levels for the capability matrix.
const (
	// CapLevelSupported — production pilot path.
	CapLevelSupported = "supported"
	// CapLevelConditional — requires qualified Jenkins resource-server controls
	// (e.g. jwt-auth-filter or approved proxy) and exact Jenkins audience.
	CapLevelConditional = "conditional"
	// CapLevelResidual — designed but not implemented / gateway-scoped.
	CapLevelResidual = "residual"
	// CapLevelNoGoDefault — out of baseline; decision-gated contingency only.
	CapLevelNoGoDefault = "no_go_default"
	// CapLevelNotApplicable — wrong protocol role; never select for MCP API 3LO.
	CapLevelNotApplicable = "not_applicable"
)

// Path IDs for matrix rows (stable for tests and docs cross-refs).
const (
	// PathAPIToken is personal Jenkins user:api_token via Secret Service.
	PathAPIToken = "api_token"
	// PathExternalIdPBearer is external IdP JWT bearer to Jenkins resource server.
	PathExternalIdPBearer = "external_idp_jwt_bearer"
	// PathAgentCore3LOOBO is managed-gateway AgentCore 3LO/OBO (Entra AS).
	PathAgentCore3LOOBO = "agentcore_3lo_obo"
	// PathCustomJenkinsAS is a full Jenkins-hosted authorization server plugin.
	PathCustomJenkinsAS = "custom_jenkins_as_plugin"
	// PathJWTAuthFilter is the bearer resource-server filter (not an AS).
	PathJWTAuthFilter = "jwt_auth_filter"
)

// CapabilityMatrixPathLevel maps auth path id → support level (OAUTH-008).
// Contract tests assert these exact values.
var CapabilityMatrixPathLevel = map[string]string{
	PathAPIToken:          CapLevelSupported,
	PathExternalIdPBearer: CapLevelConditional,
	PathAgentCore3LOOBO:   CapLevelResidual,
	PathCustomJenkinsAS:   CapLevelNoGoDefault,
	PathJWTAuthFilter:     CapLevelConditional, // OAUTH-009 offline contracts; live lab residual
}

// PluginRole classifies Jenkins-related plugins for MCP auth selection.
type PluginRole string

const (
	// PluginRoleScriptedBasicAPI — Jenkins core username:api_token Basic model.
	PluginRoleScriptedBasicAPI PluginRole = "scripted_basic_api"
	// PluginRoleBrowserSecurityRealm — UI login only; not MCP API 3LO.
	PluginRoleBrowserSecurityRealm PluginRole = "browser_security_realm"
	// PluginRoleOutboundWorkloadIssuer — issues tokens from builds outward.
	PluginRoleOutboundWorkloadIssuer PluginRole = "outbound_workload_issuer"
	// PluginRoleCredentialFramework — stores credentials for other plugins.
	PluginRoleCredentialFramework PluginRole = "credential_framework"
	// PluginRoleBearerResourceServer — validates inbound bearer JWTs for APIs.
	PluginRoleBearerResourceServer PluginRole = "bearer_resource_server"
	// PluginRoleAuthorizationServer — full OAuth AS (consent/codes/tokens).
	PluginRoleAuthorizationServer PluginRole = "authorization_server"
)

// Plugin matrix IDs (short plugin artifact ids).
const (
	PluginCoreAPIToken     = "jenkins-core-api-token"
	PluginOICAuth          = "oic-auth"
	PluginOIDCProvider     = "oidc-provider"
	PluginGitHubOAuth      = "github-oauth"
	PluginOAuthCredentials = "oauth-credentials"
	PluginJWTAuthFilter    = "jwt-auth-filter"
	PluginApprovedProxy    = "approved-reverse-proxy-jwt-rs"
	PluginCustomJenkinsAS  = "custom-jenkins-as-plugin"
)

// PluginRoleByID maps plugin id → protocol role (OAUTH-008).
var PluginRoleByID = map[string]PluginRole{
	PluginCoreAPIToken:     PluginRoleScriptedBasicAPI,
	PluginOICAuth:          PluginRoleBrowserSecurityRealm,
	PluginOIDCProvider:     PluginRoleOutboundWorkloadIssuer,
	PluginGitHubOAuth:      PluginRoleBrowserSecurityRealm,
	PluginOAuthCredentials: PluginRoleCredentialFramework,
	PluginJWTAuthFilter:    PluginRoleBearerResourceServer,
	PluginApprovedProxy:    PluginRoleBearerResourceServer,
	PluginCustomJenkinsAS:  PluginRoleAuthorizationServer,
}

// PluginMCPAPIAuthSupported reports whether the plugin alone is a valid MCP
// scripted API authentication path without an external IdP AS.
// oic-auth alone must be false → fall back to api_token (OAUTH-008 AC).
func PluginMCPAPIAuthSupported(pluginID string) bool {
	switch pluginID {
	case PluginCoreAPIToken:
		return true
	case PluginJWTAuthFilter, PluginApprovedProxy:
		// Conditional: needs external IdP-issued Jenkins-audience token.
		return false
	default:
		return false
	}
}

// PluginIsAPIAuthorizationServer is always false for UI-login / workload /
// credential plugins — contract: never treat them as an API AS.
func PluginIsAPIAuthorizationServer(pluginID string) bool {
	role, ok := PluginRoleByID[pluginID]
	if !ok {
		return false
	}
	return role == PluginRoleAuthorizationServer
}

// FallbackAuthMethodWhenOnlyOICAuth is the required provider when a deployment
// has only oic-auth (UI realm) and no bearer RS path.
const FallbackAuthMethodWhenOnlyOICAuth = MethodAPIToken
