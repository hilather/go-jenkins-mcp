package gateway

import (
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvGatewayModeVar enables gateway mode via environment (in addition to --gateway).
const EnvGatewayModeVar = "JENKINS_MCP_GATEWAY_MODE"

// EnvAgentCoreASURL is the authorization server base URL for AgentCore config.
const EnvAgentCoreASURL = "JENKINS_MCP_AGENTCORE_AS_URL"

// EnvAgentCoreAudience is the Jenkins API audience resource identifier.
const EnvAgentCoreAudience = "JENKINS_MCP_AGENTCORE_AUDIENCE"

// EnvAgentCoreClientID is the public OAuth client id (not a secret).
const EnvAgentCoreClientID = "JENKINS_MCP_AGENTCORE_CLIENT_ID"

// EnvAgentCoreMode selects authorization_code or token_exchange.
const EnvAgentCoreMode = "JENKINS_MCP_AGENTCORE_MODE"

// EnvAgentCoreAuthEndpoint optional authorization endpoint URL.
const EnvAgentCoreAuthEndpoint = "JENKINS_MCP_AGENTCORE_AUTH_ENDPOINT"

// EnvAgentCoreTokenEndpoint optional token endpoint URL.
const EnvAgentCoreTokenEndpoint = "JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT"

// ModeEnabled reports whether gateway mode is requested via flag or env.
func ModeEnabled(flagGateway bool, profileGateway bool) bool {
	if flagGateway || profileGateway {
		return true
	}
	return envTruthy(os.Getenv(EnvGatewayModeVar))
}

func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ConfigFromEnviron loads non-secret AgentCore config from environment.
// JenkinsBaseURL must be supplied by the caller (profile URL).
func ConfigFromEnviron(jenkinsBaseURL string) AgentCoreConfig {
	return AgentCoreConfig{
		AuthorizationServerBaseURL: strings.TrimSpace(os.Getenv(EnvAgentCoreASURL)),
		AuthorizationEndpoint:      strings.TrimSpace(os.Getenv(EnvAgentCoreAuthEndpoint)),
		TokenEndpoint:              strings.TrimSpace(os.Getenv(EnvAgentCoreTokenEndpoint)),
		Audience:                   strings.TrimSpace(os.Getenv(EnvAgentCoreAudience)),
		ClientID:                   strings.TrimSpace(os.Getenv(EnvAgentCoreClientID)),
		Mode:                       Mode(strings.TrimSpace(os.Getenv(EnvAgentCoreMode))),
		JenkinsBaseURL:             strings.TrimSpace(jenkinsBaseURL),
	}
}

// RequireGatewaySetup validates that gateway mode has a constructible provider.
// Returns the provider (fail-closed stub when config incomplete after validate)
// or an error when configuration is invalid (e.g. Jenkins used as AS).
//
// When cfg is incomplete (missing AS/audience), returns an error — gateway mode
// fails closed rather than starting without a provider (GWY-002).
func RequireGatewaySetup(cfg AgentCoreConfig) (CredentialProvider, error) {
	if !cfg.Configured() {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"gateway mode requires agentcore provider config (AS URL + audience); not_configured")
	}
	if err := ValidateProviderConfig(cfg); err != nil {
		return nil, err
	}
	p, err := NewAgentCoreProvider(cfg, NewMemoryTokenCache(0))
	if err != nil {
		return nil, err
	}
	return p, nil
}
