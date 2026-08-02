package gateway

import (
	"net/http"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// EnvGatewayLive opts into Mode C AgentCore Live acquisition via HTTPTokenFetcher
// (GWY-001 Live wire foundation). Values: 1 / true / yes / on.
//
// Default unset/false → AgentCoreProvider stays Live=false, Fetcher=nil (no network).
// When set without a resolvable token endpoint, enable fails closed (serve start error).
//
// Real Entra / AgentCore Identity vault pin remains residual (GWY-003 / OAUTH-010).
// This flag only attaches the production-shaped HTTPS TokenFetcher contract.
const EnvGatewayLive = "JENKINS_MCP_GATEWAY_LIVE"

// LiveEnabledFromEnviron reports whether JENKINS_MCP_GATEWAY_LIVE is truthy.
// getenv nil → os.Getenv.
func LiveEnabledFromEnviron(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return envTruthy(getenv(EnvGatewayLive))
}

// EnableLiveHTTPFetcher attaches an HTTPTokenFetcher to p and sets Live=true
// (GWY-001 opt-in Live wire foundation).
//
// Requirements (fail closed):
//   - p non-nil
//   - cfg passes ValidateProviderConfig
//   - token endpoint resolvable (JENKINS_MCP_AGENTCORE_TOKEN_ENDPOINT absolute
//     URL or path under AS base)
//
// Does not perform network I/O. HTTPS-only and no-redirect discipline are
// enforced by HTTPTokenFetcher at Obtain time. Client secrets are never stored
// on the provider (client_id only in cfg).
//
// Operators / serve wiring call this only when LiveEnabledFromEnviron is true.
// Default NewAgentCoreProvider remains Live=false / Fetcher=nil.
//
// Residual: real AgentCore 3LO browser consent UX, durable vault, Entra pin
// (GWY-003). HTTPTokenFetcher is the contract-shaped wire only.
func EnableLiveHTTPFetcher(p *AgentCoreProvider, cfg AgentCoreConfig) error {
	return EnableLiveHTTPFetcherWithClient(p, cfg, nil)
}

// EnableLiveHTTPFetcherWithClient is EnableLiveHTTPFetcher with an optional
// *http.Client (tests inject TLS mock AS clients; production passes nil).
func EnableLiveHTTPFetcherWithClient(p *AgentCoreProvider, cfg AgentCoreConfig, client *http.Client) error {
	if p == nil {
		return apperr.New(apperr.CodeCapabilityMissing, "agentcore provider is nil")
	}
	if err := ValidateProviderConfig(cfg); err != nil {
		return err
	}
	// Fail closed before Live=true: missing token endpoint must not leave Ready
	// ambiguous or enable network with incomplete config.
	if _, err := resolveTokenEndpointURL(cfg); err != nil {
		// Avoid embedding env var names that contain "TOKEN" (redact.Secrets
		// would replace them with [REDACTED] and obscure the operator message).
		return apperr.New(apperr.CodeCapabilityMissing,
			"gateway live wire requires agentcore token endpoint (absolute https URL or path under AS base); not_configured")
	}
	// Early absolute-URL https check when the endpoint is absolute (relative
	// paths resolve under AS at fetch time; AS is already origin-validated).
	if raw := strings.TrimSpace(cfg.TokenEndpoint); strings.Contains(raw, "://") {
		if err := requireHTTPSTokenURL(raw); err != nil {
			return err
		}
	}
	if strings.TrimSpace(string(cfg.Mode)) == "" {
		cfg.Mode = ModeAuthorizationCode
	} else {
		cfg.Mode = NormalizeMode(cfg.Mode)
	}
	p.Config = cfg
	p.Fetcher = NewHTTPTokenFetcher(client)
	p.Live = true
	return nil
}

// ApplyLiveHTTPFetcherFromEnviron enables Live HTTPTokenFetcher on Mode C
// providers when JENKINS_MCP_GATEWAY_LIVE is set. No-op when Live env is off.
//
// p must be *AgentCoreProvider (Mode C). Other provider types return an error
// if Live is requested (never silent no-op that leaves Live=false while env=1).
// getenv nil → os.Getenv.
func ApplyLiveHTTPFetcherFromEnviron(p CredentialProvider, cfg AgentCoreConfig, getenv func(string) string) error {
	if !LiveEnabledFromEnviron(getenv) {
		return nil
	}
	ac, ok := p.(*AgentCoreProvider)
	if !ok || ac == nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"JENKINS_MCP_GATEWAY_LIVE applies only to agentcore_3lo_obo (Mode C) providers")
	}
	return EnableLiveHTTPFetcher(ac, cfg)
}
