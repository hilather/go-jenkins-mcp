package gateway

import (
	"os"
	"path/filepath"
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

// DefaultAPITokenVaultRelPath is the conventional vault file under XDG data
// (HOST-009 lab): $XDG_DATA_HOME/jenkins-mcp/gateway/apitoken_vault.json
const DefaultAPITokenVaultRelPath = "jenkins-mcp/gateway/apitoken_vault.json"

// DefaultJWTVaultRelPath is the conventional Mode B JWT vault file under XDG
// data (HOST-010 lab): $XDG_DATA_HOME/jenkins-mcp/gateway/jwt_vault.json
const DefaultJWTVaultRelPath = "jenkins-mcp/gateway/jwt_vault.json"

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
//
// For Mode A (api_token_vault) use RequireAPITokenVaultSetup or
// CredentialProviderFromEnviron instead — AgentCore AS is not required for Mode A.
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

// CredentialModeFromEnviron reads JENKINS_MCP_GATEWAY_CREDENTIAL_MODE.
// Empty defaults to agentcore_3lo_obo (Mode C fail-closed AgentCore path).
// Unknown values are returned as-is (invalid); callers must check Valid()
// or use CredentialModeFromEnvironStrict.
func CredentialModeFromEnviron(getenv func(string) string) CredentialMode {
	if getenv == nil {
		getenv = os.Getenv
	}
	raw := strings.TrimSpace(getenv(EnvGatewayCredentialMode))
	if raw == "" {
		return CredentialModeAgentCore
	}
	return NormalizeCredentialMode(CredentialMode(raw))
}

// CredentialModeFromEnvironStrict is like CredentialModeFromEnviron but returns
// invalid_argument for unknown mode names (fail start).
func CredentialModeFromEnvironStrict(getenv func(string) string) (CredentialMode, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	raw := strings.TrimSpace(getenv(EnvGatewayCredentialMode))
	if raw == "" {
		return CredentialModeAgentCore, nil
	}
	return ParseCredentialMode(raw)
}

// EnabledModesFromEnviron reads JENKINS_MCP_GATEWAY_ENABLED_MODES.
// Empty → nil (primary-only semantics in ModeEnabledIn / ModeMatrixFromEnviron).
// Unknown mode names fail closed.
func EnabledModesFromEnviron(getenv func(string) string) ([]CredentialMode, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	return ParseEnabledModes(getenv(EnvGatewayEnabledModes))
}

// ModeMatrix is a secret-free HOST-011 mode switch snapshot (admin / doctor).
type ModeMatrix struct {
	// Primary is the single serve credential mode (JENKINS_MCP_GATEWAY_CREDENTIAL_MODE).
	Primary CredentialMode `json:"primary"`
	// Enabled is the allow-list (explicit ENABLED_MODES or [Primary] when unset).
	Enabled []CredentialMode `json:"enabled"`
	// Residual notes residual modes (e.g. Mode B HOST-010).
	Residual string `json:"residual,omitempty"`
}

// ModeMatrixFromEnviron builds the HOST-011 matrix for status surfaces.
// Fails when primary or enabled list is invalid, or primary is not enabled.
func ModeMatrixFromEnviron(getenv func(string) string) (ModeMatrix, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	primary, err := CredentialModeFromEnvironStrict(getenv)
	if err != nil {
		return ModeMatrix{}, err
	}
	enabled, err := EnabledModesFromEnviron(getenv)
	if err != nil {
		return ModeMatrix{}, err
	}
	if len(enabled) == 0 {
		enabled = []CredentialMode{primary}
	} else if !ModeEnabledIn(primary, enabled, primary) {
		return ModeMatrix{}, apperr.New(apperr.CodeInvalidArgument,
			"gateway primary credential mode is not in JENKINS_MCP_GATEWAY_ENABLED_MODES")
	}
	mx := ModeMatrix{Primary: primary, Enabled: enabled}
	if ModeEnabledIn(CredentialModeJWTRSBearer, enabled, primary) {
		// Offline vault Obtain is HOST-010 foundation; live RS pin is residual.
		mx.Residual = "jwt_rs_bearer offline vault (HOST-010); live IdP/jwt-auth-filter pin residual (OAUTH-009)"
	}
	return mx, nil
}

// VaultPathFromEnviron returns the Mode A vault file path from env or default
// under XDG_DATA_HOME (or ~/.local/share) + DefaultAPITokenVaultRelPath.
func VaultPathFromEnviron(getenv func(string) string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	if p := strings.TrimSpace(getenv(EnvGatewayVaultPath)); p != "" {
		return p
	}
	return filepath.Join(xdgDataHome(getenv), filepath.FromSlash(DefaultAPITokenVaultRelPath))
}

// JWTVaultPathFromEnviron returns the Mode B JWT vault file path from env or
// default under XDG data + DefaultJWTVaultRelPath.
func JWTVaultPathFromEnviron(getenv func(string) string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	if p := strings.TrimSpace(getenv(EnvGatewayJWTVaultPath)); p != "" {
		return p
	}
	return filepath.Join(xdgDataHome(getenv), filepath.FromSlash(DefaultJWTVaultRelPath))
}

func xdgDataHome(getenv func(string) string) string {
	dataHome := strings.TrimSpace(getenv("XDG_DATA_HOME"))
	if dataHome == "" {
		home := strings.TrimSpace(getenv("HOME"))
		if home == "" {
			home = "."
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return dataHome
}

// CredentialProviderFromEnviron selects the HOST-011 primary CredentialProvider
// from env (Mode A API token vault, Mode B JWT vault, Mode C AgentCore). No
// silent cross-mode fallthrough: unknown mode fails start; only the primary
// mode is constructed (disabled modes never fall through).
//
// Mode A/B Live providers are returned when vault paths are constructible;
// empty vault files are OK (per-subject Obtain still not_found). Mode C uses
// RequireGatewaySetup (Live=false until TokenFetcher wire).
//
// getenv nil → os.Getenv. jenkinsBaseURL is required for Mode C only.
func CredentialProviderFromEnviron(jenkinsBaseURL string, getenv func(string) string) (CredentialProvider, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	mx, err := ModeMatrixFromEnviron(getenv)
	if err != nil {
		return nil, err
	}
	mode := mx.Primary
	switch mode {
	case CredentialModeAPITokenVault:
		path := VaultPathFromEnviron(getenv)
		vault, err := NewFileAPITokenVault(path)
		if err != nil {
			return nil, err
		}
		return RequireAPITokenVaultSetup(vault)
	case CredentialModeJWTRSBearer:
		// Mode B offline vault foundation (HOST-010) — not AgentCore silent.
		// Live jwt-auth-filter production pin remains OAUTH-009 residual.
		path := JWTVaultPathFromEnviron(getenv)
		vault, err := NewFileJWTVault(path)
		if err != nil {
			return nil, err
		}
		return RequireJWTRSBearerSetup(vault)
	case CredentialModeAgentCore:
		// Mode C: AgentCore path (Live=false until TokenFetcher wire).
		// Use injected getenv so tests do not depend on process env pollution.
		cfg := AgentCoreConfig{
			AuthorizationServerBaseURL: strings.TrimSpace(getenv(EnvAgentCoreASURL)),
			AuthorizationEndpoint:      strings.TrimSpace(getenv(EnvAgentCoreAuthEndpoint)),
			TokenEndpoint:              strings.TrimSpace(getenv(EnvAgentCoreTokenEndpoint)),
			Audience:                   strings.TrimSpace(getenv(EnvAgentCoreAudience)),
			ClientID:                   strings.TrimSpace(getenv(EnvAgentCoreClientID)),
			Mode:                       Mode(strings.TrimSpace(getenv(EnvAgentCoreMode))),
			JenkinsBaseURL:             strings.TrimSpace(jenkinsBaseURL),
		}
		return RequireGatewaySetup(cfg)
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"unsupported gateway credential mode (want api_token_vault, jwt_rs_bearer, or agentcore_3lo_obo)")
	}
}
