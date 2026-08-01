package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ModeAPITokenVault is HOST-009 mode A: per-subject personal Jenkins API token
// presented as HTTP Basic (username + token). Never a shared service account.
//
// Distinct from AgentCore modes (authorization_code / token_exchange). AgentCore
// ValidateProviderConfig rejects this mode so Mode A cannot be mis-wired as AS.
const ModeAPITokenVault Mode = "api_token_vault"

// CredentialMode is the HOST-011 first-class acquisition mode for the gateway.
// Sites enable one or more; this foundation wires Mode A fully offline and
// keeps Mode B/C on existing AgentCore / residual paths.
type CredentialMode string

const (
	// CredentialModeAPITokenVault is mode A (HOST-009).
	CredentialModeAPITokenVault CredentialMode = "api_token_vault"
	// CredentialModeJWTRSBearer is mode B (HOST-010): per-subject Bearer JWT vault.
	// Live jwt-auth-filter / IdP pin remains OAUTH-009 residual.
	CredentialModeJWTRSBearer CredentialMode = "jwt_rs_bearer"
	// CredentialModeAgentCore is mode C (AgentCore 3LO/OBO; GWY-001).
	CredentialModeAgentCore CredentialMode = "agentcore_3lo_obo"
)

// EnvGatewayCredentialMode selects the HOST-011 primary mode for serve wiring.
// Values: api_token_vault | jwt_rs_bearer | agentcore_3lo_obo
// Empty defaults to agentcore_3lo_obo (existing fail-closed AgentCore path).
// Unknown values fail start (invalid_argument) — never silent fallthrough.
const EnvGatewayCredentialMode = "JENKINS_MCP_GATEWAY_CREDENTIAL_MODE"

// EnvGatewayEnabledModes is an optional comma-separated allow-list of HOST-011
// modes (multi-enable scaffold). Empty → only the primary mode is enabled.
// When set, every entry must be a known mode and the primary must be included
// (fail closed; no silent enable of other modes).
const EnvGatewayEnabledModes = "JENKINS_MCP_GATEWAY_ENABLED_MODES"

// EnvGatewayVaultPath is the optional file path for FileAPITokenVault (mode A lab).
// Default convention is documented in docs/gateway/README.md (XDG data).
const EnvGatewayVaultPath = "JENKINS_MCP_GATEWAY_VAULT_PATH"

// EnvGatewayJWTVaultPath is the optional file path for FileJWTVault (mode B lab).
// Default convention: $XDG_DATA_HOME/jenkins-mcp/gateway/jwt_vault.json
const EnvGatewayJWTVaultPath = "JENKINS_MCP_GATEWAY_JWT_VAULT_PATH"

// AllCredentialModes returns the stable HOST-011 mode enum (A, B, C).
func AllCredentialModes() []CredentialMode {
	return []CredentialMode{
		CredentialModeAPITokenVault,
		CredentialModeJWTRSBearer,
		CredentialModeAgentCore,
	}
}

// NormalizeCredentialMode maps aliases and trims whitespace.
func NormalizeCredentialMode(m CredentialMode) CredentialMode {
	switch strings.ToLower(strings.TrimSpace(string(m))) {
	case string(CredentialModeAPITokenVault), "mode_a", "a", "apitoken", "api-token-vault":
		return CredentialModeAPITokenVault
	case string(CredentialModeJWTRSBearer), "mode_b", "b", "jwt", "jwt_rs", "jwt-rs-bearer":
		return CredentialModeJWTRSBearer
	case string(CredentialModeAgentCore), "mode_c", "c", "agentcore", "3lo", "obo",
		"authorization_code", "token_exchange":
		return CredentialModeAgentCore
	default:
		return CredentialMode(strings.ToLower(strings.TrimSpace(string(m))))
	}
}

// ParseCredentialMode strictly parses a mode name or alias.
// Empty input returns an error (callers that want default use CredentialModeFromEnviron).
func ParseCredentialMode(raw string) (CredentialMode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"gateway credential mode is required (want api_token_vault, jwt_rs_bearer, or agentcore_3lo_obo)")
	}
	m := NormalizeCredentialMode(CredentialMode(raw))
	if !m.Valid() {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"unsupported gateway credential mode (want api_token_vault, jwt_rs_bearer, or agentcore_3lo_obo)")
	}
	return m, nil
}

// Valid reports whether m is a known HOST-011 credential mode.
func (m CredentialMode) Valid() bool {
	switch NormalizeCredentialMode(m) {
	case CredentialModeAPITokenVault, CredentialModeJWTRSBearer, CredentialModeAgentCore:
		return true
	default:
		return false
	}
}

// String returns the canonical mode name.
func (m CredentialMode) String() string {
	n := NormalizeCredentialMode(m)
	if n == "" {
		return ""
	}
	return string(n)
}

// ParseEnabledModes parses a comma-separated enabled-mode list (HOST-011).
// Empty raw returns nil, nil (caller treats as "primary only").
// Duplicates are collapsed; order is canonical A → B → C among present modes.
func ParseEnabledModes(raw string) ([]CredentialMode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	seen := make(map[CredentialMode]struct{}, 3)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		m, err := ParseCredentialMode(p)
		if err != nil {
			return nil, err
		}
		seen[m] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]CredentialMode, 0, len(seen))
	for _, m := range AllCredentialModes() {
		if _, ok := seen[m]; ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// ModeEnabledIn reports whether mode is present in enabled (primary-only when enabled empty).
func ModeEnabledIn(mode CredentialMode, enabled []CredentialMode, primary CredentialMode) bool {
	mode = NormalizeCredentialMode(mode)
	primary = NormalizeCredentialMode(primary)
	if len(enabled) == 0 {
		return mode == primary
	}
	for _, m := range enabled {
		if NormalizeCredentialMode(m) == mode {
			return true
		}
	}
	return false
}

// APITokenVaultProvider is the Mode A CredentialProvider (HOST-009).
//
// Obtain looks up the vault for SubjectKey(caller) and returns Basic-auth
// material (Jenkins username + personal API token). Missing entries fail closed
// (not_found / not_configured) — never fall back to another subject, ambient
// process keyring, or a shared Jenkins service account.
//
// Live=false (default from NewAPITokenVaultProvider) always returns
// not_configured so accidental construction cannot elevate.
type APITokenVaultProvider struct {
	Vault APITokenVault
	// Live enables Obtain. When false, always not_configured (cache/vault ignored).
	Live bool
}

// NewAPITokenVaultProvider constructs a fail-closed Mode A provider (Live=false).
// vault may be nil; Obtain then fails closed as not_configured when Live is set.
func NewAPITokenVaultProvider(vault APITokenVault) *APITokenVaultProvider {
	return &APITokenVaultProvider{Vault: vault, Live: false}
}

// Mode implements CredentialProvider.
func (p *APITokenVaultProvider) Mode() Mode {
	return ModeAPITokenVault
}

// Obtain implements CredentialProvider for Mode A.
//
// Fail-closed paths:
//   - Live=false → not_configured
//   - Vault=nil → not_configured
//   - invalid caller → authentication
//   - missing subject entry → not_found (never ambient keyring / other subject)
//   - empty username/token in vault → authentication
//
// Success: Credential with AccessToken=token, JenkinsPrincipal=username,
// Mode=api_token_vault. Callers use HTTPAuthFromCredential for Basic scheme.
func (p *APITokenVaultProvider) Obtain(ctx context.Context, caller Caller) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential obtain cancelled", err)
	}
	if p == nil {
		return Credential{}, notConfigured("api token vault provider is nil")
	}
	if !caller.Valid() {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject and profile are required")
	}
	if !p.Live {
		return Credential{}, notConfigured(
			"api token vault provider is not configured for live acquisition")
	}
	if p.Vault == nil {
		return Credential{}, notConfigured(
			"api token vault is not configured")
	}

	key := SubjectKey(caller)
	if err := ValidateSubjectKey(key); err != nil {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject key is invalid")
	}

	username, token, ok, err := p.Vault.Get(ctx, key)
	if err != nil {
		// Never wrap vault errors with token material (vault must not put secrets in err).
		return Credential{}, mapVaultError(err)
	}
	if !ok {
		// Fail closed: no shared SA / ambient keyring / other-subject fallthrough.
		return Credential{}, apperr.New(apperr.CodeNotFound,
			"personal api token not found for gateway subject")
	}
	username = strings.TrimSpace(username)
	token = strings.TrimSpace(token)
	if username == "" || token == "" {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"personal api token vault entry is incomplete")
	}

	// No ExpiresAt: personal API tokens are long-lived until rotated/revoked.
	return Credential{
		AccessToken:      token,
		ExpiresAt:        time.Time{},
		JenkinsPrincipal: username,
		Mode:             ModeAPITokenVault,
	}, nil
}

// Invalidate implements CredentialProvider.
// Mode A has no short-lived token cache; delete is operator-driven via vault Delete.
// Invalidate is a no-op success (does not delete durable vault entry).
func (p *APITokenVaultProvider) Invalidate(ctx context.Context, caller Caller) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway invalidate cancelled", err)
	}
	_ = caller
	return nil
}

// Status implements CredentialProvider.
func (p *APITokenVaultProvider) Status(ctx context.Context) ProviderStatus {
	_ = ctx
	st := ProviderStatus{Mode: ModeAPITokenVault}
	if p == nil {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "api token vault provider is not configured"
		return st
	}
	st.Configured = p.Vault != nil
	st.Ready = st.Configured && p.Live
	// Mode A does not use AgentCore AS/audience.
	st.AudienceSet = false
	st.ASConfigured = false
	if !st.Configured {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "api token vault is not configured"
	} else if !p.Live {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "api token vault is configured but live acquisition is not enabled"
	}
	return st
}

func mapVaultError(err error) error {
	if err == nil {
		return nil
	}
	if apperr.CodeOf(err) != "" && apperr.CodeOf(err).Valid() {
		// Preserve classified errors; strip possibility of secret-bearing free text
		// by returning a short class-only message when code is authentication-ish.
		code := apperr.CodeOf(err)
		switch code {
		case apperr.CodeCancelled, apperr.CodeTimeout, apperr.CodeInvalidArgument,
			apperr.CodeNotFound, apperr.CodeCorruptCache, apperr.CodeCapabilityMissing:
			return err
		default:
			return apperr.New(apperr.CodeAuthentication, "personal api token vault lookup failed")
		}
	}
	return apperr.New(apperr.CodeAuthentication, "personal api token vault lookup failed")
}

// HTTPAuthSchemeBasic / HTTPAuthSchemeBearer are scheme labels for Jenkins wire
// (HOST-003 foundation). Match jenkins.AuthScheme* without importing jenkins.
const (
	HTTPAuthSchemeBasic  = "basic"
	HTTPAuthSchemeBearer = "bearer"
)

// HTTPAuth is the Jenkins HTTP credential presentation derived from Obtain
// (HOST-003 hook). Token must never appear in logs, errors, or String().
type HTTPAuth struct {
	// Scheme is basic (mode A) or bearer (mode B/C).
	Scheme string
	// Username is set for Basic only (Jenkins principal).
	Username string
	// Token is the secret access token or personal API token (memory only).
	Token string
}

// String never includes the token (canary target).
func (a HTTPAuth) String() string {
	return "http_auth scheme=" + strings.TrimSpace(a.Scheme) +
		" username=" + strings.TrimSpace(a.Username)
}

// HTTPAuthFromCredential maps a gateway Credential to Jenkins HTTP auth shape
// (HOST-003 / HOST-011 foundation helper). Mode A → Basic; Mode B JWT RS and
// Mode C AgentCore → Bearer. Empty token fails closed. Never logs the token.
func HTTPAuthFromCredential(cred Credential) (HTTPAuth, error) {
	tok := strings.TrimSpace(cred.AccessToken)
	if tok == "" {
		return HTTPAuth{}, apperr.New(apperr.CodeAuthentication,
			"gateway credential has empty access token")
	}
	mode := NormalizeMode(cred.Mode)
	// Mode A: personal API token vault → Basic user:token.
	if mode == ModeAPITokenVault || cred.Mode == ModeAPITokenVault {
		user := strings.TrimSpace(cred.JenkinsPrincipal)
		if user == "" {
			return HTTPAuth{}, apperr.New(apperr.CodeAuthentication,
				"mode A basic auth requires jenkins username (principal)")
		}
		return HTTPAuth{
			Scheme:   HTTPAuthSchemeBasic,
			Username: user,
			Token:    tok,
		}, nil
	}
	// Mode B (jwt_rs_bearer) and Mode C (AgentCore / authorization_code /
	// token_exchange): Bearer access token. JWT-shaped secrets stay memory-only.
	return HTTPAuth{
		Scheme: HTTPAuthSchemeBearer,
		Token:  tok,
	}, nil
}

// residualJWTRSProvider is a Mode B fail-closed stub used when operators want
// an explicit not_configured surface without a vault (tests / disabled path).
// Prefer JWTRSBearerProvider + JWTVault for HOST-010 offline Obtain.
// Live jwt-auth-filter production pin remains OAUTH-009 residual either way.
type residualJWTRSProvider struct{}

// NewResidualJWTRSProvider returns a Mode B residual fail-closed provider
// (no vault). CredentialProviderFromEnviron wires the vault path instead;
// this helper remains for explicit residual / disabled-mode tests.
func NewResidualJWTRSProvider() CredentialProvider {
	return residualJWTRSProvider{}
}

// Mode implements CredentialProvider.
func (residualJWTRSProvider) Mode() Mode { return ModeJWTRSBearer }

// Obtain implements CredentialProvider — always residual not_configured.
func (residualJWTRSProvider) Obtain(ctx context.Context, caller Caller) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential obtain cancelled", err)
	}
	_ = caller
	return Credential{}, notConfigured(
		"gateway credential mode jwt_rs_bearer is residual (HOST-010); not_configured")
}

// Invalidate implements CredentialProvider.
func (residualJWTRSProvider) Invalidate(ctx context.Context, caller Caller) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway invalidate cancelled", err)
	}
	_ = caller
	return nil
}

// Status implements CredentialProvider.
func (residualJWTRSProvider) Status(ctx context.Context) ProviderStatus {
	_ = ctx
	return ProviderStatus{
		Configured:       false,
		Mode:             ModeJWTRSBearer,
		AudienceSet:      false,
		ASConfigured:     false,
		Ready:            false,
		ErrorCode:        string(apperr.CodeCapabilityMissing),
		ErrorMessageSafe: "jwt_rs_bearer residual (HOST-010); live IdP JWT RS not wired (OAUTH-009)",
	}
}

// RequireAPITokenVaultSetup constructs a Live Mode A provider from an injected vault.
// vault must be non-nil. Returns Ready provider for Obtain (HOST-009).
// Serve wiring residual: full multi-user Streamable HTTP is HOST-001; this only
// builds the CredentialProvider.
func RequireAPITokenVaultSetup(vault APITokenVault) (CredentialProvider, error) {
	if vault == nil {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"gateway mode api_token_vault requires a vault; not_configured")
	}
	p := NewAPITokenVaultProvider(vault)
	p.Live = true
	return p, nil
}
