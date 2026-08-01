package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// Caller is the validated gateway caller identity used to obtain Jenkins-audience
// credentials (GWY-001). Fields are non-secret labels; never put tokens here.
type Caller struct {
	// Subject is the Entra/OIDC subject (sub) of the validated inbound caller.
	Subject string
	// Tenant is the IdP tenant id when applicable.
	Tenant string
	// WorkloadID is the AgentCore / gateway workload identity.
	WorkloadID string
	// ProfileID is the MCP connection profile namespace.
	ProfileID contracts.ProfileID
}

// CacheKey returns the token-cache key for this caller (HOST-004: includes tenant).
func (c Caller) CacheKey() CacheKey {
	return CacheKey{
		User:     strings.TrimSpace(c.Subject),
		Tenant:   strings.TrimSpace(c.Tenant),
		Workload: strings.TrimSpace(c.WorkloadID),
		Profile:  strings.TrimSpace(string(c.ProfileID)),
	}
}

// SubjectKey returns the stable multi-tenant namespace key for this caller
// (tenant|subject|profile). Same as package SubjectKey(c); convenience for
// cache / continuation / limiter isolation (HOST-004 / HOST-006).
func (c Caller) SubjectKey() string {
	return SubjectKey(c)
}

// Valid reports whether the caller has the minimum binding fields.
func (c Caller) Valid() bool {
	return strings.TrimSpace(c.Subject) != "" &&
		strings.TrimSpace(string(c.ProfileID)) != ""
}

// StatusMap is a non-secret summary.
func (c Caller) StatusMap() map[string]any {
	return map[string]any{
		"subject":     strings.TrimSpace(c.Subject),
		"tenant":      strings.TrimSpace(c.Tenant),
		"workload_id": strings.TrimSpace(c.WorkloadID),
		"profile_id":  strings.TrimSpace(string(c.ProfileID)),
	}
}

// Credential is a short-lived Jenkins-audience credential result.
// AccessToken must never appear in logs, errors, or MCP tool output.
type Credential struct {
	// AccessToken is memory-only bearer material (secret).
	AccessToken string
	// ExpiresAt bounds use of AccessToken.
	ExpiresAt time.Time
	// JenkinsPrincipal is the non-secret exchanged Jenkins user id when known.
	JenkinsPrincipal string
	// Mode is the acquisition mode that produced this credential.
	Mode Mode
}

// String never includes the access token (canary target).
func (c Credential) String() string {
	exp := ""
	if !c.ExpiresAt.IsZero() {
		exp = c.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("credential principal=%s mode=%s expires=%s",
		strings.TrimSpace(c.JenkinsPrincipal), c.Mode.String(), exp)
}

// CredentialProvider obtains Jenkins-audience credentials for a validated caller.
// Implementations must fail closed when AgentCore is not configured or unavailable
// and must never fall back to a shared Jenkins service account.
type CredentialProvider interface {
	// Mode returns the configured acquisition mode.
	Mode() Mode
	// Obtain returns a Jenkins-audience credential or a ConsentRequired /
	// capability_missing / authentication error. Never returns a shared SA token.
	Obtain(ctx context.Context, caller Caller) (Credential, error)
	// Invalidate drops cached material for the caller (logout / revoke).
	Invalidate(ctx context.Context, caller Caller) error
	// Status is a non-secret provider readiness view.
	Status(ctx context.Context) ProviderStatus
}

// ProviderStatus is safe for status/doctor (no tokens).
type ProviderStatus struct {
	Configured   bool
	Mode         Mode
	AudienceSet  bool
	ASConfigured bool
	// Ready is true only when live AgentCore acquisition is available.
	// Foundation stubs always leave Ready=false.
	Ready            bool
	ErrorCode        string
	ErrorMessageSafe string
}

// AgentCoreProvider is the fail-closed AgentCore credential provider (GWY-001).
// Default construction leaves Live=false and Fetcher=nil (not_configured).
// When Live=true and Fetcher is injected (mock AS or HTTPTokenFetcher), Obtain
// validates caller/config, uses TokenCache, and calls Fetcher — never a shared SA.
// Live Entra / AgentCore production pin remains GWY-003 residual.
type AgentCoreProvider struct {
	Config AgentCoreConfig
	Cache  TokenCache
	// Live enables the obtain path. When false (default), Obtain always returns
	// not_configured regardless of cache or Fetcher.
	Live bool
	// Fetcher is the optional pluggable token acquisition backend.
	// Required when Live=true; nil + Live=true → capability_missing (not silent success).
	Fetcher TokenFetcher
	// ConsentStore holds progressive consent metadata only when Obtain returns
	// ConsentRequired (auth URL + session id; never tokens). nil → process-local
	// default (ProcessConsentSessionStore). Optional file-backed path is residual
	// crash recovery of metadata only; same-host reload-before-persist flock lite —
	// not multi-replica shared store.
	ConsentStore ConsentSessionStore
	// Principals is the optional companion PrincipalStore cleared on Invalidate
	// (GWY-002 / HOST-003 force re-auth residual lite). When nil, Invalidate
	// uses ProcessPrincipalCache so multi-user Binding/policy principals drop
	// with the token cache. Tests may inject a private *PrincipalCache.
	Principals PrincipalStore
}

// NewAgentCoreProvider constructs a provider after validating cfg.
// Always returns Live=false and Fetcher=nil (fail-closed default).
// Returns an error when ValidateProviderConfig fails.
func NewAgentCoreProvider(cfg AgentCoreConfig, cache TokenCache) (*AgentCoreProvider, error) {
	if err := ValidateProviderConfig(cfg); err != nil {
		return nil, err
	}
	if cache == nil {
		cache = NewMemoryTokenCache(0)
	}
	if strings.TrimSpace(string(cfg.Mode)) == "" {
		cfg.Mode = ModeAuthorizationCode
	} else {
		cfg.Mode = NormalizeMode(cfg.Mode)
	}
	return &AgentCoreProvider{Config: cfg, Cache: cache, Live: false, Fetcher: nil}, nil
}

// Mode implements CredentialProvider.
func (p *AgentCoreProvider) Mode() Mode {
	if p == nil {
		return ""
	}
	m := NormalizeMode(p.Config.Mode)
	if m == "" {
		return ModeAuthorizationCode
	}
	return m
}

// Obtain implements CredentialProvider.
//
// Fail-closed paths:
//   - Live=false → not_configured (cache ignored so poison cache cannot elevate)
//   - Live=true + Fetcher=nil → capability_missing
//   - Fetcher error → authentication / capability_missing / ConsentRequired;
//     never a shared Jenkins service account
//
// Success path (Live + Fetcher): cache lookup → Fetcher → cache store → Credential.
func (p *AgentCoreProvider) Obtain(ctx context.Context, caller Caller) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential obtain cancelled", err)
	}
	if p == nil {
		return Credential{}, notConfigured("credential provider is nil")
	}
	if err := ValidateProviderConfig(p.Config); err != nil {
		return Credential{}, err
	}
	if !caller.Valid() {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject and profile are required")
	}
	// Never fall back to a shared Jenkins identity.
	if !p.Live {
		return Credential{}, notConfigured(
			"agentcore credential provider is not configured for live acquisition")
	}
	if p.Fetcher == nil {
		return Credential{}, apperr.New(apperr.CodeCapabilityMissing,
			"agentcore live credential acquisition requires a TokenFetcher; not wired")
	}

	// Cache hit (memory only; never log token bytes).
	if p.Cache != nil {
		if tok, ok := p.Cache.Get(caller.CacheKey()); ok {
			return Credential{
				AccessToken:      tok.AccessToken,
				ExpiresAt:        tok.ExpiresAt,
				JenkinsPrincipal: tok.JenkinsPrincipal,
				Mode:             tok.Mode,
			}, nil
		}
	}

	cred, err := p.Fetcher.FetchJenkinsCredential(ctx, caller, p.Config)
	if err != nil {
		mapped := mapFetcherError(err)
		// Process-local consent metadata residual (OAUTH-010 / GWY-001):
		// remember auth URL + session id only when ConsentRequired — never tokens.
		if cr, ok := AsConsentRequired(mapped); ok && cr != nil {
			RememberConsentRequired(p.consentStore(), SubjectKey(caller), cr.Info)
		}
		return Credential{}, mapped
	}
	if strings.TrimSpace(cred.AccessToken) == "" {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"credential fetch returned empty access_token")
	}
	if cred.Mode == "" {
		cred.Mode = p.Mode()
	}

	if p.Cache != nil {
		p.Cache.Set(caller.CacheKey(), CachedToken{
			AccessToken:      cred.AccessToken,
			ExpiresAt:        cred.ExpiresAt,
			JenkinsPrincipal: cred.JenkinsPrincipal,
			Mode:             cred.Mode,
		})
	}
	return cred, nil
}

// Invalidate implements CredentialProvider.
// Drops token-cache material for the caller and the companion PrincipalCache
// entry (SubjectKey) so the next Obtain / Binding re-binds (force re-auth residual lite).
// Never logs tokens. Multi-pod / live Entra revocation remain residual.
func (p *AgentCoreProvider) Invalidate(ctx context.Context, caller Caller) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway invalidate cancelled", err)
	}
	if p == nil {
		return nil
	}
	principals := p.Principals
	if principals == nil {
		principals = ProcessPrincipalCache()
	}
	_ = InvalidateSubjectLocal(caller, principals, p.Cache)
	return nil
}

// Status implements CredentialProvider.
func (p *AgentCoreProvider) Status(ctx context.Context) ProviderStatus {
	_ = ctx
	st := ProviderStatus{}
	if p == nil {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "credential provider is not configured"
		return st
	}
	st.Mode = p.Mode()
	st.AudienceSet = strings.TrimSpace(p.Config.Audience) != ""
	st.ASConfigured = strings.TrimSpace(p.Config.AuthorizationServerBaseURL) != ""
	st.Configured = p.Config.Configured() && ValidateProviderConfig(p.Config) == nil
	// Ready only when live obtain can actually run (Fetcher present).
	st.Ready = st.Configured && p.Live && p.Fetcher != nil
	if !st.Configured {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "agentcore provider is not configured"
	} else if !p.Live {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "agentcore provider is configured but live acquisition is not wired"
	} else if p.Fetcher == nil {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "agentcore live acquisition requires a TokenFetcher"
	}
	return st
}

// consentStore returns the provider consent metadata store or the process default.
// Metadata only — never tokens.
func (p *AgentCoreProvider) consentStore() ConsentSessionStore {
	if p != nil && p.ConsentStore != nil {
		return p.ConsentStore
	}
	return ProcessConsentSessionStore()
}

// notConfigured returns a stable capability_missing error for unconfigured paths.
func notConfigured(msg string) error {
	if strings.TrimSpace(msg) == "" {
		msg = "gateway credential provider is not configured"
	}
	return apperr.New(apperr.CodeCapabilityMissing, msg)
}

// UnconfiguredProvider is a CredentialProvider that always fails closed.
// Useful when --gateway is set without a constructible provider.
type UnconfiguredProvider struct {
	Reason string
}

// Mode implements CredentialProvider.
func (UnconfiguredProvider) Mode() Mode { return ModeAuthorizationCode }

// Obtain implements CredentialProvider.
func (p UnconfiguredProvider) Obtain(ctx context.Context, caller Caller) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential obtain cancelled", err)
	}
	_ = caller
	msg := p.Reason
	if strings.TrimSpace(msg) == "" {
		msg = "agentcore credential provider is not configured"
	}
	return Credential{}, notConfigured(msg)
}

// Invalidate implements CredentialProvider.
func (UnconfiguredProvider) Invalidate(ctx context.Context, caller Caller) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway invalidate cancelled", err)
	}
	return nil
}

// Status implements CredentialProvider.
func (p UnconfiguredProvider) Status(ctx context.Context) ProviderStatus {
	_ = ctx
	msg := p.Reason
	if strings.TrimSpace(msg) == "" {
		msg = "agentcore credential provider is not configured"
	}
	return ProviderStatus{
		Configured:       false,
		Ready:            false,
		ErrorCode:        string(apperr.CodeCapabilityMissing),
		ErrorMessageSafe: msg,
	}
}
