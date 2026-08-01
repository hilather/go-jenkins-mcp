package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// JWTRSBearerProvider is the Mode B CredentialProvider (HOST-010 offline).
//
// Obtain looks up the JWT vault for SubjectKey(caller) and returns Bearer
// material (Jenkins-audience access token). Missing entries fail closed
// (not_found / not_configured) — never fall back to another subject, Mode A
// API token vault, AgentCore, ambient keyring, or a shared Jenkins SA.
//
// Tokens are access tokens only — never ID tokens (see JWTVault docs).
// Live jwt-auth-filter production pin remains OAUTH-009 residual.
//
// Live=false (default from NewJWTRSBearerProvider) always returns
// not_configured so accidental construction cannot elevate.
type JWTRSBearerProvider struct {
	Vault JWTVault
	// Live enables Obtain. When false, always not_configured (vault ignored).
	Live bool
	// Principals is the optional companion PrincipalCache cleared on Invalidate
	// (GWY-002 / HOST-003 force re-auth residual lite). When nil, Invalidate
	// uses ProcessPrincipalCache. Does not delete durable JWT vault entries.
	Principals *PrincipalCache
}

// NewJWTRSBearerProvider constructs a fail-closed Mode B provider (Live=false).
// vault may be nil; Obtain then fails closed as not_configured when Live is set.
func NewJWTRSBearerProvider(vault JWTVault) *JWTRSBearerProvider {
	return &JWTRSBearerProvider{Vault: vault, Live: false}
}

// Mode implements CredentialProvider.
func (p *JWTRSBearerProvider) Mode() Mode {
	return ModeJWTRSBearer
}

// Obtain implements CredentialProvider for Mode B.
//
// Fail-closed paths:
//   - Live=false → not_configured
//   - Vault=nil → not_configured
//   - invalid caller → authentication
//   - missing subject entry → not_found (never other subject / Mode A fallthrough)
//   - empty token in vault → authentication
//
// Success: Credential with AccessToken=token, Mode=jwt_rs_bearer.
// Callers use HTTPAuthFromCredential / ObtainHTTPAuth for Bearer scheme.
func (p *JWTRSBearerProvider) Obtain(ctx context.Context, caller Caller) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, apperr.Wrap(apperr.CodeCancelled, "gateway credential obtain cancelled", err)
	}
	if p == nil {
		return Credential{}, notConfigured("jwt rs bearer provider is nil")
	}
	if !caller.Valid() {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject and profile are required")
	}
	if !p.Live {
		return Credential{}, notConfigured(
			"jwt rs bearer provider is not configured for live acquisition")
	}
	if p.Vault == nil {
		return Credential{}, notConfigured(
			"jwt access token vault is not configured")
	}

	key := SubjectKey(caller)
	if err := ValidateSubjectKey(key); err != nil {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject key is invalid")
	}

	token, ok, err := p.Vault.Get(ctx, key)
	if err != nil {
		return Credential{}, mapJWTVaultError(err)
	}
	if !ok {
		// Fail closed: no shared SA / Mode A vault / other-subject fallthrough.
		return Credential{}, apperr.New(apperr.CodeNotFound,
			"jenkins-audience access token not found for gateway subject")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"jwt access token vault entry is empty")
	}
	// Defense in depth: reject id_token even if put bypassed (corrupt file).
	if err := rejectIDTokenAsAPICredential(token); err != nil {
		return Credential{}, apperr.New(apperr.CodeAuthentication,
			"id_token cannot be used as jenkins api credential")
	}

	// ExpiresAt left zero for lab vault tokens (operator-rotated); live IdP
	// tokens with exp are a residual of OAUTH-009 / cache TTL.
	return Credential{
		AccessToken: token,
		ExpiresAt:   time.Time{},
		Mode:        ModeJWTRSBearer,
	}, nil
}

// Invalidate implements CredentialProvider.
// Mode B lab vault has no short-lived token cache; durable vault delete is
// operator-driven via vault Delete. Invalidate clears the companion
// PrincipalCache entry so the next Binding/policy path re-Obtains (force
// re-auth residual lite) — never the durable JWT vault entry.
func (p *JWTRSBearerProvider) Invalidate(ctx context.Context, caller Caller) error {
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
	_ = InvalidateSubjectLocal(caller, principals, nil)
	return nil
}

// Status implements CredentialProvider.
func (p *JWTRSBearerProvider) Status(ctx context.Context) ProviderStatus {
	_ = ctx
	st := ProviderStatus{Mode: ModeJWTRSBearer}
	if p == nil {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "jwt rs bearer provider is not configured"
		return st
	}
	st.Configured = p.Vault != nil
	st.Ready = st.Configured && p.Live
	// Mode B does not use AgentCore AS; audience is enforced by Jenkins RS.
	st.AudienceSet = false
	st.ASConfigured = false
	if !st.Configured {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "jwt access token vault is not configured"
	} else if !p.Live {
		st.ErrorCode = string(apperr.CodeCapabilityMissing)
		st.ErrorMessageSafe = "jwt rs bearer is configured but live acquisition is not enabled"
	}
	return st
}

func mapJWTVaultError(err error) error {
	if err == nil {
		return nil
	}
	if apperr.CodeOf(err) != "" && apperr.CodeOf(err).Valid() {
		code := apperr.CodeOf(err)
		switch code {
		case apperr.CodeCancelled, apperr.CodeTimeout, apperr.CodeInvalidArgument,
			apperr.CodeNotFound, apperr.CodeCorruptCache, apperr.CodeCapabilityMissing:
			return err
		default:
			return apperr.New(apperr.CodeAuthentication, "jwt access token vault lookup failed")
		}
	}
	return apperr.New(apperr.CodeAuthentication, "jwt access token vault lookup failed")
}

// RequireJWTRSBearerSetup constructs a Live Mode B provider from an injected vault.
// vault must be non-nil. Returns Ready provider for Obtain (HOST-010 offline).
// Live jwt-auth-filter / Entra pin remains OAUTH-009 residual.
func RequireJWTRSBearerSetup(vault JWTVault) (CredentialProvider, error) {
	if vault == nil {
		return nil, apperr.New(apperr.CodeCapabilityMissing,
			"gateway mode jwt_rs_bearer requires a jwt vault; not_configured")
	}
	p := NewJWTRSBearerProvider(vault)
	p.Live = true
	return p, nil
}
