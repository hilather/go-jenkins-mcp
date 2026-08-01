package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// LiveSessionSource provides mid-serve OIDC credentials with single-flight
// refresh and SessionGuard fail-closed signaling (wave 14 residual close).
//
// Call Credentials (or JenkinsAuthProvider) before each Jenkins HTTP request.
// api_token sessions do not use this type — leave jenkins.Client.AuthProvider nil.
//
// Secrets never appear in returned errors or Status maps.
type LiveSessionSource struct {
	// OIDC is the provider that loads/refreshes TokenBundle material.
	OIDC *OIDCProvider
	// Profile is the non-secret auth profile (issuer, client id, token endpoint).
	Profile Profile
	// Guard is the process session gate. Refresh failures and identity changes
	// mark the guard so subsequent tool paths fail closed.
	Guard *SessionGuard
	// HTTP is used only when ValidateAtServe needs discovery JWKS (optional).
	HTTP *http.Client
	// Epoch watches session.epoch for cross-process logout/re-login (optional).
	// When the file value changes, Guard is disabled and in-memory tokens cleared.
	Epoch *SessionEpochWatcher
}

// Credentials re-runs OIDC Authenticate (refresh if needed) and returns wire
// credentials. On refresh/auth failure, marks Guard.MarkRefreshFailed and
// returns a secret-free authentication error.
//
// Before auth, checks SessionEpochWatcher so CLI logout in another process
// fail-closes this serve without waiting for refresh failure.
func (s *LiveSessionSource) Credentials(ctx context.Context) (SessionCredentials, error) {
	if s == nil || s.OIDC == nil {
		return SessionCredentials{}, apperr.New(apperr.CodeInternal, "oidc live session source is not configured")
	}
	if s.Guard != nil {
		if err := s.Guard.Check(); err != nil {
			return SessionCredentials{}, err
		}
	}
	if err := s.checkEpochInvalidation(); err != nil {
		return SessionCredentials{}, err
	}
	if err := ctx.Err(); err != nil {
		return SessionCredentials{}, apperr.Wrap(apperr.CodeCancelled, "live credentials cancelled", err)
	}
	sess, err := s.OIDC.Authenticate(ctx, s.Profile)
	if err != nil {
		if s.Guard != nil {
			s.Guard.MarkRefreshFailed()
		}
		return SessionCredentials{}, scrubLiveCredError(err)
	}
	creds := SessionCredentialsFrom(sess)
	if strings.TrimSpace(creds.Secret) == "" {
		if s.Guard != nil {
			s.Guard.MarkRefreshFailed()
		}
		return SessionCredentials{}, apperr.New(apperr.CodeAuthentication,
			authFailureWithRecovery(s.Profile.ID, "oidc access token is empty"))
	}
	return creds, nil
}

// checkEpochInvalidation fail-closes when another process bumped session.epoch
// (logout / re-login). Clears in-memory OIDC bundle and disables the guard.
func (s *LiveSessionSource) checkEpochInvalidation() error {
	if s == nil || s.Epoch == nil {
		return nil
	}
	if err := s.Epoch.Check(); err != nil {
		// Cross-process invalidation: drop process-local tokens + gate tools.
		if s.OIDC != nil {
			s.OIDC.ClearMemory(string(s.Profile.ID))
		}
		if s.Guard != nil {
			s.Guard.Disable()
		}
		return scrubLiveCredError(err)
	}
	return nil
}

// Check implements tools.AuthGate: re-check session.epoch then SessionGuard.
// Use LiveSessionSource as AuthGate so tool dispatch fail-closes on CLI logout
// even when the handler does not call Jenkins Credentials().
// Nil receiver fails closed.
func (s *LiveSessionSource) Check() error {
	if s == nil {
		return apperr.New(apperr.CodeAuthentication, "session is not configured (fail closed)")
	}
	if err := s.checkEpochInvalidation(); err != nil {
		return err
	}
	if s.Guard != nil {
		return s.Guard.Check()
	}
	return nil
}

// JenkinsAuthProvider returns a callback suitable for jenkins.Client.AuthProvider
// after mapping HTTPAuthScheme → jenkins AuthScheme string values
// ("basic" / "bearer"). The callback uses context.Background() for refresh;
// CallJenkins cancellation still aborts the HTTP request itself.
//
// schemeOut is the auth.HTTPAuthScheme wire value; callers in cmd map to
// jenkins.AuthScheme. Prefer WireAuthProvider when the jenkins package is the
// only consumer and string schemes are acceptable.
func (s *LiveSessionSource) CredentialsOrMark(ctx context.Context) (user, secret string, scheme HTTPAuthScheme, err error) {
	c, err := s.Credentials(ctx)
	if err != nil {
		return "", "", "", err
	}
	return c.User, c.Secret, c.Scheme, nil
}

// DisableSession is logout residual for an in-process serve: mark the guard
// unusable so tool dispatch fails closed even if Client still holds a secret.
func (s *LiveSessionSource) DisableSession() {
	if s == nil || s.Guard == nil {
		return
	}
	s.Guard.Disable()
}

// ServeTokenValidation holds optional JWT validation inputs for serve start.
type ServeTokenValidation struct {
	// Issuer / Audience / ClientID / TenantID configure ValidateAccessToken.
	Issuer   string
	Audience string
	ClientID string
	TenantID string
	// JenkinsURL is used to reject IdP discovery co-hosted with Jenkins (ADR 0003).
	JenkinsURL string
	// HTTP fetches discovery + JWKS when the access token is JWT-shaped.
	HTTP *http.Client
}

// ValidateServeAccessToken validates a JWT-shaped access token at serve start
// using discovery JWKS. Opaque tokens return Form=opaque without network.
// Wrong audience / signature / issuer fails closed before tools register.
// Errors never include the raw token.
func ValidateServeAccessToken(ctx context.Context, raw string, v ServeTokenValidation) (AccessTokenResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AccessTokenResult{}, apperr.New(apperr.CodeAuthentication, "access token is required")
	}
	form := ClassifyAccessToken(raw)
	if form == TokenFormOpaque {
		// Residual: opaque reference tokens rely on Jenkins whoAmI (AUTH-004).
		return AccessTokenResult{Form: TokenFormOpaque}, nil
	}
	params := AccessTokenParamsFromOIDC(v.Issuer, v.Audience, v.ClientID, v.TenantID)
	if params.Issuer == "" || params.Audience == "" {
		return AccessTokenResult{}, apperr.New(apperr.CodeInvalidArgument,
			"oidc issuer and jenkins audience are required to validate jwt access tokens at serve start")
	}
	if v.HTTP == nil {
		return AccessTokenResult{}, apperr.New(apperr.CodeInternal,
			"http client is required to fetch jwks for jwt validation")
	}
	doc, err := FetchAndValidateDiscovery(ctx, v.HTTP, params.Issuer, v.JenkinsURL)
	if err != nil {
		return AccessTokenResult{}, err
	}
	jwks, err := FetchJWKSFromDiscovery(ctx, v.HTTP, doc)
	if err != nil {
		return AccessTokenResult{}, err
	}
	return ValidateAccessToken(raw, jwks, params)
}

// GroupsFromValidatedToken extracts bounded groups for policy.Subject after
// successful JWT validation (or from opaque-safe empty set).
// Call only after ValidateAccessToken / ValidateServeAccessToken for JWT form;
// ExtractGroupsFromJWT is payload-only and does not re-verify the signature.
// Opaque tokens: no local group claims (whoAmI / Jenkins groups residual).
func GroupsFromValidatedToken(raw string, result AccessTokenResult, cfg GroupClaimConfig) (GroupExtractResult, error) {
	if result.Form != TokenFormJWT {
		// Opaque: skip JWT parse; rely on whoAmI (AUTH-004) for principal binding.
		return GroupExtractResult{}, nil
	}
	// Prefer re-parse with GroupClaimConfig (roles + groups); claims on result
	// only include the JWT "groups" array field. MaxStoredGroups + MaxGroupNameBytes apply.
	return ExtractGroupsFromJWT(raw, cfg)
}

// SubjectBinding holds non-secret identity fields derived at serve start for
// policy.Subject and SessionGuard fingerprinting.
type SubjectBinding struct {
	ExternalSubject string
	Tenant          string
	Groups          []string
	Fingerprint     string
	// ResidualNote is non-secret (group overage, etc.).
	ResidualNote string
}

// BindOIDCSubject builds policy-facing binding from JWT claims / groups and a
// verified Jenkins principal id. Never includes tokens.
func BindOIDCSubject(externalSub, tenant, jenkinsPrincipal string, groups []string, residual string) SubjectBinding {
	gs := append([]string(nil), groups...)
	fp := IdentityFingerprint(externalSub, tenant, jenkinsPrincipal, gs)
	return SubjectBinding{
		ExternalSubject: strings.TrimSpace(externalSub),
		Tenant:          strings.TrimSpace(tenant),
		Groups:          gs,
		Fingerprint:     fp,
		ResidualNote:    strings.TrimSpace(residual),
	}
}

func scrubLiveCredError(err error) error {
	if err == nil {
		return nil
	}
	// Authenticate paths already scrub; belt-and-suspenders for canary tests.
	msg := apperr.ModelMessage(err)
	if prLooksLikeSecret(msg) {
		return apperr.New(apperr.CodeOf(err), "authentication failed; re-authenticate")
	}
	return err
}
