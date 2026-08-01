package main

import (
	"context"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// attachGatewayObtainAuthProvider installs a per-request AuthProvider that
// obtains Jenkins credentials via gateway.CredentialProvider.Obtain for the
// bound caller (HOST-003 single-subject foundation).
//
// Behavior:
//   - Mode A (api_token_vault Ready): Basic username+token from vault for caller only
//   - Mode B/C Ready: Bearer access token from Obtain
//   - Obtain failure: error (fail closed); never falls back to static User/Token
//     or OIDC LiveSessionSource / keyring
//   - ConsentRequired (Mode C): surfaces as error with auth URL + session metadata
//     only (via gateway.AsConsentRequired); never embeds tokens
//
// No-op when client or provider is nil. Caller is captured by value at attach
// time so mid-serve tool args cannot rebind identity.
//
// After attach, callers should clearGatewayLocalSessionCredentials so residual
// keyring/static material cannot be used if AuthProvider is ever cleared, and
// verifyGatewayObtainWhoAmI so session-start identity uses Obtain credentials.
//
// For per-request multi-user Obtain (JENKINS_MCP_GATEWAY_MULTI_USER=1), use
// attachGatewayObtainAuthProviderDynamic instead.
func attachGatewayObtainAuthProvider(client *jenkins.Client, prov gateway.CredentialProvider, caller gateway.Caller) {
	if client == nil || prov == nil {
		return
	}
	p := prov
	c := caller
	// Single-subject path: clear any multi-user provider so pin + fixed caller win.
	client.WithAuthProviderCtx(nil)
	client.WithAuthProvider(func() (user, secret string, sch jenkins.AuthScheme, err error) {
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, c)
		if err != nil {
			// Preserve ConsentRequired for progressive UX; never map to static SA.
			return "", "", "", err
		}
		return httpAuthToJenkins(ha)
	})
}

// attachGatewayObtainAuthProviderDynamic installs AuthProviderCtx that Obtains
// credentials for the Caller on the request context when present and Valid,
// otherwise the process defaultCaller (HOST multi-user foundation).
//
// Fail closed:
//   - empty / invalid subject → error (never shared SA or ambient keyring)
//   - Obtain error → error; never another subject's token
//   - does not write secrets onto Client.User/Token (AuthProviderCtx path)
//
// On successful Obtain, records the non-secret Jenkins principal in the process
// PrincipalCache (SubjectKey → principal) so mutation Binding and multi-user
// policy SubjectFromContext (policySubjectFromGatewayCtx) can prefer it after
// Obtain. AuthProviderCtx still cannot write onto request context; the process
// PrincipalCache is the mid-call rewrite path for JenkinsUserID / Binding.
//
// No-op when client or provider is nil. defaultCaller is captured at attach
// for session-start whoAmI and stdio residual when context has no Caller.
//
// Wire with JENKINS_MCP_GATEWAY_MULTI_USER=1 and HTTP AfterIdentity injecting
// gateway.Caller from trusted RequestIdentity (never tool args).
//
// requireContextCaller=true (multi-user Ready): fail closed when context has no
// Caller — never silent fallthrough to defaultCaller (credential mix-up risk).
// Session-start whoAmI must pass ContextWithCaller(defaultCaller).
// requireContextCaller=false: allow defaultCaller when ctx has no Caller (tests).
func attachGatewayObtainAuthProviderDynamic(client *jenkins.Client, prov gateway.CredentialProvider, defaultCaller gateway.Caller, requireContextCaller bool) {
	attachGatewayObtainAuthProviderDynamicWithCache(client, prov, defaultCaller, requireContextCaller, gateway.ProcessPrincipalCache())
}

// attachGatewayObtainAuthProviderDynamicWithCache is the injectable variant for
// tests (private PrincipalCache). production wire uses ProcessPrincipalCache.
func attachGatewayObtainAuthProviderDynamicWithCache(
	client *jenkins.Client,
	prov gateway.CredentialProvider,
	defaultCaller gateway.Caller,
	requireContextCaller bool,
	principalCache gateway.PrincipalStore,
) {
	if client == nil || prov == nil {
		return
	}
	p := prov
	def := defaultCaller
	require := requireContextCaller
	cache := principalCache
	// Multi-user path: clear fixed AuthProvider so only context-scoped Obtain runs.
	client.WithAuthProvider(nil)
	client.WithAuthProviderCtx(func(ctx context.Context) (user, secret string, sch jenkins.AuthScheme, err error) {
		if err := ctx.Err(); err != nil {
			return "", "", "", apperr.Wrap(apperr.CodeCancelled, "gateway multi-user Obtain cancelled", err)
		}
		c, ok := gateway.CallerFromContext(ctx)
		if !ok || strings.TrimSpace(c.Subject) == "" {
			if require {
				return "", "", "", apperr.New(apperr.CodeAuthentication,
					"gateway multi-user Obtain requires caller in context (no defaultCaller fallthrough)")
			}
			// Test / residual path: use process default when context has no Caller.
			if !def.Valid() {
				return "", "", "", apperr.New(apperr.CodeAuthentication,
					"gateway multi-user caller subject and profile are required")
			}
			return obtainAndRememberPrincipal(ctx, p, def, cache)
		}
		// Only rebind when the context caller is Valid after merge; fail closed
		// rather than silently falling through to default for a partial spoof.
		caller := gateway.MergeCallerDefaults(c, def)
		if !caller.Valid() {
			return "", "", "", apperr.New(apperr.CodeAuthentication,
				"gateway multi-user caller subject and profile are required")
		}
		return obtainAndRememberPrincipal(ctx, p, caller, cache)
	})
}

// obtainAndRememberPrincipal Obtains credentials for caller, maps to Jenkins
// wire auth, and caches the non-secret Jenkins principal under SubjectKey.
// Uses Obtain + HTTPAuthFromCredential so Credential.JenkinsPrincipal is
// available (Mode A vault username); never stores AccessToken in the cache.
func obtainAndRememberPrincipal(
	ctx context.Context,
	p gateway.CredentialProvider,
	caller gateway.Caller,
	cache gateway.PrincipalStore,
) (user, secret string, sch jenkins.AuthScheme, err error) {
	if p == nil {
		return "", "", "", apperr.New(apperr.CodeAuthentication, "gateway credential provider is nil")
	}
	cred, err := p.Obtain(ctx, caller)
	if err != nil {
		// Preserve ConsentRequired; never map to static SA or other subject.
		return "", "", "", err
	}
	ha, err := gateway.HTTPAuthFromCredential(cred)
	if err != nil {
		return "", "", "", err
	}
	gateway.RememberObtainPrincipal(cache, caller, cred, ha)
	return httpAuthToJenkins(ha)
}

// clearGatewayLocalSessionCredentials removes static keyring/OIDC User/Token
// from the Jenkins client after Obtain AuthProvider is installed (HOST-003 Ready).
//
// When AuthProvider is set, applyAuth never falls through on Obtain failure —
// this clears residual local session material so a cleared/nil AuthProvider
// cannot silently send bootstrap keyring credentials either.
func clearGatewayLocalSessionCredentials(client *jenkins.Client) {
	if client == nil {
		return
	}
	client.User = ""
	client.Token = ""
}

// verifyGatewayObtainWhoAmI runs Jenkins whoAmI using the Obtain-wired
// AuthProvider or AuthProviderCtx (HOST-003 session-start identity for Ready path).
//
// Fail closed when:
//   - client / live Obtain provider missing
//   - Obtain / whoAmI fails (including ConsentRequired)
//   - principal anonymous / empty
//   - expectedJenkinsUser non-empty and does not match whoAmI id
//
// Secrets never appear in returned errors (AuthProvider / WhoAmI discipline).
// Multi-user: pass a context with gateway.Caller when verifying a non-default
// subject; Background uses the process defaultCaller captured at attach.
func verifyGatewayObtainWhoAmI(ctx context.Context, client *jenkins.Client, expectedJenkinsUser string) (jenkins.WhoAmI, error) {
	if err := ctx.Err(); err != nil {
		return jenkins.WhoAmI{}, apperr.Wrap(apperr.CodeCancelled, "gateway obtain whoAmI cancelled", err)
	}
	if client == nil {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeInternal, "jenkins client is nil for gateway obtain whoAmI")
	}
	if !client.HasLiveAuthProvider() {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeCapabilityMissing,
			"gateway Obtain AuthProvider is not installed; refuse local session whoAmI")
	}
	who, err := client.WhoAmI(ctx)
	if err != nil {
		// Preserve ConsentRequired / classified apperr from AuthProvider path.
		if cr, ok := gateway.AsConsentRequired(err); ok && cr != nil {
			return jenkins.WhoAmI{}, cr
		}
		if code := apperr.CodeOf(err); code != "" && code.Valid() {
			return jenkins.WhoAmI{}, err
		}
		return jenkins.WhoAmI{}, apperr.Wrap(apperr.CodeAuthentication, "gateway Obtain whoAmI failed", err)
	}
	id := strings.TrimSpace(who.ID)
	if who.Anonymous || strings.EqualFold(id, "anonymous") || id == "" {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeAuthentication,
			"gateway Obtain whoAmI is anonymous; authentication failed closed")
	}
	expected := strings.TrimSpace(expectedJenkinsUser)
	if expected != "" && !strings.EqualFold(id, expected) {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeAuthentication,
			"gateway Obtain whoAmI principal does not match bound subject jenkins identity")
	}
	return who, nil
}

// httpAuthToJenkins maps gateway.HTTPAuth to jenkins wire credentials.
// Secrets are returned only as the secret field; never embedded in err.
func httpAuthToJenkins(ha gateway.HTTPAuth) (user, secret string, sch jenkins.AuthScheme, err error) {
	switch strings.ToLower(strings.TrimSpace(ha.Scheme)) {
	case gateway.HTTPAuthSchemeBearer:
		return strings.TrimSpace(ha.Username), ha.Token, jenkins.AuthSchemeBearer, nil
	default:
		// Mode A Basic (and empty scheme treated as basic by jenkins applyAuth).
		return strings.TrimSpace(ha.Username), ha.Token, jenkins.AuthSchemeBasic, nil
	}
}

// gatewayObtainReady reports whether the provider is Ready for live Obtain
// (HOST-003 wire gate). Status is non-secret.
func gatewayObtainReady(prov gateway.CredentialProvider) bool {
	if prov == nil {
		return false
	}
	return prov.Status(context.Background()).Ready
}
