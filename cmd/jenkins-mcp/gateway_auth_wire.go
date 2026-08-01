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
// bound caller (HOST-003).
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
func attachGatewayObtainAuthProvider(client *jenkins.Client, prov gateway.CredentialProvider, caller gateway.Caller) {
	if client == nil || prov == nil {
		return
	}
	p := prov
	c := caller
	client.WithAuthProvider(func() (user, secret string, sch jenkins.AuthScheme, err error) {
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, c)
		if err != nil {
			// Preserve ConsentRequired for progressive UX; never map to static SA.
			return "", "", "", err
		}
		return httpAuthToJenkins(ha)
	})
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

// verifyGatewayObtainWhoAmI runs Jenkins whoAmI using the Obtain-wired AuthProvider
// (HOST-003 session-start identity for Ready path).
//
// Fail closed when:
//   - client/AuthProvider missing
//   - Obtain / whoAmI fails (including ConsentRequired)
//   - principal anonymous / empty
//   - expectedJenkinsUser non-empty and does not match whoAmI id
//
// Secrets never appear in returned errors (AuthProvider / WhoAmI discipline).
func verifyGatewayObtainWhoAmI(ctx context.Context, client *jenkins.Client, expectedJenkinsUser string) (jenkins.WhoAmI, error) {
	if err := ctx.Err(); err != nil {
		return jenkins.WhoAmI{}, apperr.Wrap(apperr.CodeCancelled, "gateway obtain whoAmI cancelled", err)
	}
	if client == nil {
		return jenkins.WhoAmI{}, apperr.New(apperr.CodeInternal, "jenkins client is nil for gateway obtain whoAmI")
	}
	if client.AuthProvider == nil {
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
