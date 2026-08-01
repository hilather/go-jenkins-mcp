package main

import (
	"context"
	"strings"

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
//
// No-op when client or provider is nil. Caller is captured by value at attach
// time so mid-serve tool args cannot rebind identity.
func attachGatewayObtainAuthProvider(client *jenkins.Client, prov gateway.CredentialProvider, caller gateway.Caller) {
	if client == nil || prov == nil {
		return
	}
	p := prov
	c := caller
	client.WithAuthProvider(func() (user, secret string, sch jenkins.AuthScheme, err error) {
		ha, err := gateway.ObtainHTTPAuth(context.Background(), p, c)
		if err != nil {
			return "", "", "", err
		}
		return httpAuthToJenkins(ha)
	})
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
