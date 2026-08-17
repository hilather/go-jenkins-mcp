package profile_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// Regression: validateOIDCIssuerURL accepted cleartext http issuers for ANY
// host while the comment promised "http allowed only for loopback test
// fixtures". Discovery, the token endpoint (authorization code + PKCE
// verifier + refresh_token on every refresh), and the JWKS document all flow
// over that channel — a network MITM could steal refresh tokens and swap the
// JWKS keys. http is now restricted to loopback hosts.
func TestValidateOIDCIssuerHTTPLoopbackOnly(t *testing.T) {
	t.Parallel()
	base := profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "https://jenkins.example",
		AuthMethod:    profile.AuthMethodOIDC,
		OIDC: &profile.OIDCConfig{
			Issuer:          "https://idp.example",
			ClientID:        "jenkins-mcp",
			JenkinsAudience: "api://jenkins-api",
		},
	}

	// Cleartext non-loopback issuer must fail closed.
	bad := base
	bad.OIDC = &profile.OIDCConfig{Issuer: "http://idp.corp.internal", ClientID: "jenkins-mcp", JenkinsAudience: "api://jenkins-api"}
	if err := bad.Validate(); err == nil {
		t.Fatal("http issuer on a non-loopback host must be rejected")
	} else if !strings.Contains(err.Error(), "http") {
		t.Fatalf("error should mention http restriction: %v", err)
	}

	// Loopback http issuers remain allowed (unit tests / labs).
	for _, issuer := range []string{
		"http://127.0.0.1:8080/realms/x",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		ok := base
		ok.OIDC = &profile.OIDCConfig{Issuer: issuer, ClientID: "jenkins-mcp", JenkinsAudience: "api://jenkins-api"}
		if err := ok.Validate(); err != nil {
			t.Fatalf("loopback issuer %q must stay allowed: %v", issuer, err)
		}
	}

	// https remains allowed for any host.
	good := base
	if err := good.Validate(); err != nil {
		t.Fatalf("https issuer: %v", err)
	}
}
