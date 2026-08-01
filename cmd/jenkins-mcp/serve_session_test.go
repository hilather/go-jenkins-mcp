package main

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

func TestApplyOIDCSubjectFields(t *testing.T) {
	t.Parallel()
	base := policy.NewSubject("corp", "alice", true)
	oidc := serveOIDCSession{
		TokenResult: auth.AccessTokenResult{
			Form: auth.TokenFormJWT,
			Claims: auth.AccessTokenClaims{
				Subject:  "sub-1",
				TenantID: "tid-from-token",
			},
		},
		Groups: auth.GroupExtractResult{Groups: []string{"ops", "dev"}},
	}
	prof := &profile.Profile{
		OIDC: &profile.OIDCConfig{TenantID: "tid-profile"},
	}
	got := applyOIDCSubjectFields(base, auth.Session{Method: auth.MethodOIDC}, oidc, prof)
	if got.ExternalSubject != "sub-1" {
		t.Fatalf("external: %q", got.ExternalSubject)
	}
	if got.Tenant != "tid-profile" {
		t.Fatalf("tenant prefers profile: %q", got.Tenant)
	}
	if len(got.Groups) != 2 {
		t.Fatalf("groups: %v", got.Groups)
	}
	// api_token leaves subject unchanged.
	api := applyOIDCSubjectFields(base, auth.Session{Method: auth.MethodAPIToken}, oidc, prof)
	if api.ExternalSubject != "" || len(api.Groups) != 0 {
		t.Fatalf("api_token must not attach oidc fields: %+v", api)
	}
}

func TestAttachLiveAuthProvider_NilSafe(t *testing.T) {
	t.Parallel()
	attachLiveAuthProvider(nil, nil)
	c := &jenkins.Client{}
	attachLiveAuthProvider(c, nil)
	if c.AuthProvider != nil {
		t.Fatal("nil live must not install AuthProvider")
	}
}
