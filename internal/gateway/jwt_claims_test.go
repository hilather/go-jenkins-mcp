package gateway_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// GWY-002: JWT access-token claims → InboundClaims (Verified=true).
func TestInboundClaimsFromJWTClaims_Success(t *testing.T) {
	t.Parallel()
	c := auth.AccessTokenClaims{
		Subject:           "entra-sub-1",
		PreferredUsername: "alice@corp",
		TenantID:          "tid-guid",
		Groups:            []string{"g1", "g2"},
		TokenUse:          "access_token",
	}
	claims, err := gateway.InboundClaimsFromJWTClaims(c, contracts.ProfileID("corp"), "wl-1")
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Verified {
		t.Fatal("Verified must be true for verified JWT claims")
	}
	if claims.Subject != "entra-sub-1" || claims.Tenant != "tid-guid" {
		t.Fatalf("%+v", claims)
	}
	if claims.WorkloadID != "wl-1" || claims.JenkinsPrincipal != "alice@corp" {
		t.Fatalf("%+v", claims)
	}
	if claims.ProfileID != "corp" || len(claims.Groups) != 2 {
		t.Fatalf("%+v", claims)
	}
	// BindSubject works with default opts when tenant/workload present.
	s, err := gateway.BindSubject(claims, gateway.DefaultBindOptions())
	if err != nil {
		t.Fatal(err)
	}
	if s.ExternalSubject != "entra-sub-1" || s.JenkinsUserID != "alice@corp" {
		t.Fatalf("%+v", s)
	}
}

func TestInboundClaimsFromJWTClaims_FailClosed(t *testing.T) {
	t.Parallel()
	base := auth.AccessTokenClaims{Subject: "sub-1", TenantID: "t"}

	_, err := gateway.InboundClaimsFromJWTClaims(auth.AccessTokenClaims{}, "corp", "wl")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("empty subject: %v", err)
	}

	_, err = gateway.InboundClaimsFromJWTClaims(base, "", "wl")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("empty profile: %v", err)
	}

	// ID token use rejected.
	idc := base
	idc.TokenUse = "id_token"
	_, err = gateway.InboundClaimsFromJWTClaims(idc, "corp", "wl")
	if err == nil || !strings.Contains(err.Error(), "id_token") {
		t.Fatalf("id_token: %v", err)
	}
}

func TestInboundClaimsFromRequestIdentity_SuccessAndFailClosed(t *testing.T) {
	t.Parallel()
	in := gateway.HTTPInbound{
		ExternalSubject:  "lab-sub",
		Tenant:           "t1",
		WorkloadID:       "w1",
		JenkinsPrincipal: "juser",
		Source:           "lab_header",
		Verified:         true,
	}
	claims, err := gateway.InboundClaimsFromRequestIdentity(in, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if !claims.Verified || claims.Subject != "lab-sub" || claims.ProfileID != "corp" {
		t.Fatalf("%+v", claims)
	}

	// Missing subject.
	_, err = gateway.InboundClaimsFromRequestIdentity(gateway.HTTPInbound{Verified: true}, "corp")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("missing subject: %v", err)
	}
	// Missing profile.
	_, err = gateway.InboundClaimsFromRequestIdentity(in, "")
	if err == nil {
		t.Fatal("empty profile")
	}
	// Unverified.
	bad := in
	bad.Verified = false
	_, err = gateway.InboundClaimsFromRequestIdentity(bad, "corp")
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("unverified: %v", err)
	}
}

// Regression: tool args still cannot set identity (GWY-002).
func TestRejectIdentityToolArgs_StillBlocks(t *testing.T) {
	t.Parallel()
	err := gateway.RejectIdentityToolArgs(map[string]any{
		"subject": "attacker",
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("want policy_denial got %v", err)
	}
}
