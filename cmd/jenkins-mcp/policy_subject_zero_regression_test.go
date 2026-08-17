package main

import (
	"context"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Regression (review follow-up): the group-overage fail-closed fix returns an
// empty subject from PolicySubjectFromHTTPInbound, but the production
// SubjectFromContext adapter (policySubjectFromGatewayCtx) rebuilt a VALID
// subject from the Caller + PrincipalCache with Groups=nil — resurrecting the
// over-overage user with every group-targeted deny bypassed. A stored zero
// subject must now pass through untouched so Evaluate denies it.
func TestPolicySubjectFromGatewayCtx_ZeroSubjectStaysFailClosed(t *testing.T) {
	t.Parallel()
	cache := gateway.NewPrincipalCache()
	alice := gateway.Caller{Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp"}

	// Simulate Obtain having recorded a principal for alice (the resurrection
	// path: cache hit would otherwise set JenkinsUserID + Verified).
	v := gateway.NewMemoryAPITokenVault()
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", policySubjectWireCanary+"-z"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	client := &jenkins.Client{}
	attachGatewayObtainAuthProviderDynamicWithCache(client, p, alice, false, cache)
	if _, _, _, err := client.AuthProviderCtx(gateway.ContextWithCaller(context.Background(), alice)); err != nil {
		t.Fatalf("alice Obtain: %v", err)
	}

	// Stored ZERO policy subject (the group-overage fail-closed signal) + a
	// valid caller with a cached principal.
	ctx := gateway.ContextWithCallerAndPolicySubject(context.Background(), alice, policy.Subject{})
	s, ok := policySubjectFromGatewayCtxWithCache(ctx, cache)
	if !ok {
		t.Fatal("stored subject must stay present (ok=true) so Evaluate sees it")
	}
	// Inline zero check (do not depend on the fix's helper so this test
	// compiles standalone against the pre-fix tree).
	isZero := s.ProfileID == "" && s.JenkinsUserID == "" && s.ExternalSubject == "" &&
		s.Tenant == "" && s.WorkloadID == "" && len(s.Groups) == 0 && !s.Verified
	if !isZero {
		t.Fatalf("zero subject must not be resurrected from Caller/cache: %+v", s)
	}
	// And Evaluate denies it.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	if d := ev.Evaluate(s, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}); !d.Denied() {
		t.Fatalf("zero subject must be denied: %+v", d)
	}
}
