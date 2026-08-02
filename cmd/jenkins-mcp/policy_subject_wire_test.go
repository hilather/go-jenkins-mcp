package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

const policySubjectWireCanary = "POL_SUBJ_WIRE_canary_token_never_log_xyz"

// Regression: after simulated Obtain cache Set, SubjectFromContext adapter
// returns JenkinsUserID from PrincipalCache (vault username wins).
func TestPolicySubjectFromGatewayCtx_PrefersPrincipalCacheAfterObtain(t *testing.T) {
	t.Parallel()
	cache := gateway.NewPrincipalCache()
	alice := gateway.Caller{Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp"}
	bob := gateway.Caller{Subject: "bob-sub", Tenant: "tid-1", ProfileID: "corp"}

	// Simulate multi-user AuthProviderCtx Obtain → PrincipalCache Set.
	v := gateway.NewMemoryAPITokenVault()
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", policySubjectWireCanary+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", policySubjectWireCanary+"-b"); err != nil {
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
	if _, _, _, err := client.AuthProviderCtx(gateway.ContextWithCaller(context.Background(), bob)); err != nil {
		t.Fatalf("bob Obtain: %v", err)
	}

	// Caller-only (no HTTP JenkinsPrincipal): adapter uses cache.
	aliceSubj, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCaller(context.Background(), alice), cache)
	if !ok || aliceSubj.JenkinsUserID != "alice-j" {
		t.Fatalf("alice subject from cache: ok=%v %+v", ok, aliceSubj)
	}
	if !aliceSubj.Verified || !aliceSubj.Valid() {
		t.Fatalf("alice must be Verified+Valid after Obtain cache: %+v", aliceSubj)
	}
	if aliceSubj.ExternalSubject != "alice-sub" || string(aliceSubj.ProfileID) != "corp" {
		t.Fatalf("alice labels: %+v", aliceSubj)
	}

	bobSubj, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCaller(context.Background(), bob), cache)
	if !ok || bobSubj.JenkinsUserID != "bob-j" {
		t.Fatalf("bob subject from cache: ok=%v %+v", ok, bobSubj)
	}
	if aliceSubj.JenkinsUserID == bobSubj.JenkinsUserID {
		t.Fatal("alice/bob JenkinsUserID must differ")
	}

	// Cache preferred over HTTP claim (vault username wins after Obtain).
	claimAlice := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "claim-alice",
		ExternalSubject: "alice-sub", Tenant: "tid-1", Verified: true,
		Groups: []string{"ops"},
	}
	ctxClaim := gateway.ContextWithCallerAndPolicySubject(context.Background(), alice, claimAlice)
	got, ok := policySubjectFromGatewayCtxWithCache(ctxClaim, cache)
	if !ok || got.JenkinsUserID != "alice-j" {
		t.Fatalf("cache must win over HTTP claim: ok=%v %+v", ok, got)
	}
	if !got.Verified {
		t.Fatal("Verified must stay true after cache rewrite")
	}
	// Groups preserved from HTTP PolicySubject (never elevated / invented).
	if len(got.Groups) != 1 || got.Groups[0] != "ops" {
		t.Fatalf("groups must preserve HTTP subject, got %v", got.Groups)
	}
}

// Cache miss / empty: prefer HTTP/lab PolicySubject.JenkinsUserID when Valid.
func TestPolicySubjectFromGatewayCtx_HTTPClaimWhenCacheEmpty(t *testing.T) {
	t.Parallel()
	cache := gateway.NewPrincipalCache()
	alice := gateway.Caller{Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp"}
	ps := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "claim-alice",
		ExternalSubject: "alice-sub", Tenant: "tid-1", Verified: true,
	}
	ctx := gateway.ContextWithCallerAndPolicySubject(context.Background(), alice, ps)
	got, ok := policySubjectFromGatewayCtxWithCache(ctx, cache)
	if !ok || got.JenkinsUserID != "claim-alice" {
		t.Fatalf("HTTP claim when cache empty: ok=%v %+v", ok, got)
	}
	if !got.Verified {
		t.Fatal("Verified from HTTP claim")
	}

	// PolicySubject only (no Caller): still returns HTTP subject.
	got2, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithPolicySubject(context.Background(), ps), cache)
	if !ok || got2.JenkinsUserID != "claim-alice" {
		t.Fatalf("PolicySubject only: ok=%v %+v", ok, got2)
	}

	// Caller only, empty cache: ok=true but !Valid (fail closed, no process elevate).
	got3, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCaller(context.Background(), alice), cache)
	if !ok {
		t.Fatal("Caller-only must return ok=true for fail-closed Evaluate")
	}
	if got3.Valid() || got3.JenkinsUserID != "" {
		t.Fatalf("empty cache + no claim must not invent principal: %+v", got3)
	}

	// Neither → ok=false.
	if _, ok := policySubjectFromGatewayCtxWithCache(context.Background(), cache); ok {
		t.Fatal("empty ctx must be ok=false")
	}
	if _, ok := policySubjectFromGatewayCtxWithCache(nil, cache); ok {
		t.Fatal("nil ctx must be ok=false")
	}
}

// Alice deny_tools / Bob allow using subjects whose JenkinsUserID comes from cache.
// Groups never elevate deny-only.
func TestPolicySubjectFromGatewayCtx_AliceDenyBobAllow_CacheJenkinsUserID(t *testing.T) {
	t.Parallel()
	cache := gateway.NewPrincipalCache()
	alice := gateway.Caller{Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp"}
	bob := gateway.Caller{Subject: "bob-sub", Tenant: "tid-1", ProfileID: "corp"}
	cache.Set(gateway.SubjectKey(alice), "alice-j")
	cache.Set(gateway.SubjectKey(bob), "bob-j")

	// Alice has inbound groups — still cannot elevate deny_tools.
	alicePS := policy.Subject{
		ProfileID: "corp", ExternalSubject: "alice-sub", Tenant: "tid-1",
		Groups: []string{"admin-claim", "ops"},
	}
	aliceSubj, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCallerAndPolicySubject(context.Background(), alice, alicePS), cache)
	if !ok || aliceSubj.JenkinsUserID != "alice-j" || !aliceSubj.Valid() {
		t.Fatalf("alice: ok=%v %+v", ok, aliceSubj)
	}
	bobSubj, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCaller(context.Background(), bob), cache)
	if !ok || bobSubj.JenkinsUserID != "bob-j" || !bobSubj.Valid() {
		t.Fatalf("bob: ok=%v %+v", ok, bobSubj)
	}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
		},
	})
	// Alice denied for deny_tools (groups must not elevate).
	dAlice := ev.Evaluate(aliceSubj, policy.Action{
		ToolName: "jenkins_get_build_logs", Class: policy.EffectRead,
	}, policy.Target{})
	if !dAlice.Denied() {
		t.Fatalf("alice deny_tools must deny (groups never elevate): %+v", dAlice)
	}
	// Bob allowed for a tool not in deny_tools (subject from cache is Valid).
	dBob := ev.Evaluate(bobSubj, policy.Action{
		ToolName: "jenkins_get_jobs", Class: policy.EffectRead,
	}, policy.Target{})
	if !dBob.Allowed() {
		t.Fatalf("bob allow non-denied tool: %+v", dBob)
	}
	// Bob also denied for the same deny_tools entry (global deny-only).
	dBobDenied := ev.Evaluate(bobSubj, policy.Action{
		ToolName: "jenkins_get_build_logs", Class: policy.EffectRead,
	}, policy.Target{})
	if !dBobDenied.Denied() {
		t.Fatalf("deny_tools applies to bob subject too: %+v", dBobDenied)
	}
}

// StatusMap / String must never include tokens or canary secrets after Obtain.
func TestPolicySubjectFromGatewayCtx_StatusMapSecretFree(t *testing.T) {
	t.Parallel()
	cache := gateway.NewPrincipalCache()
	alice := gateway.Caller{Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp"}
	v := gateway.NewMemoryAPITokenVault()
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", policySubjectWireCanary); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	client := &jenkins.Client{}
	attachGatewayObtainAuthProviderDynamicWithCache(client, p, alice, false, cache)
	if _, secret, _, err := client.AuthProviderCtx(gateway.ContextWithCaller(context.Background(), alice)); err != nil {
		t.Fatal(err)
	} else if secret != policySubjectWireCanary {
		t.Fatal("fixture secret mismatch")
	}

	s, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCaller(context.Background(), alice), cache)
	if !ok {
		t.Fatal("ok")
	}
	sm := s.StatusMap()
	dump := fmt.Sprintf("%v %v %s %s", s, sm, cache.String(), fmt.Sprint(cache.StatusMap()))
	if strings.Contains(dump, policySubjectWireCanary) {
		t.Fatalf("canary leaked into subject/StatusMap/String: %s", dump)
	}
	// StatusMap is non-secret identity summary only.
	if sm["jenkins_user"] != "alice-j" {
		t.Fatalf("status jenkins_user: %v", sm["jenkins_user"])
	}
	if _, hasTok := sm["token"]; hasTok {
		t.Fatal("StatusMap must not have token field")
	}
	if _, hasSecret := sm["secret"]; hasSecret {
		t.Fatal("StatusMap must not have secret field")
	}
	// PrincipalCache StatusMap is entry count only.
	csm := cache.StatusMap()
	if csm["entries"] != 1 {
		t.Fatalf("cache StatusMap entries: %v", csm["entries"])
	}
	for k, v := range csm {
		if strings.Contains(fmt.Sprint(v), policySubjectWireCanary) ||
			strings.Contains(k, "token") {
			t.Fatalf("cache StatusMap secret-ish: %s=%v", k, v)
		}
	}
}

// Production helper uses ProcessPrincipalCache (smoke).
func TestPolicySubjectFromGatewayCtx_ProcessCacheSmoke(t *testing.T) {
	// Not parallel: mutates process PrincipalCache.
	pc := gateway.ProcessPrincipalCache()
	c := gateway.Caller{Subject: "smoke-sub-policy-wire", Tenant: "tid-smoke", ProfileID: "corp"}
	key := gateway.SubjectKey(c)
	pc.Delete(key)
	t.Cleanup(func() { pc.Delete(key) })

	pc.Set(key, "smoke-j")
	got, ok := policySubjectFromGatewayCtx(gateway.ContextWithCaller(context.Background(), c))
	if !ok || got.JenkinsUserID != "smoke-j" {
		t.Fatalf("process cache: ok=%v %+v", ok, got)
	}
}

// Anonymous principal in cache must not elevate Verified / Valid.
func TestPolicySubjectFromGatewayCtx_RejectsAnonymousCachePrincipal(t *testing.T) {
	t.Parallel()
	cache := gateway.NewPrincipalCache()
	c := gateway.Caller{Subject: "anon-sub", Tenant: "tid-1", ProfileID: "corp"}
	// PrincipalCache.Set allows non-empty strings including "anonymous".
	cache.Set(gateway.SubjectKey(c), policy.AnonymousJenkinsUser)
	got, ok := policySubjectFromGatewayCtxWithCache(
		gateway.ContextWithCaller(context.Background(), c), cache)
	if !ok {
		t.Fatal("ok")
	}
	if got.JenkinsUserID != "" || got.Verified || got.Valid() {
		t.Fatalf("anonymous cache principal must not elevate: %+v", got)
	}
}
