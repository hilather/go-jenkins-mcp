package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Regression: multi-user Binding prefers PolicySubject JenkinsUserID (HTTP claim /
// lab JenkinsPrincipal) over process principal when subject is Valid.
func TestMutationBindingFromGatewayCtx_PrefersPolicySubjectPrincipal(t *testing.T) {
	t.Parallel()
	const processPrincipal = "process-jenkins"
	s := policy.Subject{
		ProfileID:       "corp",
		JenkinsUserID:   "j-alice",
		ExternalSubject: "entra-alice",
		Tenant:          "tid-1",
		Verified:        true,
	}
	if !s.Valid() {
		t.Fatal("fixture subject must be Valid")
	}
	ctx := gateway.ContextWithPolicySubject(context.Background(), s)
	b, ok := mutationBindingFromGatewayCtx(ctx, processPrincipal)
	if !ok {
		t.Fatal("expected binding from Valid PolicySubject")
	}
	if b.PrincipalID != "j-alice" {
		t.Fatalf("PrincipalID want j-alice from PolicySubject, got %q (must not be process %q)",
			b.PrincipalID, processPrincipal)
	}
	if b.ProfileID != "corp" || b.ExternalSubject != "entra-alice" || b.Tenant != "tid-1" {
		t.Fatalf("binding labels: %+v", b)
	}
}

// Caller-only path (PolicySubject missing / !Valid) keeps process PrincipalID
// and ExternalSubject isolation from Caller (prior HOST-006 behavior).
func TestMutationBindingFromGatewayCtx_CallerFallbackProcessPrincipal(t *testing.T) {
	t.Parallel()
	const processPrincipal = "process-jenkins"
	c := gateway.Caller{
		Subject:   "entra-bob",
		Tenant:    "tid-1",
		ProfileID: contracts.ProfileID("corp"),
	}
	ctx := gateway.ContextWithCaller(context.Background(), c)
	b, ok := mutationBindingFromGatewayCtx(ctx, processPrincipal)
	if !ok {
		t.Fatal("expected binding from Valid Caller")
	}
	if b.PrincipalID != processPrincipal {
		t.Fatalf("PrincipalID want process fallback %q, got %q", processPrincipal, b.PrincipalID)
	}
	if b.ExternalSubject != "entra-bob" || b.ProfileID != "corp" || b.Tenant != "tid-1" {
		t.Fatalf("binding: %+v", b)
	}

	// PolicySubject present but !Valid (no Jenkins principal) → still Caller + process.
	sEmpty := policy.Subject{
		ProfileID:       "corp",
		JenkinsUserID:   "", // !Valid
		ExternalSubject: "entra-bob",
		Tenant:          "tid-1",
	}
	if sEmpty.Valid() {
		t.Fatal("empty jenkins must not be Valid")
	}
	ctx2 := gateway.ContextWithCallerAndPolicySubject(context.Background(), c, sEmpty)
	b2, ok := mutationBindingFromGatewayCtx(ctx2, processPrincipal)
	if !ok {
		t.Fatal("expected Caller fallback when subject !Valid")
	}
	if b2.PrincipalID != processPrincipal {
		t.Fatalf("!Valid subject must not elevate PrincipalID: got %q", b2.PrincipalID)
	}
	if b2.ExternalSubject != "entra-bob" {
		t.Fatalf("ExternalSubject: %q", b2.ExternalSubject)
	}
}

// Empty context → ok=false (stdio / missing multi-user identity).
func TestMutationBindingFromGatewayCtx_Empty(t *testing.T) {
	t.Parallel()
	if _, ok := mutationBindingFromGatewayCtx(context.Background(), "proc"); ok {
		t.Fatal("background ctx must not yield binding")
	}
	if _, ok := mutationBindingFromGatewayCtx(nil, "proc"); ok {
		t.Fatal("nil ctx must not yield binding")
	}
}

// Alice/Bob: different PrincipalID from PolicySubject → confirm token binding_mismatch
// even when ExternalSubject isolation is also present; audit uses effective Bob.
func TestMutationBindingFromGatewayCtx_AliceBobPrincipalMismatch_Audit(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	const processPrincipal = "process-shared"
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     processPrincipal,
		ConfirmCooldown: -1,
		TTL:             2 * time.Minute,
		Now:             func() time.Time { return now },
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			return mutationBindingFromGatewayCtx(ctx, processPrincipal)
		},
	})
	aliceSubj := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "j-alice",
		ExternalSubject: "entra-alice", Tenant: "tid-1", Verified: true,
	}
	bobSubj := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "j-bob",
		ExternalSubject: "entra-bob", Tenant: "tid-1", Verified: true,
	}
	aliceCaller := gateway.Caller{Subject: "entra-alice", Tenant: "tid-1", ProfileID: "corp"}
	bobCaller := gateway.Caller{Subject: "entra-bob", Tenant: "tid-1", ProfileID: "corp"}
	aliceCtx := gateway.ContextWithCallerAndPolicySubject(context.Background(), aliceCaller, aliceSubj)
	bobCtx := gateway.ContextWithCallerAndPolicySubject(context.Background(), bobCaller, bobSubj)

	// Sanity: bindings differ on PrincipalID (not only ExternalSubject).
	ba, _ := mutationBindingFromGatewayCtx(aliceCtx, processPrincipal)
	bb, _ := mutationBindingFromGatewayCtx(bobCtx, processPrincipal)
	if ba.PrincipalID == bb.PrincipalID || ba.PrincipalID != "j-alice" || bb.PrincipalID != "j-bob" {
		t.Fatalf("want distinct per-request principals; alice=%+v bob=%+v", ba, bb)
	}
	if ba.PrincipalID == processPrincipal || bb.PrincipalID == processPrincipal {
		t.Fatal("must not use process principal when PolicySubject Valid")
	}

	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Confirm(bobCtx, prev.ConfirmationToken, intent)
	if err == nil {
		t.Fatal("Alice preview must binding_mismatch under Bob (PrincipalID + ExternalSubject)")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	var sawMismatch bool
	for _, e := range mem.Events() {
		if e.ReasonCode == mutation.ReasonBindingMismatch {
			sawMismatch = true
			if e.PrincipalID != "j-bob" {
				t.Fatalf("deny audit PrincipalID want j-bob (effective), got %q", e.PrincipalID)
			}
			if e.ProfileID != "corp" {
				t.Fatalf("audit profile: %q", e.ProfileID)
			}
		}
		// Canary: confirmation token / secret-like never in audit fields.
		blob := e.Type + e.ProfileID + e.PrincipalID + e.Tool + e.Action +
			e.Decision + e.ReasonCode + e.TargetHash + e.RequestID
		if strings.Contains(blob, prev.ConfirmationToken) {
			t.Fatalf("confirmation token in audit: %+v", e)
		}
		if strings.Contains(strings.ToLower(blob), "secret") {
			t.Fatalf("secret-like audit field: %+v", e)
		}
	}
	if !sawMismatch {
		t.Fatalf("want binding_mismatch; events=%+v", mem.Events())
	}

	// Alice still confirms; audit PrincipalID is j-alice (not process-shared).
	mem.Reset()
	if _, err := m.Confirm(aliceCtx, prev.ConfirmationToken, intent); err != nil {
		t.Fatalf("alice confirm: %v", err)
	}
	var sawConfirm bool
	for _, e := range mem.Events() {
		if e.Type == mutation.TypeConfirm {
			sawConfirm = true
			if e.PrincipalID != "j-alice" {
				t.Fatalf("confirm audit PrincipalID want j-alice, got %q", e.PrincipalID)
			}
		}
	}
	if !sawConfirm {
		t.Fatal("expected confirm audit")
	}
}

// Same ExternalSubject+Tenant, different Jenkins PrincipalID alone must mismatch
// (closes residual where PrincipalID was always process and only ExternalSubject isolated).
func TestMutationBindingFromGatewayCtx_PrincipalOnlyMismatch(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	const processPrincipal = "process-shared"
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     processPrincipal,
		ConfirmCooldown: -1,
		TTL:             time.Minute,
		Now:             func() time.Time { return now },
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			return mutationBindingFromGatewayCtx(ctx, processPrincipal)
		},
	})
	// Shared IdP sub (edge) but different Jenkins principals from lab/claim.
	sharedExt := "shared-entra-sub"
	alice := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "j-alice",
		ExternalSubject: sharedExt, Tenant: "tid-1", Verified: true,
	}
	bob := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "j-bob",
		ExternalSubject: sharedExt, Tenant: "tid-1", Verified: true,
	}
	aliceCtx := gateway.ContextWithPolicySubject(context.Background(), alice)
	bobCtx := gateway.ContextWithPolicySubject(context.Background(), bob)
	ba, _ := mutationBindingFromGatewayCtx(aliceCtx, processPrincipal)
	bb, _ := mutationBindingFromGatewayCtx(bobCtx, processPrincipal)
	if ba.ExternalSubject != bb.ExternalSubject || ba.Tenant != bb.Tenant {
		t.Fatal("fixture requires same ExternalSubject+Tenant")
	}
	if ba.PrincipalID == bb.PrincipalID {
		t.Fatal("fixture requires different PrincipalID")
	}

	intent := mutation.Intent{Action: mutation.ActionStopBuild, JobName: "demo", BuildNumber: 1}
	prev, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(bobCtx, prev.ConfirmationToken, intent); err == nil {
		t.Fatal("different PrincipalID alone must binding_mismatch")
	}
	var saw bool
	for _, e := range mem.Events() {
		if e.ReasonCode == mutation.ReasonBindingMismatch {
			saw = true
			if e.PrincipalID != "j-bob" {
				t.Fatalf("effective principal on deny audit: %q", e.PrincipalID)
			}
		}
	}
	if !saw {
		t.Fatal("want binding_mismatch")
	}
}

// Mode A / lab: PolicySubjectFromHTTPInbound JenkinsPrincipal matches vault username path.
func TestMutationBinding_LabJenkinsPrincipalMatchesVaultStyleUsername(t *testing.T) {
	t.Parallel()
	// Simulates AfterIdentity: lab header JenkinsPrincipal = vault Mode A username.
	in := gateway.HTTPInbound{
		ExternalSubject:  "entra-alice",
		Tenant:           "tid-1",
		JenkinsPrincipal: "alice-vault-user",
		Source:           "lab_header",
		Verified:         true,
	}
	process := policy.Subject{
		ProfileID:     "corp",
		JenkinsUserID: "process-whoami",
		Verified:      true,
	}
	ps := gateway.PolicySubjectFromHTTPInbound(in, "corp", process)
	if ps.JenkinsUserID != "alice-vault-user" {
		t.Fatalf("JenkinsUserID from lab claim: %q", ps.JenkinsUserID)
	}
	if !ps.Valid() {
		t.Fatal("lab principal + profile must be Valid for Binding")
	}
	// Must not elevate process whoAmI into Binding PrincipalID.
	if ps.JenkinsUserID == process.JenkinsUserID {
		t.Fatal("must not use process jenkins when inbound principal present")
	}
	ctx := gateway.ContextWithPolicySubject(context.Background(), ps)
	b, ok := mutationBindingFromGatewayCtx(ctx, process.JenkinsUserID)
	if !ok || b.PrincipalID != "alice-vault-user" {
		t.Fatalf("binding principal for Mode A lab path: ok=%v %+v", ok, b)
	}
	if b.ExternalSubject != "entra-alice" {
		t.Fatalf("external: %q", b.ExternalSubject)
	}
}

// Regression: Obtain Mode A vault → PrincipalCache → Binding PrincipalID = alice-j
// even without lab/JWT JenkinsPrincipal (policy.Subject !Valid). Bob isolated.
func TestMutationBinding_ObtainPrincipalCache_ModeAWithoutLabClaim(t *testing.T) {
	t.Parallel()
	const processPrincipal = "process-whoami"
	const canaryTok = "MUT_BIND_PCACHE_canary_token_never_log_xyz"
	cache := gateway.NewPrincipalCache()
	v := gateway.NewMemoryAPITokenVault()
	alice := gateway.Caller{Subject: "alice-sub", Tenant: "tid-1", ProfileID: "corp"}
	bob := gateway.Caller{Subject: "bob-sub", Tenant: "tid-1", ProfileID: "corp"}
	if err := v.Put(context.Background(), gateway.SubjectKey(alice), "alice-j", canaryTok+"-a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(context.Background(), gateway.SubjectKey(bob), "bob-j", canaryTok+"-b"); err != nil {
		t.Fatal(err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate multi-user AuthProviderCtx Obtain for Alice then Bob.
	client := &jenkins.Client{}
	attachGatewayObtainAuthProviderDynamicWithCache(client, p, alice, false, cache)
	if _, _, _, err := client.AuthProviderCtx(gateway.ContextWithCaller(context.Background(), alice)); err != nil {
		t.Fatalf("alice Obtain: %v", err)
	}
	if _, _, _, err := client.AuthProviderCtx(gateway.ContextWithCaller(context.Background(), bob)); err != nil {
		t.Fatalf("bob Obtain: %v", err)
	}
	// Cache has vault usernames; String secret-free.
	if got, ok := cache.Get(gateway.SubjectKey(alice)); !ok || got != "alice-j" {
		t.Fatalf("cache alice: ok=%v got=%q", ok, got)
	}
	if got, ok := cache.Get(gateway.SubjectKey(bob)); !ok || got != "bob-j" {
		t.Fatalf("cache bob: ok=%v got=%q", ok, got)
	}
	if strings.Contains(cache.String(), canaryTok) {
		t.Fatalf("cache.String leaked canary: %s", cache.String())
	}
	if strings.Contains(cache.String(), canaryTok+"-a") || strings.Contains(cache.String(), canaryTok+"-b") {
		t.Fatal("cache.String leaked tokens")
	}

	// Binding without Valid PolicySubject (no lab JenkinsPrincipal): use cache.
	aliceCtx := gateway.ContextWithCaller(context.Background(), alice)
	bobCtx := gateway.ContextWithCaller(context.Background(), bob)
	ba, ok := mutationBindingFromGatewayCtxWithCache(aliceCtx, processPrincipal, cache)
	if !ok || ba.PrincipalID != "alice-j" {
		t.Fatalf("alice Binding PrincipalID want alice-j (not process %q): ok=%v %+v", processPrincipal, ok, ba)
	}
	bb, ok := mutationBindingFromGatewayCtxWithCache(bobCtx, processPrincipal, cache)
	if !ok || bb.PrincipalID != "bob-j" {
		t.Fatalf("bob Binding PrincipalID want bob-j: ok=%v %+v", ok, bb)
	}
	if ba.PrincipalID == bb.PrincipalID {
		t.Fatal("alice/bob PrincipalID must differ")
	}
	if ba.PrincipalID == processPrincipal || bb.PrincipalID == processPrincipal {
		t.Fatal("must not fall back to process when cache hit")
	}
	if ba.ExternalSubject != "alice-sub" || bb.ExternalSubject != "bob-sub" {
		t.Fatalf("ExternalSubject isolation: alice=%+v bob=%+v", ba, bb)
	}

	// Delete on Invalidate companion: remove alice → Binding falls back to process.
	cache.Delete(gateway.SubjectKey(alice))
	ba2, ok := mutationBindingFromGatewayCtxWithCache(aliceCtx, processPrincipal, cache)
	if !ok || ba2.PrincipalID != processPrincipal {
		t.Fatalf("after Delete alice want process fallback: ok=%v %+v", ok, ba2)
	}
	// Bob still cached.
	bb2, _ := mutationBindingFromGatewayCtxWithCache(bobCtx, processPrincipal, cache)
	if bb2.PrincipalID != "bob-j" {
		t.Fatalf("bob must remain after alice Delete: %+v", bb2)
	}

	// Valid PolicySubject still wins over cache (HTTP claim preferred).
	ps := policy.Subject{
		ProfileID: "corp", JenkinsUserID: "claim-alice",
		ExternalSubject: "alice-sub", Tenant: "tid-1", Verified: true,
	}
	cache.Set(gateway.SubjectKey(alice), "alice-j")
	ctxClaim := gateway.ContextWithCallerAndPolicySubject(context.Background(), alice, ps)
	bc, ok := mutationBindingFromGatewayCtxWithCache(ctxClaim, processPrincipal, cache)
	if !ok || bc.PrincipalID != "claim-alice" {
		t.Fatalf("Valid PolicySubject must win over cache: ok=%v %+v", ok, bc)
	}
}

// Caller path with empty cache keeps process principal (prior residual path).
func TestMutationBinding_PrincipalCacheMiss_ProcessFallback(t *testing.T) {
	t.Parallel()
	const processPrincipal = "process-jenkins"
	cache := gateway.NewPrincipalCache()
	c := gateway.Caller{Subject: "entra-bob", Tenant: "tid-1", ProfileID: "corp"}
	ctx := gateway.ContextWithCaller(context.Background(), c)
	b, ok := mutationBindingFromGatewayCtxWithCache(ctx, processPrincipal, cache)
	if !ok || b.PrincipalID != processPrincipal {
		t.Fatalf("cache miss: ok=%v %+v", ok, b)
	}
	// nil cache also process fallback.
	b2, ok := mutationBindingFromGatewayCtxWithCache(ctx, processPrincipal, nil)
	if !ok || b2.PrincipalID != processPrincipal {
		t.Fatalf("nil cache: ok=%v %+v", ok, b2)
	}
}
