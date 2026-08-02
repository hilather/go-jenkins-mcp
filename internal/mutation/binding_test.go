package mutation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// HOST-006 / MUT-001: Alice preview token must not confirm under Bob's binding
// on a shared Manager (BindingFromContext multi-user).
func TestConfirmTokenRejectedAcrossSubjects_AliceBob(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))

	type bindKey struct{}
	alice := mutation.Binding{
		ProfileID: "corp", PrincipalID: "j-alice",
		ExternalSubject: "entra-alice", Tenant: "tid-1",
	}
	bob := mutation.Binding{
		ProfileID: "corp", PrincipalID: "j-bob",
		ExternalSubject: "entra-bob", Tenant: "tid-1",
	}
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "process-fallback",
		ConfirmCooldown: -1,
		TTL:             2 * time.Minute,
		Now:             now,
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			if b, ok := ctx.Value(bindKey{}).(mutation.Binding); ok {
				return b, true
			}
			return mutation.Binding{}, false
		},
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}

	aliceCtx := context.WithValue(context.Background(), bindKey{}, alice)
	bobCtx := context.WithValue(context.Background(), bindKey{}, bob)

	prev, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	// Bob cannot confirm Alice's token.
	_, err = m.Confirm(bobCtx, prev.ConfirmationToken, intent)
	if err == nil {
		t.Fatal("Alice preview token must be rejected for Bob confirm")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "bound") &&
		!strings.Contains(strings.ToLower(err.Error()), "subject") {
		t.Fatalf("msg should mention binding/subject: %v", err)
	}
	assertDenyReason(t, mem, mutation.ReasonBindingMismatch)

	// Binding mismatch deny must attribute Bob's ExternalSubject + SubjectKeyHash.
	var sawMismatch bool
	wantBobHash := audit.HashOpaque("tid-1|entra-bob|corp")
	for _, e := range mem.Events() {
		if e.ReasonCode != mutation.ReasonBindingMismatch {
			continue
		}
		sawMismatch = true
		if e.PrincipalID != "j-bob" {
			t.Fatalf("mismatch deny PrincipalID want j-bob, got %q", e.PrincipalID)
		}
		if e.ExternalSubject != "entra-bob" {
			t.Fatalf("mismatch deny ExternalSubject want entra-bob, got %q", e.ExternalSubject)
		}
		if e.SubjectKeyHash != wantBobHash {
			t.Fatalf("mismatch deny SubjectKeyHash want %q, got %q", wantBobHash, e.SubjectKeyHash)
		}
		if strings.Contains(e.SubjectKeyHash, "|") {
			t.Fatalf("SubjectKeyHash must be opaque (no raw key): %q", e.SubjectKeyHash)
		}
	}
	if !sawMismatch {
		t.Fatal("expected binding_mismatch deny audit with ExternalSubject")
	}

	// Alice can still confirm her own token after Bob's failed attempt.
	mem.Reset()
	bound, err := m.Confirm(aliceCtx, prev.ConfirmationToken, intent)
	if err != nil {
		t.Fatalf("Alice confirm after Bob deny: %v", err)
	}
	if bound.JobName != "demo" {
		t.Fatalf("bound: %+v", bound)
	}
	// Audit attribution uses effective Alice subject (not process fallback).
	wantAliceHash := audit.HashOpaque("tid-1|entra-alice|corp")
	var sawConfirm bool
	for _, e := range mem.Events() {
		if e.Type == mutation.TypeConfirm {
			sawConfirm = true
			if e.ProfileID != "corp" || e.PrincipalID != "j-alice" {
				t.Fatalf("confirm audit want alice attribution, got profile=%q principal=%q",
					e.ProfileID, e.PrincipalID)
			}
			if e.ExternalSubject != "entra-alice" {
				t.Fatalf("confirm audit ExternalSubject want entra-alice, got %q", e.ExternalSubject)
			}
			if e.SubjectKeyHash != wantAliceHash {
				t.Fatalf("confirm audit SubjectKeyHash want %q, got %q", wantAliceHash, e.SubjectKeyHash)
			}
		}
		// Canary: secrets must never appear in audit string fields.
		for _, s := range []string{e.Type, e.Tool, e.ReasonCode, e.ProfileID, e.PrincipalID, e.ExternalSubject, e.SubjectKeyHash, e.Action, e.Decision, e.TargetHash, e.RequestID} {
			if strings.Contains(s, "secret") || strings.Contains(s, "token-") || strings.Contains(s, "Bearer ") {
				t.Fatalf("secret-like value in audit field: %q event=%+v", s, e)
			}
		}
		// Canary: confirmation token and raw subject key shape must not appear in hash field.
		if strings.Contains(e.SubjectKeyHash, prev.ConfirmationToken) || strings.Contains(e.SubjectKeyHash, "|") {
			t.Fatalf("SubjectKeyHash must stay opaque: %q event=%+v", e.SubjectKeyHash, e)
		}
	}
	if !sawConfirm {
		t.Fatal("expected confirm audit event")
	}
}

// Same ExternalSubject+Tenant, different PrincipalID alone → binding_mismatch
// (per-request Jenkins principal on Binding; not only ExternalSubject isolation).
func TestConfirmTokenRejectedAcrossPrincipalID_Only(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	type bindKey struct{}
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "process-fallback",
		ConfirmCooldown: -1,
		TTL:             time.Minute,
		Now:             now,
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			if b, ok := ctx.Value(bindKey{}).(mutation.Binding); ok {
				return b, true
			}
			return mutation.Binding{}, false
		},
	})
	sharedExt := "shared-entra"
	alice := mutation.Binding{
		ProfileID: "corp", PrincipalID: "j-alice",
		ExternalSubject: sharedExt, Tenant: "tid-1",
	}
	bob := mutation.Binding{
		ProfileID: "corp", PrincipalID: "j-bob",
		ExternalSubject: sharedExt, Tenant: "tid-1",
	}
	aliceCtx := context.WithValue(context.Background(), bindKey{}, alice)
	bobCtx := context.WithValue(context.Background(), bindKey{}, bob)
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(bobCtx, prev.ConfirmationToken, intent); err == nil {
		t.Fatal("different PrincipalID alone must binding_mismatch")
	}
	assertDenyReason(t, mem, mutation.ReasonBindingMismatch)
	// Audit deny attributes Bob's effective PrincipalID.
	for _, e := range mem.Events() {
		if e.ReasonCode == mutation.ReasonBindingMismatch && e.PrincipalID != "j-bob" {
			t.Fatalf("deny audit PrincipalID want j-bob, got %q", e.PrincipalID)
		}
	}
}

// Config ExternalSubject/Tenant differentiate subjects without BindingFromContext
// when Managers are process-pinned per user (or Config defaults differ).
func TestConfirmTokenRejectedAcrossExternalSubject_ConfigOnly(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	// Shared store simulation: one Manager with Config ExternalSubject alice,
	// then Confirm under a Manager that cannot see the token is not the case —
	// instead BindingFromContext is omitted and we issue under alice external,
	// then rebind via a second Manager cannot share tokens. Test the equal path
	// by minting with BindingFromContext nil and Config external alice, then
	// Confirm on same manager with Config external still alice (happy), and a
	// second Manager with bob ExternalSubject that has no token (unknown).
	// Stronger: BindingFromContext that only changes ExternalSubject.
	type extKey struct{}
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "shared-jenkins", // same Jenkins label residual
		ConfirmCooldown: -1,
		TTL:             time.Minute,
		Now:             now,
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			ext, _ := ctx.Value(extKey{}).(string)
			if ext == "" {
				return mutation.Binding{}, false
			}
			return mutation.Binding{
				ProfileID: "corp", PrincipalID: "shared-jenkins",
				ExternalSubject: ext, Tenant: "tid-a",
			}, true
		},
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	aliceCtx := context.WithValue(context.Background(), extKey{}, "alice-sub")
	bobCtx := context.WithValue(context.Background(), extKey{}, "bob-sub")
	prev, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(bobCtx, prev.ConfirmationToken, intent); err == nil {
		t.Fatal("same principal different ExternalSubject must binding_mismatch")
	}
	assertDenyReason(t, mem, mutation.ReasonBindingMismatch)
}

// Tenant mismatch is also a binding mismatch (multi-tenant isolation).
func TestConfirmTokenRejectedAcrossTenant(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	type tenantKey struct{}
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "alice",
		ConfirmCooldown: -1,
		Now:             now,
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			ten, _ := ctx.Value(tenantKey{}).(string)
			if ten == "" {
				return mutation.Binding{}, false
			}
			return mutation.Binding{
				ProfileID: "corp", PrincipalID: "alice",
				ExternalSubject: "entra-alice", Tenant: ten,
			}, true
		},
	})
	intent := mutation.Intent{Action: mutation.ActionStopBuild, JobName: "demo", BuildNumber: 1}
	t1 := context.WithValue(context.Background(), tenantKey{}, "tenant-a")
	t2 := context.WithValue(context.Background(), tenantKey{}, "tenant-b")
	prev, err := m.Preview(t1, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(t2, prev.ConfirmationToken, intent); err == nil {
		t.Fatal("tenant mismatch must deny")
	}
	assertDenyReason(t, mem, mutation.ReasonBindingMismatch)
}

// Audit deny for binding mismatch uses Bob's effective PrincipalID/ExternalSubject
// (not Alice's) and opaque SubjectKeyHash; secret canary free.
func TestBindingMismatchAuditUsesEffectiveSubject_SecretCanary(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	const canary = "super-secret-api-token-VALUE-xyz"
	type bindKey struct{}
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "alice",
		ConfirmCooldown: -1,
		Now:             now,
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			if b, ok := ctx.Value(bindKey{}).(mutation.Binding); ok {
				return b, true
			}
			return mutation.Binding{}, false
		},
	})
	intent := mutation.Intent{
		Action:     mutation.ActionStartJob,
		JobName:    "demo",
		Parameters: map[string]any{"BRANCH": "main"}, // non-secret; secrets rejected earlier
	}
	alice := mutation.Binding{ProfileID: "corp", PrincipalID: "alice", ExternalSubject: "sub-a", Tenant: "t"}
	bob := mutation.Binding{ProfileID: "corp", PrincipalID: "bob", ExternalSubject: "sub-b", Tenant: "t"}
	prev, err := m.Preview(context.WithValue(context.Background(), bindKey{}, alice), intent)
	if err != nil {
		t.Fatal(err)
	}
	// Preview audit also carries Alice ExternalSubject + SubjectKeyHash.
	wantAliceHash := audit.HashOpaque("t|sub-a|corp")
	var sawPreview bool
	for _, e := range mem.Events() {
		if e.Type == mutation.TypePreview && e.ReasonCode == mutation.ReasonPreviewOK {
			sawPreview = true
			if e.ExternalSubject != "sub-a" || e.SubjectKeyHash != wantAliceHash {
				t.Fatalf("preview audit subject: external=%q hash=%q want sub-a / %q",
					e.ExternalSubject, e.SubjectKeyHash, wantAliceHash)
			}
		}
	}
	if !sawPreview {
		t.Fatal("expected preview audit with ExternalSubject")
	}
	mem.Reset()
	_, _ = m.Confirm(context.WithValue(context.Background(), bindKey{}, bob), prev.ConfirmationToken, intent)
	events := mem.Events()
	if len(events) == 0 {
		t.Fatal("expected deny audit")
	}
	wantBobHash := audit.HashOpaque("t|sub-b|corp")
	var sawMismatch bool
	for _, e := range events {
		if e.ReasonCode == mutation.ReasonBindingMismatch {
			sawMismatch = true
			if e.PrincipalID != "bob" {
				t.Fatalf("deny audit should attribute bob (effective subject), got %q", e.PrincipalID)
			}
			if e.ExternalSubject != "sub-b" {
				t.Fatalf("deny audit ExternalSubject want sub-b, got %q", e.ExternalSubject)
			}
			if e.SubjectKeyHash != wantBobHash {
				t.Fatalf("deny audit SubjectKeyHash want %q, got %q", wantBobHash, e.SubjectKeyHash)
			}
		}
		// Canary: raw secret string must never appear in any audit field.
		blob := e.Type + e.ProfileID + e.PrincipalID + e.ExternalSubject + e.SubjectKeyHash +
			e.Tool + e.Action + e.Decision + e.ReasonCode + e.TargetHash + e.RequestID
		if strings.Contains(blob, canary) {
			t.Fatalf("canary secret leaked into audit: %+v", e)
		}
		if strings.Contains(blob, prev.ConfirmationToken) {
			t.Fatalf("confirmation token must not appear in audit: %+v", e)
		}
		// Opaque hash only — never raw tenant|subject|profile.
		if strings.Contains(e.SubjectKeyHash, "|") || strings.Contains(e.SubjectKeyHash, "t|sub") {
			t.Fatalf("raw subject key leaked into SubjectKeyHash: %q", e.SubjectKeyHash)
		}
	}
	if !sawMismatch {
		t.Fatal("expected binding_mismatch with ExternalSubject")
	}
}

// Single-user / empty ExternalSubject leaves ExternalSubject and SubjectKeyHash empty.
func TestAuditSubjectFieldsEmptyWithoutExternalSubject(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "alice",
		ConfirmCooldown: -1,
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	for _, e := range mem.Events() {
		if e.ExternalSubject != "" || e.SubjectKeyHash != "" {
			t.Fatalf("stdio residual must not set multi-user audit fields: %+v", e)
		}
		if e.ProfileID != "corp" || e.PrincipalID != "alice" {
			t.Fatalf("still want profile/principal: %+v", e)
		}
	}
}

// Confirm cooldown is per binding: Alice confirm does not block Bob on same target.
func TestConfirmCooldownIsolatedPerSubject(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	type bindKey struct{}
	m := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:                mem,
		MaxPreviewsPerMinute: -1,
		ConfirmCooldown:      5 * time.Second,
		TTL:                  2 * time.Minute,
		Now:                  now,
		BindingFromContext: func(ctx context.Context) (mutation.Binding, bool) {
			if b, ok := ctx.Value(bindKey{}).(mutation.Binding); ok {
				return b, true
			}
			return mutation.Binding{}, false
		},
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "same-job"}
	alice := mutation.Binding{ProfileID: "corp", PrincipalID: "alice", ExternalSubject: "a", Tenant: "t"}
	bob := mutation.Binding{ProfileID: "corp", PrincipalID: "bob", ExternalSubject: "b", Tenant: "t"}
	aliceCtx := context.WithValue(context.Background(), bindKey{}, alice)
	bobCtx := context.WithValue(context.Background(), bindKey{}, bob)

	prevA, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(aliceCtx, prevA.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	// Alice re-confirm within cooldown denied.
	prevA2, err := m.Preview(aliceCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(aliceCtx, prevA2.ConfirmationToken, intent); err == nil {
		t.Fatal("alice should be in cooldown")
	}
	// Bob is not blocked by Alice's cooldown.
	prevB, err := m.Preview(bobCtx, intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(bobCtx, prevB.ConfirmationToken, intent); err != nil {
		t.Fatalf("bob should not inherit alice cooldown: %v", err)
	}
}

// Process-default ExternalSubject/Tenant on Config (no context) still binds tokens.
func TestConfigExternalSubjectInBinding(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	// Two managers with same profile/principal but different ExternalSubject —
	// different stores, so token unknown; use one manager with BindingFromContext
	// override vs Config is already covered. Here: happy path with Config-only
	// ExternalSubject appears in audit principal path still PrincipalID.
	m := mutation.NewManager(mutation.Config{
		Gate:            policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:           mem,
		ProfileID:       "corp",
		PrincipalID:     "alice",
		ExternalSubject: "entra-alice",
		Tenant:          "tid-1",
		ConfirmCooldown: -1,
		Now:             now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	// Config-path Binding still attributes ExternalSubject + SubjectKeyHash on audit.
	wantHash := audit.HashOpaque("tid-1|entra-alice|corp")
	for _, e := range mem.Events() {
		if e.Type != mutation.TypePreview && e.Type != mutation.TypeConfirm {
			continue
		}
		if e.ExternalSubject != "entra-alice" || e.SubjectKeyHash != wantHash {
			t.Fatalf("Config ExternalSubject audit: external=%q hash=%q want entra-alice/%q event=%+v",
				e.ExternalSubject, e.SubjectKeyHash, wantHash, e)
		}
	}
	// Mismatch: construct token under alice external then Confirm under manager
	// that has BindingFromContext returning different external — covered above.
	// Binding.Equal self-check for Config path.
	b1 := mutation.Binding{ProfileID: "corp", PrincipalID: "alice", ExternalSubject: "entra-alice", Tenant: "tid-1"}
	b2 := mutation.Binding{ProfileID: "corp", PrincipalID: "alice", ExternalSubject: "entra-alice", Tenant: "tid-1"}
	if !b1.Equal(b2) {
		t.Fatal("equal bindings")
	}
	b2.Tenant = "tid-2"
	if b1.Equal(b2) {
		t.Fatal("tenant change must not equal")
	}
}
