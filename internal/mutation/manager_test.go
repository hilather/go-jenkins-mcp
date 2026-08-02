package mutation_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

func testClock(start time.Time) (now func() time.Time, advance func(d time.Duration)) {
	var mu sync.Mutex
	t := start.UTC()
	now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return t
	}
	advance = func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		t = t.Add(d)
	}
	return now, advance
}

func allowMutationsManager(t *testing.T, mem *audit.Memory, now func() time.Time, ttl time.Duration) *mutation.Manager {
	t.Helper()
	return mutation.NewManager(mutation.Config{
		Gate:        policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:       mem,
		ProfileID:   "corp",
		PrincipalID: "alice",
		TTL:         ttl,
		Now:         now,
	})
}

func TestPreviewAndConfirmHappyPath(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, 2*time.Minute)

	intent := mutation.Intent{
		Action:     mutation.ActionStartJob,
		JobName:    "folder/demo",
		Parameters: map[string]any{"BRANCH": "main"},
	}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if prev.Status != "preview" || prev.ConfirmationToken == "" {
		t.Fatalf("preview: %+v", prev)
	}
	if prev.Parameters["BRANCH"] != "main" {
		t.Fatalf("params: %+v", prev.Parameters)
	}
	if prev.EndpointClass != mutation.EndpointBuildWithParameters {
		t.Fatalf("endpoint: %s", prev.EndpointClass)
	}

	bound, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent)
	if err != nil {
		t.Fatal(err)
	}
	if bound.JobName != "folder/demo" || bound.Parameters["BRANCH"] != "main" {
		t.Fatalf("bound: %+v", bound)
	}
	if bound.TargetHash != prev.TargetHash {
		t.Fatalf("target hash mismatch")
	}

	// Audit: preview + confirm.
	var types []string
	for _, e := range mem.Events() {
		types = append(types, e.Type)
		// No secret-looking payload in audit fields.
		if strings.Contains(e.TargetHash, "main") {
			t.Fatalf("raw value leaked into target hash event field: %q", e.TargetHash)
		}
	}
	if !contains(types, mutation.TypePreview) || !contains(types, mutation.TypeConfirm) {
		t.Fatalf("audit types: %v", types)
	}
}

func TestTokenExpiry(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, 2*time.Minute)

	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	advance(2*time.Minute + time.Second)
	_, err = m.Confirm(context.Background(), prev.ConfirmationToken, intent)
	if err == nil {
		t.Fatal("expected expiry denial")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "expir") {
		t.Fatalf("msg: %v", err)
	}
	assertDenyReason(t, mem, mutation.ReasonTokenExpired)
}

func TestWrongTargetDenied(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, 2*time.Minute)

	intentA := mutation.Intent{
		Action:     mutation.ActionStartJob,
		JobName:    "job-a",
		Parameters: map[string]any{"X": "1"},
	}
	prev, err := m.Preview(context.Background(), intentA)
	if err != nil {
		t.Fatal(err)
	}
	// Same token, different job.
	intentB := mutation.Intent{
		Action:     mutation.ActionStartJob,
		JobName:    "job-b",
		Parameters: map[string]any{"X": "1"},
	}
	_, err = m.Confirm(context.Background(), prev.ConfirmationToken, intentB)
	if err == nil {
		t.Fatal("expected target mismatch")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	assertDenyReason(t, mem, mutation.ReasonTargetMismatch)

	// Different params also mismatch.
	mem.Reset()
	prev2, err := m.Preview(context.Background(), intentA)
	if err != nil {
		t.Fatal(err)
	}
	intentC := mutation.Intent{
		Action:     mutation.ActionStartJob,
		JobName:    "job-a",
		Parameters: map[string]any{"X": "2"},
	}
	_, err = m.Confirm(context.Background(), prev2.ConfirmationToken, intentC)
	if err == nil {
		t.Fatal("expected param mismatch")
	}
	assertDenyReason(t, mem, mutation.ReasonTargetMismatch)
}

func TestReuseDenied(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, 2*time.Minute)

	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	_, err = m.Confirm(context.Background(), prev.ConfirmationToken, intent)
	if err == nil {
		t.Fatal("expected reuse denial")
	}
	// After consume, token is deleted → unknown (or reused if still present).
	code := apperr.CodeOf(err)
	if code != apperr.CodePolicyDenial {
		t.Fatalf("code: %v", code)
	}
	// Either token_unknown (deleted) or token_reused is acceptable; we delete on use.
	reasons := denyReasons(mem)
	if !contains(reasons, mutation.ReasonTokenUnknown) && !contains(reasons, mutation.ReasonTokenReused) {
		t.Fatalf("reasons: %v", reasons)
	}
}

func TestReadOnlyBlocksPreviewAndConfirmEvenWithToken(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))

	// Issue under allow-mutations, then switch gate to RO for confirm via new manager
	// sharing is not possible — instead issue, then use a RO manager that cannot
	// see the token, OR simulate by Confirm on RO manager with empty store.
	// Spec: "RO blocks even with token" — gate check runs before token lookup.
	// Build a custom manager that has a token then flip gate is not exported.
	// Approach: Preview under allow; Confirm under RO with same token string is
	// denied at gate (read_only) without needing the store.
	allow := allowMutationsManager(t, mem, now, 2*time.Minute)
	intent := mutation.Intent{Action: mutation.ActionStopBuild, JobName: "demo", BuildNumber: 7}
	prev, err := allow.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}

	// New manager with same clock/ids but RO gate (and empty store — still must be RO deny first).
	ro := mutation.NewManager(mutation.Config{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Audit:       mem,
		ProfileID:   "corp",
		PrincipalID: "alice",
		TTL:         2 * time.Minute,
		Now:         now,
	})
	// Preview under RO denied.
	if _, err := ro.Preview(context.Background(), intent); err == nil {
		t.Fatal("RO preview must deny")
	} else if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}

	// Confirm with "valid-looking" token under RO must deny with read_only.
	mem.Reset()
	_, err = ro.Confirm(context.Background(), prev.ConfirmationToken, intent)
	if err == nil {
		t.Fatal("RO confirm must deny even with token")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	assertDenyReason(t, mem, mutation.ReasonReadOnly)
}

// Regression: token issued under allow-mutations is unusable after enterprise force RO
// when Confirm checks gate first (even if token were in the same store).
func TestConfirmROOnSameManagerAfterForce(t *testing.T) {
	t.Parallel()
	// Manager holds a gate pointer; create with force RO from the start and
	// verify Confirm never succeeds.
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate: policy.NewReadOnlyGate(policy.Inputs{
			AllowMutations: true,
			Force:          policy.StaticForce{Force: true, Present: true},
		}),
		Audit:       mem,
		ProfileID:   "corp",
		PrincipalID: "alice",
		Now:         now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	if _, err := m.Preview(context.Background(), intent); err == nil {
		t.Fatal("force RO must block preview")
	}
	if _, err := m.Confirm(context.Background(), "deadbeef", intent); err == nil {
		t.Fatal("force RO must block confirm")
	}
	assertDenyReason(t, mem, mutation.ReasonReadOnly)
}

func TestSecretParamsRejected(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, time.Minute)

	_, err := m.Preview(context.Background(), mutation.Intent{
		Action:     mutation.ActionStartJob,
		JobName:    "demo",
		Parameters: map[string]any{"PASSWORD": "s3cret", "BRANCH": "main"},
	})
	if err == nil {
		t.Fatal("expected secret param reject")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "secret") && !strings.Contains(err.Error(), "PASSWORD") {
		t.Fatalf("msg: %v", err)
	}
}

func TestRedactParamsInPreview(t *testing.T) {
	t.Parallel()
	// Non-sensitive key with secret-shaped value still redacted in preview text.
	in := map[string]any{
		"note": "Bearer super-secret-token-value-xyz",
	}
	out := mutation.RedactParams(in)
	if s, ok := out["note"].(string); !ok || strings.Contains(s, "super-secret-token-value-xyz") {
		t.Fatalf("note not redacted: %#v", out["note"])
	}
	if out["note"] == "" {
		// Replacement or redacted form must remain non-empty typically.
	}
	// Sensitive key fully replaced.
	out2 := mutation.RedactParams(map[string]any{"API_TOKEN": "raw"})
	if out2["API_TOKEN"] != redact.Replacement {
		t.Fatalf("%v", out2)
	}
}

func TestStopBuildPreviewRequiresBuildNumber(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, time.Minute)
	_, err := m.Preview(context.Background(), mutation.Intent{
		Action:  mutation.ActionStopBuild,
		JobName: "demo",
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("err=%v", err)
	}
}

func TestCancelQueuePreviewAndConfirm(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, 2*time.Minute)

	intent := mutation.Intent{
		Action:       mutation.ActionCancelQueue,
		JobName:      "demo",
		QueueID:      55,
		CurrentState: "queued",
	}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if prev.Status != "preview" || prev.QueueID != 55 || prev.EndpointClass != mutation.EndpointCancelItem {
		t.Fatalf("preview: %+v", prev)
	}
	if prev.ConfirmationToken == "" {
		t.Fatal("missing token")
	}
	// Target hash must include queue id (different queue ⇒ different hash).
	other := mutation.TargetHash(mutation.ActionCancelQueue, "demo", 0, 56, mutation.ParamFingerprint(nil))
	if prev.TargetHash == other {
		t.Fatal("target hash must bind queue id")
	}
	same := mutation.TargetHash(mutation.ActionCancelQueue, "demo", 0, 55, mutation.ParamFingerprint(nil))
	if prev.TargetHash != same {
		t.Fatalf("target hash=%s want %s", prev.TargetHash, same)
	}

	bound, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent)
	if err != nil {
		t.Fatal(err)
	}
	if bound.QueueID != 55 || bound.Action != mutation.ActionCancelQueue {
		t.Fatalf("bound: %+v", bound)
	}
	// Audit has no secrets.
	for _, e := range mem.Events() {
		if strings.Contains(e.TargetHash, "secret") {
			t.Fatalf("secret in audit: %+v", e)
		}
	}
}

func TestCancelQueueRequiresQueueID(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, time.Minute)
	_, err := m.Preview(context.Background(), mutation.Intent{
		Action: mutation.ActionCancelQueue,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("err=%v", err)
	}
}

func TestCancelQueueWrongQueueIDTargetMismatch(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, time.Minute)
	intent := mutation.Intent{Action: mutation.ActionCancelQueue, QueueID: 10}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Confirm(context.Background(), prev.ConfirmationToken, mutation.Intent{
		Action: mutation.ActionCancelQueue, QueueID: 11,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("err=%v", err)
	}
}

func TestConcurrentConfirmSingleUse(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := allowMutationsManager(t, mem, now, time.Minute)
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var ok, fail int
	for err := range errs {
		if err == nil {
			ok++
		} else {
			fail++
		}
	}
	if ok != 1 || fail != 7 {
		t.Fatalf("ok=%d fail=%d", ok, fail)
	}
}

// MUT-001: Preview sliding-window rate limit.
func TestPreviewRateLimited(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:                mem,
		ProfileID:            "corp",
		PrincipalID:          "alice",
		TTL:                  time.Minute,
		MaxPreviewsPerMinute: 2,
		ConfirmCooldown:      -1, // off
		Now:                  now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	if _, err := m.Preview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Preview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	_, err := m.Preview(context.Background(), intent)
	if err == nil {
		t.Fatal("expected preview rate limit")
	}
	if apperr.CodeOf(err) != apperr.CodeThrottled {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rate limited") {
		t.Fatalf("msg: %v", err)
	}
	assertDenyReason(t, mem, mutation.ReasonPreviewRateLimited)

	// Window slides: after 1m, previews allowed again.
	mem.Reset()
	advance(time.Minute + time.Second)
	if _, err := m.Preview(context.Background(), intent); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

// MUT-001: Confirm cooldown per (profile, action, targetHash).
func TestConfirmCooldown(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:                mem,
		ProfileID:            "corp",
		PrincipalID:          "alice",
		TTL:                  2 * time.Minute,
		MaxPreviewsPerMinute: -1, // unlimited
		ConfirmCooldown:      5 * time.Second,
		Now:                  now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	prev1, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev1.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}

	// New preview+confirm for same target within cooldown → deny (no execute).
	prev2, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Confirm(context.Background(), prev2.ConfirmationToken, intent)
	if err == nil {
		t.Fatal("expected confirm cooldown")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	assertDenyReason(t, mem, mutation.ReasonConfirmCooldown)

	// Token not consumed on cooldown deny — after cooldown, same token works.
	advance(5*time.Second + time.Millisecond)
	mem.Reset()
	bound, err := m.Confirm(context.Background(), prev2.ConfirmationToken, intent)
	if err != nil {
		t.Fatalf("after cooldown: %v", err)
	}
	if bound.JobName != "demo" {
		t.Fatalf("bound: %+v", bound)
	}

	// Different target is not blocked by the other target's cooldown.
	other := mutation.Intent{Action: mutation.ActionStartJob, JobName: "other-job"}
	prevOther, err := m.Preview(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prevOther.ConfirmationToken, other); err != nil {
		t.Fatalf("other target: %v", err)
	}
}

// Negative MaxPreviewsPerMinute / ConfirmCooldown disable limits (test escape hatch).
func TestRateAndCooldownUnlimitedWhenNegative(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, _ := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	m := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:                mem,
		ProfileID:            "corp",
		PrincipalID:          "alice",
		MaxPreviewsPerMinute: -1,
		ConfirmCooldown:      -1,
		Now:                  now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	// More previews than production default without throttling.
	for i := 0; i < mutation.DefaultMaxPreviewsPerMinute+5; i++ {
		if _, err := m.Preview(context.Background(), intent); err != nil {
			t.Fatalf("preview %d: %v", i, err)
		}
	}
	// Back-to-back confirms on same target with fresh tokens (cooldown off).
	for i := 0; i < 3; i++ {
		prev, err := m.Preview(context.Background(), intent)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Confirm(context.Background(), prev.ConfirmationToken, intent); err != nil {
			t.Fatalf("confirm %d: %v", i, err)
		}
	}
}

// Zero config fields resolve to production defaults (mirror TTL pattern).
func TestZeroConfigUsesProductionRateDefaults(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	now, advance := testClock(time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
	// MaxPreviewsPerMinute=0 and ConfirmCooldown=0 → production defaults.
	m := mutation.NewManager(mutation.Config{
		Gate:        policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:       mem,
		ProfileID:   "corp",
		PrincipalID: "alice",
		Now:         now,
	})
	intent := mutation.Intent{Action: mutation.ActionStartJob, JobName: "demo"}
	// Confirm cooldown default is active: second confirm for same target denied.
	prev1, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev1.ConfirmationToken, intent); err != nil {
		t.Fatal(err)
	}
	prev2, err := m.Preview(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(context.Background(), prev2.ConfirmationToken, intent); err == nil {
		t.Fatal("default confirm cooldown should deny immediate re-confirm")
	}
	assertDenyReason(t, mem, mutation.ReasonConfirmCooldown)
	advance(mutation.DefaultConfirmCooldown + time.Millisecond)
	if _, err := m.Confirm(context.Background(), prev2.ConfirmationToken, intent); err != nil {
		t.Fatalf("after default cooldown: %v", err)
	}

	// Default preview rate: fill window then throttle.
	// Explicit DefaultMaxPreviewsPerMinute so this case is independent of process
	// live SetMaxPreviewsPerMinute (Wave 52 Track C; zero Config uses process live).
	mem.Reset()
	m2 := mutation.NewManager(mutation.Config{
		Gate:                 policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
		Audit:                mem,
		MaxPreviewsPerMinute: mutation.DefaultMaxPreviewsPerMinute,
		ConfirmCooldown:      -1,
		Now:                  now,
	})
	for i := 0; i < mutation.DefaultMaxPreviewsPerMinute; i++ {
		if _, err := m2.Preview(context.Background(), intent); err != nil {
			t.Fatalf("preview %d under default cap: %v", i, err)
		}
	}
	_, err = m2.Preview(context.Background(), intent)
	if err == nil || apperr.CodeOf(err) != apperr.CodeThrottled {
		t.Fatalf("want throttled after default cap, got %v", err)
	}
	assertDenyReason(t, mem, mutation.ReasonPreviewRateLimited)
}

func assertDenyReason(t *testing.T, mem *audit.Memory, want string) {
	t.Helper()
	reasons := denyReasons(mem)
	if !contains(reasons, want) {
		t.Fatalf("want deny reason %q in %v (events=%+v)", want, reasons, mem.Events())
	}
}

func denyReasons(mem *audit.Memory) []string {
	var out []string
	for _, e := range mem.Events() {
		if e.Type == mutation.TypeDeny || e.Decision == audit.DecisionDeny {
			out = append(out, e.ReasonCode)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
