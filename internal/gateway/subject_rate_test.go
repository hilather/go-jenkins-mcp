package gateway_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

func TestSubjectRateLimiter_AliceCapDoesNotBlockBob(t *testing.T) {
	t.Parallel()
	// burst 2, slow refill so Alice exhausts burst without time recovery.
	l := gateway.NewSubjectRateLimiter(30, 2, 300, 60)
	alice := gateway.SubjectKeyParts("t1", "alice", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob", "corp")

	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	err := l.Allow(alice)
	if err == nil {
		t.Fatal("alice third allow must fail closed at burst")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("want subject rate message: %v", err)
	}

	// Bob still has full burst (isolation / fair share).
	if err := l.Allow(bob); err != nil {
		t.Fatalf("bob must not share alice tokens: %v", err)
	}
	if err := l.Allow(bob); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(bob); err == nil {
		t.Fatal("bob third must fail at burst")
	}
}

func TestSubjectRateLimiter_ProcessCeilingBinds(t *testing.T) {
	t.Parallel()
	// High per-subject burst, tight process burst: process wins.
	l := gateway.NewSubjectRateLimiter(600, 10, 600, 3)
	a := gateway.SubjectKeyParts("t", "a", "p")
	b := gateway.SubjectKeyParts("t", "b", "p")
	c := gateway.SubjectKeyParts("t", "c", "p")

	if err := l.Allow(a); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(b); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(c); err != nil {
		t.Fatal(err)
	}
	err := l.Allow(gateway.SubjectKeyParts("t", "d", "p"))
	if err == nil {
		t.Fatal("process rate ceiling must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "process") {
		t.Fatalf("want process rate message: %v", err)
	}
}

func TestSubjectRateLimiter_FairShareUnderProcessCap(t *testing.T) {
	t.Parallel()
	// Documented fair-share: Alice at her subject burst does not burn process
	// tokens on failed Allow, so Bob still gets his allocation.
	l := gateway.NewSubjectRateLimiter(30, 2, 10, 10)
	alice := gateway.SubjectKeyParts("t", "alice", "corp")
	bob := gateway.SubjectKeyParts("t", "bob", "corp")

	_ = l.Allow(alice)
	_ = l.Allow(alice)
	if err := l.Allow(alice); err == nil {
		t.Fatal("alice over burst")
	}
	// Extra denied Alice calls must not starve Bob (refund process on subject deny).
	for i := 0; i < 20; i++ {
		_ = l.Allow(alice)
	}
	if err := l.Allow(bob); err != nil {
		t.Fatalf("bob starved by alice spam: %v", err)
	}
	if err := l.Allow(bob); err != nil {
		t.Fatalf("bob second token: %v", err)
	}
}

func TestSubjectRateLimiter_RefillOverTime(t *testing.T) {
	t.Parallel()
	// 60/min = 1/s, burst 1 — after 1s should allow again.
	l := gateway.NewSubjectRateLimiter(60, 1, 600, 60)
	key := gateway.SubjectKeyParts("t", "u", "p")
	base := time.Unix(1_700_000_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	if err := l.Allow(key); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(key); err == nil {
		t.Fatal("burst exhausted")
	}
	clock.Store(base.Add(time.Second + 10*time.Millisecond))
	if err := l.Allow(key); err != nil {
		t.Fatalf("after refill: %v", err)
	}
}

func TestSubjectRateLimiter_EmptySubjectFailClosed(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(30, 10, 300, 60)
	err := l.Allow("")
	if err == nil {
		t.Fatal("empty subject must fail")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	// Nil limiter is unlimited no-op.
	var nilL *gateway.SubjectRateLimiter
	if err := nilL.Allow("t|u|p"); err != nil {
		t.Fatal(err)
	}
}

func TestSubjectRateLimiter_ConcurrentSafety(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(600, 50, 6000, 500)
	const subjects = 8
	const tries = 40
	var okCount atomic.Int64
	var wg sync.WaitGroup
	for s := 0; s < subjects; s++ {
		key := gateway.SubjectKeyParts("t", "u"+string(rune('a'+s)), "corp")
		for i := 0; i < tries; i++ {
			wg.Add(1)
			go func(k string) {
				defer wg.Done()
				if err := l.Allow(k); err == nil {
					okCount.Add(1)
				}
			}(key)
		}
	}
	wg.Wait()
	if okCount.Load() == 0 {
		t.Fatal("expected some successful allows")
	}
	// Cannot exceed process burst on a single synchronized start (all at t0).
	if okCount.Load() > int64(l.ProcessBurst()) {
		// With concurrent refill still at start, cap is process burst.
		// Allow equality with process burst only when all hit empty buckets.
		t.Fatalf("ok=%d process_burst=%d (leak or over-allow)", okCount.Load(), l.ProcessBurst())
	}
}

func TestSubjectRateLimiter_StatusMapSecretFree(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(30, 10, 300, 60)
	key := gateway.SubjectKeyParts("secret-tenant", "secret-sub", "corp")
	_ = l.Allow(key)
	st := l.StatusMap()
	blob := fmt.Sprintf("%v", st)
	if strings.Contains(blob, "secret-tenant") || strings.Contains(blob, "secret-sub") {
		t.Fatalf("status leaked subject material: %v", st)
	}
	if st["configured"] != true {
		t.Fatal(st)
	}
	if st["ha_multi_replica"] != false {
		t.Fatal("HOST-008 residual must report ha_multi_replica=false")
	}
	// Canary: no token-like secrets in status.
	canary := "sk-super-secret-token-value"
	if strings.Contains(blob, canary) {
		t.Fatal("status leaked canary")
	}
}

func TestResolveSubjectRateCaps(t *testing.T) {
	t.Parallel()
	rpm, burst, err := gateway.ResolveSubjectRateCaps("", "")
	if err != nil {
		t.Fatal(err)
	}
	if rpm != gateway.DefaultSubjectRatePerMinute || burst != gateway.DefaultSubjectRateBurst {
		t.Fatalf("defaults: rpm=%d burst=%d", rpm, burst)
	}
	rpm, burst, err = gateway.ResolveSubjectRateCaps("60", "5")
	if err != nil {
		t.Fatal(err)
	}
	if rpm != 60 || burst != 5 {
		t.Fatalf("override: rpm=%d burst=%d", rpm, burst)
	}
	// Explicit 0 disables residual.
	rpm, _, err = gateway.ResolveSubjectRateCaps("0", "")
	if err != nil {
		t.Fatal(err)
	}
	if rpm != 0 {
		t.Fatalf("0 must disable: rpm=%d", rpm)
	}
	if _, _, err := gateway.ResolveSubjectRateCaps("-1", ""); err == nil {
		t.Fatal("negative rate must fail closed")
	}
	if _, _, err := gateway.ResolveSubjectRateCaps("x", ""); err == nil {
		t.Fatal("non-integer must fail closed")
	}
	if _, _, err := gateway.ResolveSubjectRateCaps("", "-2"); err == nil {
		t.Fatal("negative burst must fail closed")
	}
	if gateway.EnvSubjectRatePerMinute != "JENKINS_MCP_SUBJECT_RATE_PER_MINUTE" {
		t.Fatalf("env name: %q", gateway.EnvSubjectRatePerMinute)
	}
	if gateway.EnvSubjectRateBurst != "JENKINS_MCP_SUBJECT_RATE_BURST" {
		t.Fatalf("burst env name: %q", gateway.EnvSubjectRateBurst)
	}
}

// HOST-008 residual: rateEnabled admin field source (secret-free env parse only).
func TestSubjectRateEnabledFromEnviron(t *testing.T) {
	t.Parallel()
	if !gateway.SubjectRateEnabledFromEnviron(func(string) string { return "" }) {
		t.Fatal("empty env → default enabled")
	}
	if gateway.SubjectRateEnabledFromEnviron(func(k string) string {
		if k == gateway.EnvSubjectRatePerMinute {
			return "0"
		}
		return ""
	}) {
		t.Fatal("explicit 0 → disabled")
	}
	if !gateway.SubjectRateEnabledFromEnviron(func(k string) string {
		if k == gateway.EnvSubjectRatePerMinute {
			return "30"
		}
		return ""
	}) {
		t.Fatal("positive → enabled")
	}
	if gateway.SubjectRateEnabledFromEnviron(func(k string) string {
		if k == gateway.EnvSubjectRatePerMinute {
			return "nope"
		}
		return ""
	}) {
		t.Fatal("invalid → fail closed not enabled")
	}
}

// HOST-006 / HOST-007 admin residual: resolved rate knobs (secret-free; never tokens).
func TestSubjectRateConfigFromEnviron(t *testing.T) {
	t.Parallel()
	en, rpm, burst := gateway.SubjectRateConfigFromEnviron(func(string) string { return "" })
	if !en || rpm != gateway.DefaultSubjectRatePerMinute || burst != gateway.DefaultSubjectRateBurst {
		t.Fatalf("defaults: enabled=%v rpm=%d burst=%d", en, rpm, burst)
	}
	en, rpm, burst = gateway.SubjectRateConfigFromEnviron(func(k string) string {
		switch k {
		case gateway.EnvSubjectRatePerMinute:
			return "45"
		case gateway.EnvSubjectRateBurst:
			return "7"
		default:
			return ""
		}
	})
	if !en || rpm != 45 || burst != 7 {
		t.Fatalf("override: enabled=%v rpm=%d burst=%d", en, rpm, burst)
	}
	// Explicit 0 → disabled; burst reported 0 (ignored when rate off).
	en, rpm, burst = gateway.SubjectRateConfigFromEnviron(func(k string) string {
		if k == gateway.EnvSubjectRatePerMinute {
			return "0"
		}
		if k == gateway.EnvSubjectRateBurst {
			return "99"
		}
		return ""
	})
	if en || rpm != 0 || burst != 0 {
		t.Fatalf("disabled: enabled=%v rpm=%d burst=%d", en, rpm, burst)
	}
	// Invalid → fail closed zeros.
	en, rpm, burst = gateway.SubjectRateConfigFromEnviron(func(k string) string {
		if k == gateway.EnvSubjectRatePerMinute {
			return "x"
		}
		return ""
	})
	if en || rpm != 0 || burst != 0 {
		t.Fatalf("invalid: enabled=%v rpm=%d burst=%d", en, rpm, burst)
	}
}

func TestSubjectRateLimiter_AbsoluteCeilingsClamped(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(10_000, 10_000, 10_000, 10_000)
	if l.RatePerMinute() > gateway.AbsoluteMaxSubjectRatePerMinute {
		t.Fatal("rate abs not clamped")
	}
	if l.Burst() > gateway.AbsoluteMaxSubjectRateBurst {
		t.Fatal("burst abs not clamped")
	}
	if l.ProcessRatePerMinute() > gateway.AbsoluteMaxProcessRatePerMinute {
		t.Fatal("process rate abs not clamped")
	}
	if l.ProcessBurst() > gateway.AbsoluteMaxProcessRateBurst {
		t.Fatal("process burst abs not clamped")
	}
}

// HOST-006 residual: policy/overlay may only lower serve-bootstrap rate.
func TestSubjectRateLimiter_LowerRateOnlyLowers(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(30, 10, 300, 60)
	if l.RatePerMinute() != 30 || l.Burst() != 10 {
		t.Fatalf("bootstrap rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}

	// Lower both dimensions.
	if !l.LowerRate(15, 4) {
		t.Fatal("LowerRate to 15/4 should change")
	}
	if l.RatePerMinute() != 15 || l.Burst() != 4 {
		t.Fatalf("after lower: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}

	// Cannot raise back (policy never elevates).
	if l.LowerRate(30, 10) {
		t.Fatal("LowerRate must not raise rate/burst")
	}
	if l.RatePerMinute() != 15 || l.Burst() != 4 {
		t.Fatalf("still lowered: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}

	// Cannot raise above absolute ceilings via huge request.
	if l.LowerRate(10_000, 10_000) {
		t.Fatal("request above abs must not raise")
	}
	if l.RatePerMinute() != 15 || l.Burst() != 4 {
		t.Fatalf("abs request left live: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}

	// Equal values are no-ops (strictly smaller only).
	if l.LowerRate(15, 4) {
		t.Fatal("equal LowerRate must be no-op")
	}

	// Empty / non-positive = no change for that dimension.
	if l.LowerRate(0, 0) {
		t.Fatal("empty LowerRate must be no-op")
	}
	if l.LowerRate(-1, -5) {
		t.Fatal("negative LowerRate must be no-op")
	}
	if l.RatePerMinute() != 15 || l.Burst() != 4 {
		t.Fatal("empty must leave live values")
	}

	// Rate-only lower; burst arg empty keeps burst.
	if !l.LowerRate(10, 0) {
		t.Fatal("rate-only lower")
	}
	if l.RatePerMinute() != 10 || l.Burst() != 4 {
		t.Fatalf("rate-only: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}
	// Burst-only lower; rate empty keeps rate.
	if !l.LowerRate(0, 2) {
		t.Fatal("burst-only lower")
	}
	if l.RatePerMinute() != 10 || l.Burst() != 2 {
		t.Fatalf("burst-only: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}

	// Absolute floor: request below min clamps to min, then applies if below current.
	if !l.LowerRate(1, 1) {
		t.Fatal("lower to floor")
	}
	// Further request still at/below floor cannot go under min or change when already min.
	if l.LowerRate(1, 1) {
		t.Fatal("already at floor equal is no-op")
	}
	// Request that clamps to min when already at min is no-op.
	if l.LowerRate(gateway.MinSubjectRatePerMinute, gateway.MinSubjectRateBurst) {
		t.Fatal("min equal is no-op")
	}
	if l.RatePerMinute() != gateway.MinSubjectRatePerMinute || l.Burst() != gateway.MinSubjectRateBurst {
		t.Fatalf("floor: rpm=%d burst=%d", l.RatePerMinute(), l.Burst())
	}

	// Nil receiver.
	var nilL *gateway.SubjectRateLimiter
	if nilL.LowerRate(1, 1) {
		t.Fatal("nil LowerRate")
	}

	// Process ceilings unchanged by LowerRate.
	l2 := gateway.NewSubjectRateLimiter(30, 10, 300, 60)
	procRPM, procBurst := l2.ProcessRatePerMinute(), l2.ProcessBurst()
	_ = l2.LowerRate(5, 2)
	if l2.ProcessRatePerMinute() != procRPM || l2.ProcessBurst() != procBurst {
		t.Fatal("LowerRate must not touch process ceilings")
	}
}

// HOST-008 residual lite: MaxSubjects=0 (default) never bounds the subject map.
func TestSubjectRateLimiter_MaxSubjectsUnlimitedDefault(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(600, 50, 6000, 500)
	if l.MaxSubjects() != 0 {
		t.Fatalf("default MaxSubjects=%d want 0", l.MaxSubjects())
	}
	for i := 0; i < 40; i++ {
		if err := l.Allow(gateway.SubjectKeyParts("t", fmt.Sprintf("u%02d", i), "p")); err != nil {
			t.Fatalf("allow %d: %v", i, err)
		}
	}
	if l.SubjectsTracked() != 40 {
		t.Fatalf("unlimited tracked=%d want 40", l.SubjectsTracked())
	}
	st := l.StatusMap()
	if _, ok := st["subject_rate_max_subjects"]; ok {
		t.Fatalf("unlimited must omit subject_rate_max_subjects: %+v", st)
	}
}

// HOST-008 residual lite: MaxSubjects LRU by lastAccess (oldest insert without
// re-touch is evicted). Alice/Bob isolation still holds under the cap.
// Clock advances are tiny so buckets stay partial (idle-full purge does not
// free space) — LRU path is what we assert here.
func TestSubjectRateLimiter_MaxSubjectsEvictOldest(t *testing.T) {
	t.Parallel()
	// Low refill rate: 30/min; nanosecond clock steps keep tokens partial.
	l := gateway.NewSubjectRateLimiter(30, 10, 6000, 500)
	l.SetMaxSubjects(2)
	if l.MaxSubjects() != 2 {
		t.Fatalf("MaxSubjects=%d", l.MaxSubjects())
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	k1 := gateway.SubjectKeyParts("t", "u1", "p")
	k2 := gateway.SubjectKeyParts("t", "u2", "p")
	k3 := gateway.SubjectKeyParts("t", "u3", "p")

	if err := l.Allow(k1); err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(time.Nanosecond))
	if err := l.Allow(k2); err != nil {
		t.Fatal(err)
	}
	if l.SubjectsTracked() != 2 {
		t.Fatalf("tracked=%d want 2", l.SubjectsTracked())
	}
	clock.Store(base.Add(2 * time.Nanosecond))
	if err := l.Allow(k3); err != nil {
		t.Fatal(err)
	}
	if l.SubjectsTracked() != 2 {
		t.Fatalf("after eviction tracked=%d want 2", l.SubjectsTracked())
	}
	// k1 was oldest lastAccess → evicted. k2 and k3 remain.
	// Re-allow k2/k3 (existing keys) must not fail for "missing" reasons.
	clock.Store(base.Add(3 * time.Nanosecond))
	if err := l.Allow(k2); err != nil {
		t.Fatalf("k2 must remain: %v", err)
	}
	clock.Store(base.Add(4 * time.Nanosecond))
	if err := l.Allow(k3); err != nil {
		t.Fatalf("k3 must remain: %v", err)
	}
	// k1 is new again → gets a fresh full burst (eviction not "deny").
	clock.Store(base.Add(5 * time.Nanosecond))
	if err := l.Allow(k1); err != nil {
		t.Fatalf("re-admit k1 after eviction: %v", err)
	}
	// Still capped at 2: one of k2/k3 was evicted for k1.
	if l.SubjectsTracked() != 2 {
		t.Fatalf("still capped tracked=%d", l.SubjectsTracked())
	}

	st := l.StatusMap()
	if st["subject_rate_max_subjects"] != 2 {
		t.Fatalf("status max: %+v", st)
	}
	if strings.Contains(fmt.Sprint(st), "u1") || strings.Contains(fmt.Sprint(st), "u2") {
		t.Fatalf("StatusMap leaked subject keys: %+v", st)
	}
}

// When subjects are fully refilled (idle), MaxSubjects prefers purging them
// over LRU of partial-budget subjects.
func TestSubjectRateLimiter_MaxSubjectsPurgeIdleFull(t *testing.T) {
	t.Parallel()
	// 60/min = 1/s refill; burst 2 → after spend-1, 2s later tokens full again.
	l := gateway.NewSubjectRateLimiter(60, 2, 6000, 500)
	l.SetMaxSubjects(2)
	base := time.Unix(1_700_300_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	k1 := gateway.SubjectKeyParts("t", "idle1", "p")
	k2 := gateway.SubjectKeyParts("t", "idle2", "p")
	k3 := gateway.SubjectKeyParts("t", "new", "p")
	if err := l.Allow(k1); err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(time.Nanosecond))
	if err := l.Allow(k2); err != nil {
		t.Fatal(err)
	}
	// Advance enough that both idle subjects refill to capacity.
	clock.Store(base.Add(5 * time.Second))
	if err := l.Allow(k3); err != nil {
		t.Fatal(err)
	}
	// Idle-full purge can free both k1+k2 before insert; map may be just k3
	// or k3 + whatever was not full. Must not exceed MaxSubjects.
	if n := l.SubjectsTracked(); n > 2 {
		t.Fatalf("tracked=%d exceeds max", n)
	}
	// k3 must be present (fresh allow succeeded and is tracked).
	// Touch only k3: if only k3 remains, tracked=1; if one idle remained, =2.
	if n := l.SubjectsTracked(); n < 1 {
		t.Fatal("k3 should be tracked")
	}
	// New allow for k3 (existing) must not grow past cap.
	if err := l.Allow(k3); err != nil {
		t.Fatal(err)
	}
	if n := l.SubjectsTracked(); n > 2 {
		t.Fatalf("after re-touch tracked=%d", n)
	}
}

// Re-Allow of an existing subject under MaxSubjects does not grow or thrash.
func TestSubjectRateLimiter_MaxSubjectsReplaceDoesNotGrow(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(600, 20, 6000, 500)
	l.SetMaxSubjects(2)
	base := time.Unix(1_700_100_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	k1 := gateway.SubjectKeyParts("t", "a", "p")
	k2 := gateway.SubjectKeyParts("t", "b", "p")
	if err := l.Allow(k1); err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(time.Second))
	if err := l.Allow(k2); err != nil {
		t.Fatal(err)
	}
	// Touch k1 many times — still 2 subjects.
	for i := 0; i < 5; i++ {
		clock.Store(base.Add(time.Duration(2+i) * time.Second))
		if err := l.Allow(k1); err != nil {
			t.Fatalf("touch k1: %v", err)
		}
	}
	if l.SubjectsTracked() != 2 {
		t.Fatalf("tracked=%d want 2", l.SubjectsTracked())
	}
}

// Alice burst isolation still holds when MaxSubjects is configured.
func TestSubjectRateLimiter_MaxSubjectsAliceBobIsolation(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(30, 2, 300, 60)
	l.SetMaxSubjects(8)
	alice := gateway.SubjectKeyParts("t1", "alice", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob", "corp")
	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(alice); err == nil {
		t.Fatal("alice third must fail at burst")
	}
	if err := l.Allow(bob); err != nil {
		t.Fatalf("bob isolated under MaxSubjects: %v", err)
	}
}

// Concurrent Allow under MaxSubjects must not race (go test -race).
func TestSubjectRateLimiter_MaxSubjectsConcurrentAllow(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(600, 50, 6000, 500)
	l.SetMaxSubjects(4)
	const subjects = 16
	const tries = 20
	var okCount atomic.Int64
	var wg sync.WaitGroup
	for s := 0; s < subjects; s++ {
		key := gateway.SubjectKeyParts("t", fmt.Sprintf("u%02d", s), "corp")
		for i := 0; i < tries; i++ {
			wg.Add(1)
			go func(k string) {
				defer wg.Done()
				if err := l.Allow(k); err == nil {
					okCount.Add(1)
				}
			}(key)
		}
	}
	wg.Wait()
	if okCount.Load() == 0 {
		t.Fatal("expected some successful allows")
	}
	if n := l.SubjectsTracked(); n > 4 {
		t.Fatalf("tracked=%d exceeds MaxSubjects=4", n)
	}
}

func TestResolveSubjectRateMaxSubjects(t *testing.T) {
	t.Parallel()
	n, err := gateway.ResolveSubjectRateMaxSubjects("")
	if err != nil || n != 0 {
		t.Fatalf("empty: n=%d err=%v", n, err)
	}
	n, err = gateway.ResolveSubjectRateMaxSubjects("  ")
	if err != nil || n != 0 {
		t.Fatalf("blank: n=%d err=%v", n, err)
	}
	n, err = gateway.ResolveSubjectRateMaxSubjects("4096")
	if err != nil || n != 4096 {
		t.Fatalf("4096: n=%d err=%v", n, err)
	}
	n, err = gateway.ResolveSubjectRateMaxSubjects("0")
	if err != nil || n != 0 {
		t.Fatalf("explicit 0 unlimited: n=%d err=%v", n, err)
	}
	if _, err := gateway.ResolveSubjectRateMaxSubjects("-1"); err == nil {
		t.Fatal("negative must fail closed")
	}
	if _, err := gateway.ResolveSubjectRateMaxSubjects("x"); err == nil {
		t.Fatal("non-int must fail closed")
	}
	if gateway.EnvGatewaySubjectRateMaxSubjects != "JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS" {
		t.Fatalf("env name: %q", gateway.EnvGatewaySubjectRateMaxSubjects)
	}
	n, err = gateway.SubjectRateMaxSubjectsFromEnviron(func(k string) string {
		if k == gateway.EnvGatewaySubjectRateMaxSubjects {
			return "64"
		}
		return ""
	})
	if err != nil || n != 64 {
		t.Fatalf("from environ: n=%d err=%v", n, err)
	}
	_, err = gateway.SubjectRateMaxSubjectsFromEnviron(func(k string) string {
		if k == gateway.EnvGatewaySubjectRateMaxSubjects {
			return "nope"
		}
		return ""
	})
	if err == nil {
		t.Fatal("invalid from environ must fail closed")
	}
}

// LowerRate updates existing subject buckets so tighter caps bind immediately.
func TestSubjectRateLimiter_LowerRateUpdatesBuckets(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectRateLimiter(60, 5, 600, 60)
	key := gateway.SubjectKeyParts("t", "u", "p")
	// Consume 1 token from burst 5 → 4 remaining.
	if err := l.Allow(key); err != nil {
		t.Fatal(err)
	}
	// Lower burst to 2: remaining tokens must clamp from 4 → 2 (not leave 4).
	if !l.LowerRate(0, 2) {
		t.Fatal("LowerRate burst")
	}
	if err := l.Allow(key); err != nil {
		t.Fatal(err)
	}
	if err := l.Allow(key); err != nil {
		t.Fatal(err)
	}
	// Third post-lower allow must fail: without clamp would still have room.
	err := l.Allow(key)
	if err == nil {
		t.Fatal("after LowerRate burst clamp, further allow must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}
}
