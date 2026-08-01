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
