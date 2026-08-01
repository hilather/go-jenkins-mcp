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

func TestSubjectLimiter_PerSubjectCapIndependent(t *testing.T) {
	t.Parallel()
	// 2 per subject, process max 10 — Alice can fill her 2 without starving Bob.
	l := gateway.NewSubjectLimiter(2, 10)
	alice := gateway.SubjectKeyParts("t1", "alice", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob", "corp")

	if err := l.Acquire(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(alice); err != nil {
		t.Fatal(err)
	}
	// Alice at cap.
	err := l.Acquire(alice)
	if err == nil {
		t.Fatal("alice third acquire must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Fatalf("want subject budget message: %v", err)
	}

	// Bob still has full allocation (fair share / isolation).
	if err := l.Acquire(bob); err != nil {
		t.Fatalf("bob must not share alice slots: %v", err)
	}
	if err := l.Acquire(bob); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(bob); err == nil {
		t.Fatal("bob third must fail")
	}

	sn, pn := l.InUse(alice)
	if sn != 2 || pn != 4 {
		t.Fatalf("in use alice=%d process=%d", sn, pn)
	}

	l.Release(alice)
	l.Release(alice)
	// After release, alice can acquire again.
	if err := l.Acquire(alice); err != nil {
		t.Fatal(err)
	}
	l.Release(alice)
	l.Release(bob)
	l.Release(bob)
	_, pn = l.InUse(alice)
	if pn != 0 {
		t.Fatalf("process in use after full release: %d", pn)
	}
}

func TestSubjectLimiter_ProcessCeilingBinds(t *testing.T) {
	t.Parallel()
	// High per-subject, tight process ceiling: process wins.
	l := gateway.NewSubjectLimiter(10, 3)
	if l.MaxPerSubject() != 3 {
		// Construction clamps per-subject to process max.
		t.Fatalf("max per subject=%d want 3 (clamped to process)", l.MaxPerSubject())
	}
	a := gateway.SubjectKeyParts("t", "a", "p")
	b := gateway.SubjectKeyParts("t", "b", "p")
	c := gateway.SubjectKeyParts("t", "c", "p")

	if err := l.Acquire(a); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(b); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(c); err != nil {
		t.Fatal(err)
	}
	err := l.Acquire(gateway.SubjectKeyParts("t", "d", "p"))
	if err == nil {
		t.Fatal("process ceiling must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "process") {
		t.Fatalf("want process budget message: %v", err)
	}
	// Release one → another subject can enter.
	l.Release(a)
	if err := l.Acquire(gateway.SubjectKeyParts("t", "d", "p")); err != nil {
		t.Fatal(err)
	}
}

func TestSubjectLimiter_EmptySubjectFailClosed(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(2, 4)
	err := l.Acquire("")
	if err == nil {
		t.Fatal("empty subject must fail")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s", apperr.CodeOf(err))
	}
	// Nil limiter is unlimited no-op.
	var nilL *gateway.SubjectLimiter
	if err := nilL.Acquire("t|u|p"); err != nil {
		t.Fatal(err)
	}
	nilL.Release("t|u|p")
}

func TestSubjectLimiter_HoldAndWithSubjectSlot(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(1, 2)
	key := gateway.SubjectKeyParts("t1", "user", "corp")

	release, err := l.Hold(key)
	if err != nil {
		t.Fatal(err)
	}
	// Second hold fails (per-subject=1).
	_, err = l.Hold(key)
	if err == nil || apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("second hold: %v", err)
	}
	release()
	release() // idempotent

	var ran bool
	err = l.WithSubjectSlot(key, func() error {
		ran = true
		// Nested acquire under same subject fails while held.
		if err := l.Acquire(key); err == nil {
			t.Fatal("nested acquire while slot held")
		}
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("with slot: ran=%v err=%v", ran, err)
	}
	// Slot released after WithSubjectSlot.
	if err := l.Acquire(key); err != nil {
		t.Fatal(err)
	}
	l.Release(key)
}

func TestSubjectLimiter_FairShareUnderProcessCap(t *testing.T) {
	t.Parallel()
	// Documented fair-share policy (HOST-006): each subject gets up to
	// maxPerSubject until processMax binds. Subject A spam cannot take Bob's
	// reserved headroom while process has room for Bob's slots.
	l := gateway.NewSubjectLimiter(2, 5)
	alice := gateway.SubjectKeyParts("t", "alice", "corp")
	bob := gateway.SubjectKeyParts("t", "bob", "corp")

	// Alice spams to her cap.
	_ = l.Acquire(alice)
	_ = l.Acquire(alice)
	if err := l.Acquire(alice); err == nil {
		t.Fatal("alice over cap")
	}
	// Bob still gets his floor (2 slots) while process has room.
	if err := l.Acquire(bob); err != nil {
		t.Fatalf("bob starved by alice: %v", err)
	}
	if err := l.Acquire(bob); err != nil {
		t.Fatalf("bob second slot: %v", err)
	}
	// Process remaining = 1; a third subject can take the last process slot.
	carol := gateway.SubjectKeyParts("t", "carol", "corp")
	if err := l.Acquire(carol); err != nil {
		t.Fatal(err)
	}
	// Process full — no more for anyone.
	if err := l.Acquire(gateway.SubjectKeyParts("t", "dave", "corp")); err == nil {
		t.Fatal("process full")
	}
}

func TestSubjectLimiter_ConcurrentSafety(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(4, 32)
	const subjects = 8
	const tries = 50
	var okCount atomic.Int64
	var wg sync.WaitGroup
	for s := 0; s < subjects; s++ {
		key := gateway.SubjectKeyParts("t", "u"+string(rune('a'+s)), "corp")
		for i := 0; i < tries; i++ {
			wg.Add(1)
			go func(k string) {
				defer wg.Done()
				if err := l.WithSubjectSlot(k, func() error {
					okCount.Add(1)
					return nil
				}); err == nil {
					return
				}
			}(key)
		}
	}
	wg.Wait()
	if okCount.Load() == 0 {
		t.Fatal("expected some successful slots")
	}
	_, pn := l.InUse("")
	if pn != 0 {
		t.Fatalf("leaked process slots: %d", pn)
	}
}

func TestSubjectLimiter_StatusMapSecretFree(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(2, 8)
	key := gateway.SubjectKeyParts("secret-tenant", "secret-sub", "corp")
	_ = l.Acquire(key)
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
	l.Release(key)
}

func TestResolveSubjectLimiterCaps(t *testing.T) {
	t.Parallel()
	per, proc, err := gateway.ResolveSubjectLimiterCaps("", "")
	if err != nil {
		t.Fatal(err)
	}
	if per != gateway.DefaultMaxConcurrentPerSubject || proc != gateway.DefaultProcessConcurrentSlots {
		t.Fatalf("defaults: per=%d proc=%d", per, proc)
	}
	per, proc, err = gateway.ResolveSubjectLimiterCaps("4", "16")
	if err != nil {
		t.Fatal(err)
	}
	if per != 4 || proc != 16 {
		t.Fatalf("override: per=%d proc=%d", per, proc)
	}
	if _, _, err := gateway.ResolveSubjectLimiterCaps("-1", ""); err == nil {
		t.Fatal("negative per-subject must fail closed")
	}
	if _, _, err := gateway.ResolveSubjectLimiterCaps("x", ""); err == nil {
		t.Fatal("non-integer must fail closed")
	}
	if gateway.EnvSubjectMaxConcurrent != "JENKINS_MCP_SUBJECT_MAX_CONCURRENT" {
		t.Fatalf("env name: %q", gateway.EnvSubjectMaxConcurrent)
	}
	if gateway.EnvSubjectProcessMaxConcurrent != "JENKINS_MCP_SUBJECT_PROCESS_MAX_CONCURRENT" {
		t.Fatalf("process env name: %q", gateway.EnvSubjectProcessMaxConcurrent)
	}
}

func TestSubjectLimiter_AbsoluteCeilingsClamped(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(10_000, 10_000)
	if l.MaxPerSubject() > gateway.AbsoluteMaxConcurrentPerSubject {
		t.Fatal("per-subject abs not clamped")
	}
	if l.ProcessMax() > gateway.AbsoluteMaxProcessConcurrentSlots {
		t.Fatal("process abs not clamped")
	}
	// Defaults when non-positive.
	d := gateway.NewSubjectLimiter(0, 0)
	if d.MaxPerSubject() != gateway.DefaultMaxConcurrentPerSubject {
		t.Fatalf("default per subject=%d", d.MaxPerSubject())
	}
	if d.ProcessMax() != gateway.DefaultProcessConcurrentSlots {
		t.Fatalf("default process=%d", d.ProcessMax())
	}
}

// HOST-006 residual lite: MaxSubjects=0 (default) never bounds the subject map
// and Release drops zeroed entries (no idle retention).
func TestSubjectLimiter_MaxSubjectsUnlimitedDefault(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(4, 64)
	if l.MaxSubjects() != 0 {
		t.Fatalf("default MaxSubjects=%d want 0", l.MaxSubjects())
	}
	for i := 0; i < 40; i++ {
		key := gateway.SubjectKeyParts("t", fmt.Sprintf("u%02d", i), "p")
		if err := l.Acquire(key); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		l.Release(key)
	}
	// Unlimited path deletes on full release → map empty.
	if l.SubjectsTracked() != 0 {
		t.Fatalf("unlimited after release tracked=%d want 0", l.SubjectsTracked())
	}
	st := l.StatusMap()
	if _, ok := st["subject_limiter_max_subjects"]; ok {
		t.Fatalf("unlimited must omit subject_limiter_max_subjects: %+v", st)
	}
}

// HOST-006 residual lite: MaxSubjects evicts idle (0 in-use) oldest lastAccess.
// Subjects still holding slots are never stolen.
func TestSubjectLimiter_MaxSubjectsEvictOldestIdle(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(2, 16)
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

	if err := l.Acquire(k1); err != nil {
		t.Fatal(err)
	}
	l.Release(k1) // idle retained under MaxSubjects
	clock.Store(base.Add(time.Second))
	if err := l.Acquire(k2); err != nil {
		t.Fatal(err)
	}
	l.Release(k2)
	if l.SubjectsTracked() != 2 {
		t.Fatalf("tracked idle=%d want 2", l.SubjectsTracked())
	}
	clock.Store(base.Add(2 * time.Second))
	if err := l.Acquire(k3); err != nil {
		t.Fatal(err)
	}
	// k1 oldest idle evicted; k2 idle + k3 active remain (or k2 dropped if only room for k3).
	if n := l.SubjectsTracked(); n > 2 {
		t.Fatalf("after eviction tracked=%d want <=2", n)
	}
	// k3 must hold one slot.
	sn, _ := l.InUse(k3)
	if sn != 1 {
		t.Fatalf("k3 inUse=%d", sn)
	}
	l.Release(k3)

	st := l.StatusMap()
	if st["subject_limiter_max_subjects"] != 2 {
		t.Fatalf("status max: %+v", st)
	}
	if strings.Contains(fmt.Sprint(st), "u1") || strings.Contains(fmt.Sprint(st), "u2") {
		t.Fatalf("StatusMap leaked subject keys: %+v", st)
	}
}

// When every tracked subject still holds slots, MaxSubjects fails closed —
// never steals live holders (safer than wrong-subject elevation).
func TestSubjectLimiter_MaxSubjectsFailClosedAllHolders(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(2, 16)
	l.SetMaxSubjects(2)
	k1 := gateway.SubjectKeyParts("t", "hold1", "p")
	k2 := gateway.SubjectKeyParts("t", "hold2", "p")
	k3 := gateway.SubjectKeyParts("t", "new", "p")
	if err := l.Acquire(k1); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(k2); err != nil {
		t.Fatal(err)
	}
	err := l.Acquire(k3)
	if err == nil {
		t.Fatal("must fail closed when map full of live holders")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%s want quota", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "subject map") {
		t.Fatalf("want subject map budget message: %v", err)
	}
	// Live holders unchanged.
	sn1, pn := l.InUse(k1)
	sn2, _ := l.InUse(k2)
	if sn1 != 1 || sn2 != 1 || pn != 2 {
		t.Fatalf("holders corrupted: k1=%d k2=%d process=%d", sn1, sn2, pn)
	}
	// Release one → idle can be evicted for new subject.
	l.Release(k1)
	if err := l.Acquire(k3); err != nil {
		t.Fatalf("after idle free: %v", err)
	}
	l.Release(k2)
	l.Release(k3)
}

// Re-Acquire of an existing subject under MaxSubjects does not grow the map.
func TestSubjectLimiter_MaxSubjectsExistingDoesNotGrow(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(4, 16)
	l.SetMaxSubjects(2)
	base := time.Unix(1_700_100_000, 0).UTC()
	var clock atomic.Value
	clock.Store(base)
	l.SetNow(func() time.Time { return clock.Load().(time.Time) })

	k1 := gateway.SubjectKeyParts("t", "a", "p")
	k2 := gateway.SubjectKeyParts("t", "b", "p")
	if err := l.Acquire(k1); err != nil {
		t.Fatal(err)
	}
	clock.Store(base.Add(time.Second))
	if err := l.Acquire(k2); err != nil {
		t.Fatal(err)
	}
	// Touch k1 many times with acquire/release — still 2 subjects tracked.
	for i := 0; i < 5; i++ {
		clock.Store(base.Add(time.Duration(2+i) * time.Second))
		if err := l.Acquire(k1); err != nil {
			t.Fatalf("re-acquire k1: %v", err)
		}
		l.Release(k1)
	}
	if l.SubjectsTracked() != 2 {
		t.Fatalf("tracked=%d want 2", l.SubjectsTracked())
	}
	// Release remaining holds (initial k1 + k2); idle retained under MaxSubjects.
	l.Release(k1)
	l.Release(k2)
	if l.SubjectsTracked() != 2 {
		t.Fatalf("idle retained tracked=%d want 2", l.SubjectsTracked())
	}
	sn1, pn := l.InUse(k1)
	sn2, _ := l.InUse(k2)
	if sn1 != 0 || sn2 != 0 || pn != 0 {
		t.Fatalf("want all idle: k1=%d k2=%d process=%d", sn1, sn2, pn)
	}
}

// Alice/Bob concurrent isolation still holds when MaxSubjects is configured.
func TestSubjectLimiter_MaxSubjectsAliceBobIsolation(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(2, 10)
	l.SetMaxSubjects(8)
	alice := gateway.SubjectKeyParts("t1", "alice", "corp")
	bob := gateway.SubjectKeyParts("t1", "bob", "corp")
	if err := l.Acquire(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(alice); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(alice); err == nil {
		t.Fatal("alice third must fail at per-subject cap")
	}
	if err := l.Acquire(bob); err != nil {
		t.Fatalf("bob isolated under MaxSubjects: %v", err)
	}
	l.Release(alice)
	l.Release(alice)
	l.Release(bob)
}

// Concurrent Acquire/Release under MaxSubjects must not race (go test -race).
func TestSubjectLimiter_MaxSubjectsConcurrent(t *testing.T) {
	t.Parallel()
	l := gateway.NewSubjectLimiter(4, 32)
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
				if err := l.WithSubjectSlot(k, func() error {
					okCount.Add(1)
					return nil
				}); err == nil {
					return
				}
			}(key)
		}
	}
	wg.Wait()
	if okCount.Load() == 0 {
		t.Fatal("expected some successful slots")
	}
	if n := l.SubjectsTracked(); n > 4 {
		t.Fatalf("tracked=%d exceeds MaxSubjects=4", n)
	}
	_, pn := l.InUse("")
	if pn != 0 {
		t.Fatalf("leaked process slots: %d", pn)
	}
}

func TestResolveSubjectLimiterMaxSubjects(t *testing.T) {
	t.Parallel()
	n, err := gateway.ResolveSubjectLimiterMaxSubjects("")
	if err != nil || n != 0 {
		t.Fatalf("empty: n=%d err=%v", n, err)
	}
	n, err = gateway.ResolveSubjectLimiterMaxSubjects("  ")
	if err != nil || n != 0 {
		t.Fatalf("blank: n=%d err=%v", n, err)
	}
	n, err = gateway.ResolveSubjectLimiterMaxSubjects("4096")
	if err != nil || n != 4096 {
		t.Fatalf("4096: n=%d err=%v", n, err)
	}
	n, err = gateway.ResolveSubjectLimiterMaxSubjects("0")
	if err != nil || n != 0 {
		t.Fatalf("explicit 0 unlimited: n=%d err=%v", n, err)
	}
	if _, err := gateway.ResolveSubjectLimiterMaxSubjects("-1"); err == nil {
		t.Fatal("negative must fail closed")
	}
	if _, err := gateway.ResolveSubjectLimiterMaxSubjects("x"); err == nil {
		t.Fatal("non-int must fail closed")
	}
	if gateway.EnvGatewaySubjectLimiterMaxSubjects != "JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS" {
		t.Fatalf("env name: %q", gateway.EnvGatewaySubjectLimiterMaxSubjects)
	}
	n, err = gateway.SubjectLimiterMaxSubjectsFromEnviron(func(k string) string {
		if k == gateway.EnvGatewaySubjectLimiterMaxSubjects {
			return "64"
		}
		return ""
	})
	if err != nil || n != 64 {
		t.Fatalf("from environ: n=%d err=%v", n, err)
	}
	_, err = gateway.SubjectLimiterMaxSubjectsFromEnviron(func(k string) string {
		if k == gateway.EnvGatewaySubjectLimiterMaxSubjects {
			return "nope"
		}
		return ""
	})
	if err == nil {
		t.Fatal("invalid from environ must fail closed")
	}
}
