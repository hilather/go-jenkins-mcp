package gateway_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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
