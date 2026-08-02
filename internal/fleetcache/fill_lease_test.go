package fleetcache_test

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestFillLease_SingleProducerHighConcurrency(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := strings.Repeat("ab", 32)
	const n = 64
	var producers atomic.Int64
	var waiters atomic.Int64
	var fences sync.Map // fence -> count
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			member := fmt.Sprintf("m-%d", i)
			res, err := auth.Join("fleet", lh, member)
			if err != nil {
				t.Errorf("join: %v", err)
				return
			}
			switch res.Role {
			case fleetcache.FillRoleProducer:
				producers.Add(1)
				fences.Store(res.Lease.Fence, true)
			case fleetcache.FillRoleWaiter:
				waiters.Add(1)
			default:
				t.Errorf("unexpected role %s", res.Role)
			}
		}()
	}
	wg.Wait()
	if producers.Load() != 1 {
		t.Fatalf("producers=%d want 1", producers.Load())
	}
	if waiters.Load() != int64(n-1) {
		t.Fatalf("waiters=%d want %d", waiters.Load(), n-1)
	}
	// Exactly one fence value for this concurrent wave.
	count := 0
	fences.Range(func(_, _ any) bool { count++; return true })
	if count != 1 {
		t.Fatalf("distinct fences=%d want 1", count)
	}
	st := auth.Status(lh)
	if st.State != fleetcache.FillLeaseActive || st.Fence == 0 {
		t.Fatalf("%+v", st)
	}
}

func TestFillLease_ExpiryTakeoverAndStaleFence(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(10 * time.Second)
	lh := strings.Repeat("cd", 32)
	// Fixed clock.
	var clock atomic.Int64
	base := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	auth.SetNow(func() time.Time {
		return base.Add(time.Duration(clock.Load()) * time.Second)
	})

	j1, err := auth.Join("fleet", lh, "producer-a")
	if err != nil || j1.Role != fleetcache.FillRoleProducer {
		t.Fatalf("%+v %v", j1, err)
	}
	fence1 := j1.Lease.Fence
	lease1 := j1.Lease.LeaseID

	// Before expiry, other member is waiter.
	j2, err := auth.Join("fleet", lh, "producer-b")
	if err != nil || j2.Role != fleetcache.FillRoleWaiter {
		t.Fatalf("%+v %v", j2, err)
	}
	if j2.Lease.Fence != fence1 {
		t.Fatal("waiter must observe same fence")
	}

	// Advance past expiry.
	clock.Store(15)
	j3, err := auth.Join("fleet", lh, "producer-b")
	if err != nil || j3.Role != fleetcache.FillRoleProducer {
		t.Fatalf("takeover %+v %v", j3, err)
	}
	if j3.Lease.Fence <= fence1 {
		t.Fatalf("takeover fence %d must exceed %d", j3.Lease.Fence, fence1)
	}
	if j3.Residual != "takeover_after_expiry" {
		t.Fatalf("residual %q", j3.Residual)
	}
	fence2 := j3.Lease.Fence
	lease2 := j3.Lease.LeaseID

	// Stale producer cannot complete with old fence.
	err = auth.Complete("fleet", lh, "producer-a", lease1, fence1, strings.Repeat("11", 32))
	if err == nil {
		t.Fatal("stale complete must fail")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}

	// Wrong member on new lease fails.
	err = auth.Complete("fleet", lh, "producer-a", lease2, fence2, strings.Repeat("22", 32))
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("wrong member: %v", err)
	}

	// New producer completes.
	digest := strings.Repeat("ab", 32)
	if err := auth.Complete("fleet", lh, "producer-b", lease2, fence2, digest); err != nil {
		t.Fatal(err)
	}
	// Stale still cannot overwrite.
	err = auth.Complete("fleet", lh, "producer-a", lease1, fence1, strings.Repeat("ff", 32))
	if err == nil {
		t.Fatal("stale after complete must fail")
	}
	st := auth.Status(lh)
	if st.State != fleetcache.FillLeaseCompleted || st.ManifestDigest != digest {
		t.Fatalf("%+v", st)
	}
	// Join after complete returns completed role.
	j4, err := auth.Join("fleet", lh, "producer-c")
	if err != nil || j4.Role != fleetcache.FillRoleCompleted {
		t.Fatalf("%+v %v", j4, err)
	}
	// Idempotent complete same fence.
	if err := auth.Complete("fleet", lh, "producer-b", lease2, fence2, digest); err != nil {
		t.Fatal(err)
	}
}

func TestFillLease_SecretFreeCanary(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(0)
	lh := strings.Repeat("ef", 32)
	// Reject secret-shaped member.
	_, err := auth.Join("fleet", lh, "Bearer super-secret-token")
	if err == nil {
		t.Fatal("expected secret-shaped reject")
	}
	j, err := auth.Join("fleet", lh, "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	snap := j.Lease.SecretFreeSnapshot()
	for _, bad := range []string{"password", "Bearer ", "ghp_", "authorization:", "token="} {
		if strings.Contains(strings.ToLower(snap), strings.ToLower(bad)) {
			t.Fatalf("secret-like in snapshot: %q contains %q", snap, bad)
		}
	}
	st := auth.Status(lh)
	stStr := fmt.Sprintf("%+v", st)
	for _, bad := range []string{"password", "Bearer ", "ghp_"} {
		if strings.Contains(stStr, bad) {
			t.Fatalf("status secret-like: %s", stStr)
		}
	}
	// Residual note documents partition honesty.
	if !strings.Contains(fleetcache.FillLeaseAuthorityResidual(), "partition") {
		t.Fatal(fleetcache.FillLeaseAuthorityResidual())
	}
	if !strings.Contains(fleetcache.FillLeaseAuthorityResidual(), "FLC-045") {
		t.Fatal("041 residual")
	}
}

func TestFillLease_ExpiredCannotCompleteWithoutTakeover(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(5 * time.Second)
	lh := strings.Repeat("11", 32)
	var clock atomic.Int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	auth.SetNow(func() time.Time { return base.Add(time.Duration(clock.Load()) * time.Second) })
	j, err := auth.Join("fleet", lh, "p1")
	if err != nil {
		t.Fatal(err)
	}
	clock.Store(10)
	err = auth.Complete("fleet", lh, "p1", j.Lease.LeaseID, j.Lease.Fence, strings.Repeat("00", 32))
	if err == nil {
		t.Fatal("expired complete must fail")
	}
	st := auth.Status(lh)
	if st.State != fleetcache.FillLeaseExpired {
		t.Fatalf("%+v", st)
	}
}
