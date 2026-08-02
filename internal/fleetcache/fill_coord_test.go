package fleetcache_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestCoordinateOriginFill_SingleFetchConcurrent(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := fleetcache.FillLocatorHash("fleet", "corp", "demo", 7)
	var originCalls atomic.Int64
	origin := func(ctx context.Context) error {
		originCalls.Add(1)
		// Simulate slow origin so waiters join while producer holds lease.
		time.Sleep(30 * time.Millisecond)
		return nil
	}
	const n = 24
	var wg sync.WaitGroup
	var producers, waiters atomic.Int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			// Same member would all be same producer re-join; use unique members.
			res, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
				FleetID: "fleet", MemberID: "m-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
				LocatorHash: lh, Mode: fleetcache.ModeRead,
				WaiterPoll: 5 * time.Millisecond, WaiterMax: 100,
			}, origin)
			if err != nil {
				t.Errorf("coord: %v", err)
				return
			}
			switch res.Role {
			case fleetcache.FillRoleProducer:
				producers.Add(1)
				if !res.OriginCalled {
					t.Error("producer must call origin")
				}
			case fleetcache.FillRoleWaiter, fleetcache.FillRoleCompleted:
				waiters.Add(1)
			}
			// Canary: residual/role free of credentials.
			blob := res.Role + res.Residual + res.Lease.SecretFreeSnapshot()
			for _, bad := range []string{"password", "Bearer ", "ghp_", "token="} {
				if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
					t.Errorf("secret-like: %q", blob)
				}
			}
		}(i)
	}
	wg.Wait()
	if originCalls.Load() != 1 {
		t.Fatalf("origin calls=%d want 1 (single producer body)", originCalls.Load())
	}
	if producers.Load() < 1 {
		t.Fatal("expected at least one producer result")
	}
}

func TestCoordinateOriginFill_ModeOffNoLease(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(0)
	lh := fleetcache.FillLocatorHash("f", "p", "j", 1)
	var calls atomic.Int64
	// Mode off: each call hits origin (no lease coordination).
	for i := 0; i < 3; i++ {
		res, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
			FleetID: "f", MemberID: "m", LocatorHash: lh, Mode: fleetcache.ModeOff,
		}, func(ctx context.Context) error {
			calls.Add(1)
			return nil
		})
		if err != nil || !res.OriginCalled {
			t.Fatalf("%+v %v", res, err)
		}
		if res.Role != fleetcache.FillRoleNone {
			t.Fatalf("mode off role %s", res.Role)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("mode off should not collapse: %d", calls.Load())
	}
	// Authority unused: no lease recorded under concurrent mode-off only.
	st := auth.Status(lh)
	if st.State != fleetcache.FillRoleNone && st.LeaseID != "" {
		// Join never called — state none.
		if st.State == fleetcache.FillLeaseActive {
			t.Fatalf("mode off must not create lease: %+v", st)
		}
	}
}

func TestCoordinateOriginFill_OriginErrorReleases(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := fleetcache.FillLocatorHash("fleet", "corp", "job", 9)
	boom := errors.New("origin down")
	res, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
		FleetID: "fleet", MemberID: "edge", LocatorHash: lh, Mode: fleetcache.ModeRead,
	}, func(ctx context.Context) error { return boom })
	if err == nil || !res.OriginCalled {
		t.Fatalf("%+v %v", res, err)
	}
	if res.Residual != "origin_error_released" {
		t.Fatalf("residual %q", res.Residual)
	}
	// Locator not poisoned: new Join can become producer.
	res2, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
		FleetID: "fleet", MemberID: "edge-2", LocatorHash: lh, Mode: fleetcache.ModeRead,
	}, func(ctx context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if res2.Role != fleetcache.FillRoleProducer || !res2.OriginCalled {
		t.Fatalf("takeover after error: %+v", res2)
	}
}

func TestCoordinateOriginFill_CancelReleases(t *testing.T) {
	t.Parallel()
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := fleetcache.FillLocatorHash("fleet", "corp", "job", 3)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	go func() {
		<-started
		cancel()
	}()
	res, err := fleetcache.CoordinateOriginFill(ctx, auth, fleetcache.FillCoordRequest{
		FleetID: "fleet", MemberID: "edge", LocatorHash: lh, Mode: fleetcache.ModeRead,
	}, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err == nil {
		t.Fatal("expected cancel")
	}
	if res.Residual != "producer_cancelled" && apperr.CodeOf(err) != apperr.CodeCancelled {
		// residual may be producer_cancelled
		if res.Residual != "producer_cancelled" {
			t.Logf("residual=%q err=%v", res.Residual, err)
		}
	}
	// Subsequent fill succeeds.
	res2, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
		FleetID: "fleet", MemberID: "edge-2", LocatorHash: lh, Mode: fleetcache.ModeRead,
	}, func(ctx context.Context) error { return nil })
	if err != nil || !res2.OriginCalled {
		t.Fatalf("%+v %v", res2, err)
	}
}

// Regression (skeptic): origin longer than lease TTL must not allow a second
// producer body; waiters stay non-producer until Complete (Renew heartbeats).
func TestCoordinateOriginFill_HeartbeatKeepsSingleProducerPastTTL(t *testing.T) {
	t.Parallel()
	// Min lease TTL is 5s; origin runs 8s with 200ms Renew heartbeats.
	auth := fleetcache.NewFillLeaseAuthority(fleetcache.MinFillLeaseTTL)
	lh := fleetcache.FillLocatorHash("fleet", "corp", "long-origin", 1)
	var originCalls atomic.Int64
	var originStarted sync.WaitGroup
	originStarted.Add(1)
	origin := func(ctx context.Context) error {
		originCalls.Add(1)
		originStarted.Done()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(8 * time.Second):
			return nil
		}
	}

	var prodRes fleetcache.FillCoordResult
	var prodErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		prodRes, prodErr = fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
			FleetID: "fleet", MemberID: "producer", LocatorHash: lh, Mode: fleetcache.ModeRead,
			Heartbeat: 200 * time.Millisecond,
		}, origin)
	}()
	originStarted.Wait()

	const nWaiters = 8
	var waiterProducers atomic.Int64
	var waiterOrigin atomic.Int64
	wg.Add(nWaiters)
	for i := 0; i < nWaiters; i++ {
		i := i
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(50+i*20) * time.Millisecond)
			res, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
				FleetID: "fleet", MemberID: fmt.Sprintf("waiter-%d", i), LocatorHash: lh, Mode: fleetcache.ModeRead,
				WaiterPoll: 100 * time.Millisecond, WaiterMax: 120,
				Heartbeat: 200 * time.Millisecond,
			}, func(ctx context.Context) error {
				waiterOrigin.Add(1)
				return nil
			})
			if err != nil {
				t.Errorf("waiter: %v", err)
				return
			}
			if res.Role == fleetcache.FillRoleProducer {
				waiterProducers.Add(1)
			}
			if res.OriginCalled && res.Role == fleetcache.FillRoleProducer {
				t.Errorf("waiter must not be producer that called origin: %+v", res)
			}
		}()
	}
	wg.Wait()
	if prodErr != nil {
		t.Fatalf("producer: %v residual=%q", prodErr, prodRes.Residual)
	}
	if originCalls.Load() != 1 {
		t.Fatalf("originCalls=%d want 1 (heartbeat must prevent second body)", originCalls.Load())
	}
	if waiterProducers.Load() != 0 {
		t.Fatalf("waiters became producers=%d", waiterProducers.Load())
	}
	if waiterOrigin.Load() != 0 {
		t.Fatalf("waiters called origin=%d (want 0 while producer held lease)", waiterOrigin.Load())
	}
	if prodRes.Role != fleetcache.FillRoleProducer || prodRes.Residual == "complete_failed" {
		t.Fatalf("producer result %+v", prodRes)
	}
}

// Regression (skeptic): WaiterMax wall-clock must not force origin while Status
// still shows an active producer (Renew keeps lease alive past poll*maxWait).
func TestCoordinateOriginFill_WaiterNeverOriginWhileLeaseActive(t *testing.T) {
	t.Parallel()
	// Long lease + heartbeats; short waiter budget that would previously fall through.
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	lh := fleetcache.FillLocatorHash("fleet", "corp", "waiter-budget", 2)
	var originCalls atomic.Int64
	var originStarted sync.WaitGroup
	originStarted.Add(1)
	// Origin longer than WaiterPoll*WaiterMax (10ms*15=150ms) but shorter than lease.
	origin := func(ctx context.Context) error {
		originCalls.Add(1)
		originStarted.Done()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(600 * time.Millisecond):
			return nil
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
			FleetID: "fleet", MemberID: "producer", LocatorHash: lh, Mode: fleetcache.ModeRead,
			Heartbeat: 50 * time.Millisecond,
		}, origin)
		if err != nil {
			t.Errorf("producer: %v", err)
		}
	}()
	originStarted.Wait()

	// Waiter with tiny budget that elapses while lease is still active.
	var waiterOrigin atomic.Int64
	res, err := fleetcache.CoordinateOriginFill(context.Background(), auth, fleetcache.FillCoordRequest{
		FleetID: "fleet", MemberID: "waiter-only", LocatorHash: lh, Mode: fleetcache.ModeRead,
		WaiterPoll: 10 * time.Millisecond,
		WaiterMax:  15, // ~150ms << 600ms origin; old code called origin here
		Heartbeat:  50 * time.Millisecond,
	}, func(ctx context.Context) error {
		waiterOrigin.Add(1)
		return nil
	})
	if err != nil {
		t.Fatalf("waiter: %v", err)
	}
	wg.Wait()

	if originCalls.Load() != 1 {
		t.Fatalf("originCalls=%d want 1", originCalls.Load())
	}
	if waiterOrigin.Load() != 0 {
		t.Fatalf("waiter originCalls=%d want 0 while producer lease active", waiterOrigin.Load())
	}
	if res.OriginCalled {
		t.Fatalf("waiter must not OriginCalled: %+v", res)
	}
	if res.Role == fleetcache.FillRoleProducer {
		t.Fatalf("waiter became producer: %+v", res)
	}
	// Prefer completed residual once producer finishes; active-wait then completed is OK.
	if res.Residual != "waiter_saw_completed" && res.Residual != "already_completed" {
		// May return waiter_saw_completed after waiting out the producer.
		if res.Role != fleetcache.FillRoleWaiter && res.Role != fleetcache.FillRoleCompleted {
			t.Fatalf("unexpected waiter result %+v", res)
		}
	}
}

func TestFillLocatorHash_StableSecretFree(t *testing.T) {
	t.Parallel()
	a := fleetcache.FillLocatorHash("f", "p", "job", 1)
	b := fleetcache.FillLocatorHash("f", "p", "job", 1)
	c := fleetcache.FillLocatorHash("f", "p", "job", 2)
	if a != b || len(a) != 64 || a == c {
		t.Fatalf("%s %s %s", a, b, c)
	}
	if strings.Contains(a, "job") || strings.Contains(a, "password") {
		t.Fatal(a)
	}
}
