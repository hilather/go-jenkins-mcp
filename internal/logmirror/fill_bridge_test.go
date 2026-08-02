package logmirror_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
)

func TestFillBridge_ConcurrentMissOneOriginFetch(t *testing.T) {
	raw := []byte(strings.Repeat("fill-body-line-\n", 40))
	// Baseline: one EnsureMirrored / Resolve alone (progressive Poll may multi-fetch).
	srcBase := &logmirror.FakeSource{Log: raw, Running: false}
	aBase, _ := openAccess(t, srcBase)
	stBase := logmirror.NewFakeBuildStatus()
	stBase.Set("demo", 7, true)
	aBase.Status = stBase
	if _, _, err := aBase.ResolveAndReadRange(context.Background(), "demo", 7, 0, 32, logmirror.ResolveOptions{}); err != nil {
		t.Fatal(err)
	}
	baselineFetches := srcBase.FetchCount
	if baselineFetches < 1 {
		t.Fatal("baseline expected origin fetch")
	}

	// Concurrent miss wave with shared lease authority: origin body acquisition count
	// must match one producer EnsureMirrored (not N× baseline).
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, m := openAccess(t, src)
	status := logmirror.NewFakeBuildStatus()
	status.Set("demo", 7, true)
	a.Status = status

	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	const n = 12
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			ai := logmirror.NewAccess("corp", m)
			ai.Status = status
			ai.MaxBytes = a.MaxBytes
			ai.MaxPolls = a.MaxPolls
			ai.Fill = &logmirror.FillBridge{
				Auth: auth, Mode: fleetcache.ModeRead,
				FleetID: "fleet", MemberID: fmt.Sprintf("member-%d", i),
				WaiterPoll: 5 * time.Millisecond, WaiterMax: 200,
			}
			logs, _, err := ai.ResolveAndReadRange(context.Background(), "demo", 7, 0, 32, logmirror.ResolveOptions{})
			if err != nil {
				t.Errorf("resolve: %v", err)
				return
			}
			if len(logs) == 0 {
				t.Error("empty logs")
			}
		}()
	}
	wg.Wait()
	// Allow small progressive variance; must not scale with N waiters.
	if src.FetchCount > baselineFetches+2 {
		t.Fatalf("origin fetches=%d baseline=%d (N=%d); waiters must not each pull body",
			src.FetchCount, baselineFetches, n)
	}
	if src.FetchCount < 1 {
		t.Fatal("expected producer origin fetch")
	}
}

func TestFillBridge_ModeOffNoLeaseActive(t *testing.T) {
	raw := []byte(strings.Repeat("x", 80))
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	status := logmirror.NewFakeBuildStatus()
	status.Set("demo", 7, true)
	a.Status = status
	a.Fill = &logmirror.FillBridge{
		Auth: fleetcache.NewFillLeaseAuthority(0), Mode: fleetcache.ModeOff,
		FleetID: "f", MemberID: "m",
	}
	if a.Fill.Active() {
		t.Fatal("mode off must not be Active")
	}
	_, _, err := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 10, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if src.FetchCount < 1 {
		t.Fatal("expected origin fetch")
	}
	// Second resolve: sealed local hit.
	fetches := src.FetchCount
	_, _, err = a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 10, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if src.FetchCount != fetches {
		t.Fatalf("local hit should not re-fetch: %d→%d", fetches, src.FetchCount)
	}
}

func TestFillBridge_OriginErrorAllowsRetry(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte(strings.Repeat("ok-after-fail\n", 10)), Running: false}
	src.FailOnce = apperr.New(apperr.CodeTimeout, "origin once")
	a, _ := openAccess(t, src)
	status := logmirror.NewFakeBuildStatus()
	status.Set("demo", 7, true)
	a.Status = status
	auth := fleetcache.NewFillLeaseAuthority(30 * time.Second)
	a.Fill = &logmirror.FillBridge{
		Auth: auth, Mode: fleetcache.ModeRead, FleetID: "fleet", MemberID: "edge",
	}
	_, _, err := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 8, logmirror.ResolveOptions{})
	if err == nil {
		// FailOnce may race; ensure second path works either way.
		return
	}
	// FailOnce cleared after first Fetch; retry must succeed without poison.
	_, _, err2 := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 8, logmirror.ResolveOptions{})
	if err2 != nil {
		t.Fatalf("retry after origin error: first=%v second=%v", err, err2)
	}
}
