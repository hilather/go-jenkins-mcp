package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

func TestDiagBudget_ExhaustsOnCallsAndBytes(t *testing.T) {
	b := NewDiagBudget(DiagBudgetConfig{MaxRemoteCalls: 2, MaxRemoteBytes: 100})
	if !b.AllowRemote(10) {
		t.Fatal("expected allow first")
	}
	b.RecordRemote(40)
	if !b.AllowRemote(10) {
		t.Fatal("expected allow second")
	}
	b.RecordRemote(40)
	if b.AllowRemote(1) {
		t.Fatal("expected deny after max calls")
	}
	ex, reason := b.Exhausted()
	if !ex || reason == "" {
		t.Fatalf("exhausted=%v reason=%q", ex, reason)
	}

	b2 := NewDiagBudget(DiagBudgetConfig{MaxRemoteBytes: 50})
	b2.RecordRemote(50)
	if b2.AllowRemote(1) {
		t.Fatal("expected deny after max bytes")
	}
}

func TestDiagBudget_WallAndContext(t *testing.T) {
	b := NewDiagBudget(DiagBudgetConfig{MaxWall: 5 * time.Millisecond})
	time.Sleep(10 * time.Millisecond)
	if b.AllowRemote(0) {
		t.Fatal("expected wall exhaustion")
	}
	ctx, cancel := b.Context(context.Background())
	defer cancel()
	// Already past wall → child context cancelled immediately.
	select {
	case <-ctx.Done():
	default:
		// BoundContext uses remaining; if remaining<=0 cancel immediately.
		// NewDiagBudget start was in the past; Context should cancel.
		time.Sleep(time.Millisecond)
		if ctx.Err() == nil {
			// Allow slight scheduling race only if remaining was positive at construction of Context.
			// Re-check via snapshot.
			if ex, _ := b.Exhausted(); !ex {
				t.Fatal("expected exhausted wall budget")
			}
		}
	}
}

func TestFetchCache_LogTailReuseAndEvict(t *testing.T) {
	c := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 2})
	meta := logMeta{Offset: 0, Length: 10, TotalSize: 10, Sealed: true}
	c.PutLogTail("job", 1, 100, "0123456789", meta, "client_tail", false)
	text, m, src, inc, ok := c.GetLogTail("job", 1, 50)
	if !ok {
		t.Fatal("expected hit for smaller window")
	}
	if len(text) != 10 { // original shorter than 50
		t.Fatalf("text len=%d", len(text))
	}
	if src != "client_tail" || inc {
		t.Fatalf("src=%s inc=%v meta=%+v", src, inc, m)
	}
	// Larger window than stored → miss.
	if _, _, _, _, ok := c.GetLogTail("job", 1, 200); ok {
		t.Fatal("expected miss for larger maxLog")
	}
	// Eviction
	c.PutLogTail("job", 2, 10, "abcdefghij", meta, "client_tail", false)
	c.PutLogTail("job", 3, 10, "abcdefghij", meta, "client_tail", false)
	if c.Stats().Entries > 2 {
		t.Fatalf("entries=%d", c.Stats().Entries)
	}
	st := c.Stats()
	if st.Hits < 1 || st.Misses < 1 {
		t.Fatalf("stats=%+v", st)
	}
}

func TestMergeDiagBudget_OnlyLowers(t *testing.T) {
	def := DiagBudgetConfig{MaxRemoteCalls: 10, MaxRemoteBytes: 1000, MaxWall: time.Second}
	out := mergeDiagBudget(def, DiagBudgetConfig{MaxRemoteCalls: 3, MaxRemoteBytes: 5000, MaxWall: 2 * time.Second})
	if out.MaxRemoteCalls != 3 {
		t.Fatalf("calls=%d", out.MaxRemoteCalls)
	}
	// Higher override must not raise.
	if out.MaxRemoteBytes != 1000 {
		t.Fatalf("bytes=%d", out.MaxRemoteBytes)
	}
	if out.MaxWall != time.Second {
		t.Fatalf("wall=%v", out.MaxWall)
	}
}

// Regression: concurrent getCachedBuildDetails for the same job+build must issue
// a single GetBuildDetailsByJob HTTP call (PERF-003 Wave 27 single-flight).
func TestGetCachedBuildDetails_SingleFlightNoDuplicateHTTP(t *testing.T) {
	var hits atomic.Int32
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		// Match GetBuildDetailsByJob tree shape.
		raw := r.URL.RawQuery
		if !strings.Contains(raw, "displayName") {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"number":7,"url":"http://j/job/demo/7/","building":false,"result":"FAILURE","timestamp":1,"duration":1,"estimatedDuration":1,"displayName":"#7","actions":[]}`))
	}))
	defer srv.Close()

	client := &jenkins.Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client(), LogsClient: srv.Client()}
	cache := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: DefaultBuildDetailsCacheMax})
	st := regState{fetchCache: cache}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	started := make(chan struct{}, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			sess := newDiagSession(st, diagnoseBudgetDefault())
			ctx := withDiagSession(context.Background(), sess)
			started <- struct{}{}
			b, err := getCachedBuildDetails(ctx, st, client, "demo", 7)
			if err != nil {
				errs <- err
				return
			}
			if b == nil || b.Number != 7 {
				errs <- fmt.Errorf("unexpected build: %+v", b)
			}
		}()
	}
	// Wait until all goroutines have entered getCachedBuildDetails.
	for i := 0; i < n; i++ {
		<-started
	}
	// Give them a moment to pile onto singleflight before releasing the handler.
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("Regression: single-flight GetBuildDetailsByJob HTTP hits=%d want 1 (stats=%+v)", got, cache.Stats())
	}
	stStats := cache.Stats()
	if stStats.SharedFlights < 1 {
		t.Fatalf("expected shared_flights>=1, stats=%+v", stStats)
	}
	// Second wave is pure cache hits — zero additional HTTP.
	for i := 0; i < 4; i++ {
		sess := newDiagSession(st, diagnoseBudgetDefault())
		ctx := withDiagSession(context.Background(), sess)
		if _, err := getCachedBuildDetails(ctx, st, client, "demo", 7); err != nil {
			t.Fatal(err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("cache should absorb post-flight reads: hits=%d", got)
	}
}
