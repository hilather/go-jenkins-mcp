package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
)

func TestParseJWKSRefreshTTL(t *testing.T) {
	t.Parallel()
	t.Run("empty_default", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseJWKSRefreshTTL("")
		if err != nil || d != auth.DefaultJWKSRefreshTTL {
			t.Fatalf("got %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSRefreshTTL("0")
		if err != nil || d != auth.DefaultJWKSRefreshTTL {
			t.Fatalf("zero: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSRefreshTTL("0s")
		if err != nil || d != auth.DefaultJWKSRefreshTTL {
			t.Fatalf("0s: %v err=%v", d, err)
		}
	})
	t.Run("min_max_ok", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseJWKSRefreshTTL(auth.MinJWKSRefreshTTL.String())
		if err != nil || d != auth.MinJWKSRefreshTTL {
			t.Fatalf("min: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSRefreshTTL(auth.MaxJWKSRefreshTTL.String())
		if err != nil || d != auth.MaxJWKSRefreshTTL {
			t.Fatalf("max: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSRefreshTTL("5m")
		if err != nil || d != 5*time.Minute {
			t.Fatalf("5m: %v err=%v", d, err)
		}
	})
	t.Run("fail_closed_bounds", func(t *testing.T) {
		t.Parallel()
		if _, err := auth.ParseJWKSRefreshTTL("29s"); err == nil {
			t.Fatal("below min should fail")
		}
		if _, err := auth.ParseJWKSRefreshTTL("61m"); err == nil {
			t.Fatal("above max should fail")
		}
		if _, err := auth.ParseJWKSRefreshTTL("-1s"); err == nil {
			t.Fatal("negative should fail")
		}
		if _, err := auth.ParseJWKSRefreshTTL("not-a-duration"); err == nil {
			t.Fatal("garbage should fail")
		}
	})
}

func TestStaticJWKS(t *testing.T) {
	t.Parallel()
	if auth.NewStaticJWKS(nil) != nil {
		t.Fatal("nil set")
	}
	if auth.NewStaticJWKS(&auth.JWKS{}) != nil {
		t.Fatal("empty keys")
	}
	_, jwks := testRSAJWKS(t, "static-1")
	src := auth.NewStaticJWKS(jwks)
	got, err := src.Get(context.Background())
	if err != nil || got == nil || len(got.Keys) != 1 || got.Keys[0].Kid != "static-1" {
		t.Fatalf("got %+v err=%v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = src.Get(ctx)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("cancel: %v", err)
	}
}

func TestRefreshingJWKS_RotateKid(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "kid-v1")
	_, j2 := testRSAJWKS(t, "kid-v2")

	var mu sync.Mutex
	doc := j1
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		mu.Lock()
		cur := doc
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cur)
	}))
	t.Cleanup(srv.Close)

	// Controllable clock: start at t0, advance past TTL to force refresh.
	var clockMu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client: srv.Client(),
		URI:    srv.URL + "/jwks",
		TTL:    30 * time.Second,
		Now:    nowFn,
		Logf:   func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.StopBackground)

	if hits.Load() != 1 {
		t.Fatalf("initial fetch hits=%d", hits.Load())
	}
	got, err := src.Get(context.Background())
	if err != nil || got.Keys[0].Kid != "kid-v1" {
		t.Fatalf("before rotate: %+v err=%v", got, err)
	}
	// Within TTL: no re-fetch.
	got, err = src.Get(context.Background())
	if err != nil || got.Keys[0].Kid != "kid-v1" {
		t.Fatalf("within TTL: %+v err=%v", got, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("within TTL should not re-fetch hits=%d", hits.Load())
	}

	// Rotate remote JWKS to new kid.
	mu.Lock()
	doc = j2
	mu.Unlock()
	advance(31 * time.Second)

	got, err = src.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Keys[0].Kid != "kid-v2" {
		t.Fatalf("after rotate want kid-v2 got %q", got.Keys[0].Kid)
	}
	if hits.Load() < 2 {
		t.Fatalf("expected refresh fetch hits=%d", hits.Load())
	}
}

func TestRefreshingJWKS_FailedRefreshKeepsOld(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "keep-me")

	var mu sync.Mutex
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		shouldFail := fail
		mu.Unlock()
		if shouldFail {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("outage"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)

	var clockMu sync.Mutex
	now := time.Unix(1_700_000_100, 0)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	var logBuf strings.Builder
	var logMu sync.Mutex

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client: srv.Client(),
		URI:    srv.URL,
		TTL:    30 * time.Second,
		Now:    nowFn,
		Logf: func(format string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			logBuf.WriteString(strings.TrimSpace(format) + "\n")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Induce outage and expire TTL.
	mu.Lock()
	fail = true
	mu.Unlock()
	clockMu.Lock()
	now = now.Add(40 * time.Second)
	clockMu.Unlock()

	got, err := src.Get(context.Background())
	if err != nil {
		t.Fatalf("stale-if-error should return last good: %v", err)
	}
	if got == nil || got.Keys[0].Kid != "keep-me" {
		t.Fatalf("want last good kid keep-me: %+v", got)
	}
	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logged, "jwks refresh failed") {
		t.Fatalf("expected non-secret refresh failure log, got %q", logged)
	}
	// Canary: outage body must not be treated as secret, but JWKS n/e material
	// should not appear in log format either (we only log err).
	if strings.Contains(logged, "outage") {
		// FetchJWKS error is status code only — ok if not present; if present still no key material.
	}
	if strings.Contains(logged, j1.Keys[0].N) {
		t.Fatalf("Regression: modulus in log: %q", logged)
	}

	// ForceRefresh failure also keeps old.
	if err := src.ForceRefresh(context.Background()); err == nil {
		t.Fatal("expected force refresh error during outage")
	}
	snap := src.Snapshot()
	if snap == nil || snap.Keys[0].Kid != "keep-me" {
		t.Fatalf("snapshot after failed force: %+v", snap)
	}
}

func TestRefreshingJWKS_CancelContext(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "k1")
	// Block handler until test cancels... use a server that hangs.
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		// Hang until request context done.
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	// Initial fetch needs success: use a second quick server then switch? Simpler:
	// first construct with a good server, then test Get cancel on Static and
	// NewRefreshingJWKS init cancel separately.

	// Init cancel:
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := auth.NewRefreshingJWKS(ctx, auth.RefreshingJWKSConfig{
		Client: srv.Client(),
		URI:    srv.URL,
		TTL:    30 * time.Second,
		Logf:   func(string, ...any) {},
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("init cancel: %v", err)
	}

	// Successful init with immediate-respond server.
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(good.Close)

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client: good.Client(),
		URI:    good.URL,
		TTL:    30 * time.Second,
		Logf:   func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, err = src.Get(ctx2)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("Get cancel: %v", err)
	}
}

func TestRefreshingJWKS_InitialFetchFailClosed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	_, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client: srv.Client(),
		URI:    srv.URL,
		TTL:    30 * time.Second,
		Logf:   func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("initial fetch must fail closed")
	}
}

func TestParseJWKSMaxStaleAge(t *testing.T) {
	t.Parallel()
	t.Run("empty_unlimited", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseJWKSMaxStaleAge("")
		if err != nil || d != 0 {
			t.Fatalf("empty: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSMaxStaleAge("0")
		if err != nil || d != 0 {
			t.Fatalf("0: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSMaxStaleAge("0s")
		if err != nil || d != 0 {
			t.Fatalf("0s: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSMaxStaleAge("  ")
		if err != nil || d != 0 {
			t.Fatalf("whitespace: %v err=%v", d, err)
		}
	})
	t.Run("min_max_ok", func(t *testing.T) {
		t.Parallel()
		d, err := auth.ParseJWKSMaxStaleAge(auth.MinJWKSMaxStaleAge.String())
		if err != nil || d != auth.MinJWKSMaxStaleAge {
			t.Fatalf("min: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSMaxStaleAge(auth.MaxJWKSMaxStaleAge.String())
		if err != nil || d != auth.MaxJWKSMaxStaleAge {
			t.Fatalf("max: %v err=%v", d, err)
		}
		d, err = auth.ParseJWKSMaxStaleAge("15m")
		if err != nil || d != 15*time.Minute {
			t.Fatalf("15m: %v err=%v", d, err)
		}
	})
	t.Run("fail_closed_bounds", func(t *testing.T) {
		t.Parallel()
		if _, err := auth.ParseJWKSMaxStaleAge("59s"); err == nil {
			t.Fatal("below min should fail")
		}
		if _, err := auth.ParseJWKSMaxStaleAge("25h"); err == nil {
			t.Fatal("above max should fail")
		}
		if _, err := auth.ParseJWKSMaxStaleAge("-1m"); err == nil {
			t.Fatal("negative should fail")
		}
		if _, err := auth.ParseJWKSMaxStaleAge("not-a-duration"); err == nil {
			t.Fatal("garbage should fail")
		}
	})
}

func TestRefreshingJWKS_MaxStaleAgeFailClosed(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "old")
	var mu sync.Mutex
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		shouldFail := fail
		mu.Unlock()
		if shouldFail {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)

	var clockMu sync.Mutex
	now := time.Unix(1_700_000_200, 0)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	var logBuf strings.Builder
	var logMu sync.Mutex
	logf := func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logBuf.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n")
	}

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:      srv.Client(),
		URI:         srv.URL,
		TTL:         30 * time.Second,
		MaxStaleAge: 2 * time.Minute,
		Now:         nowFn,
		Logf:        logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	if src.MaxStaleAge() != 2*time.Minute {
		t.Fatalf("MaxStaleAge accessor: %v", src.MaxStaleAge())
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	// Past TTL but within max stale → last good ok (stale-if-error still works).
	clockMu.Lock()
	now = now.Add(40 * time.Second)
	clockMu.Unlock()
	got, err := src.Get(context.Background())
	if err != nil || got.Keys[0].Kid != "old" {
		t.Fatalf("within max stale: %+v err=%v", got, err)
	}
	logMu.Lock()
	withinLog := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(withinLog, "stale-if-error") {
		t.Fatalf("within window should log stale-if-error, got %q", withinLog)
	}
	if strings.Contains(withinLog, "max stale age exceeded") {
		t.Fatalf("within window must not fail-closed log: %q", withinLog)
	}
	// Beyond max stale + still failing → fail closed.
	clockMu.Lock()
	now = now.Add(3 * time.Minute)
	clockMu.Unlock()
	_, err = src.Get(context.Background())
	if err == nil {
		t.Fatal("max stale exceeded must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want CodeAuthentication got %v err=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "max stale age exceeded") {
		t.Fatalf("error should mention max stale: %v", err)
	}
	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logged, "max stale age exceeded") || !strings.Contains(logged, "fail closed") {
		t.Fatalf("expected secret-free max-stale fail-closed log, got %q", logged)
	}
	// Canary: no JWKS key material in log.
	if strings.Contains(logged, j1.Keys[0].N) || strings.Contains(logged, j1.Keys[0].E) {
		t.Fatalf("Regression: JWKS key material in max-stale log: %q", logged)
	}
	// Unlimited (MaxStaleAge=0) still serves after a long outage window.
	mu.Lock()
	fail = false
	mu.Unlock()
	clock2 := time.Unix(1_700_100_000, 0)
	var clock2Mu sync.Mutex
	src2, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client: srv.Client(),
		URI:    srv.URL,
		TTL:    30 * time.Second,
		// MaxStaleAge 0 = unlimited
		Now: func() time.Time {
			clock2Mu.Lock()
			defer clock2Mu.Unlock()
			return clock2
		},
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	clock2Mu.Lock()
	clock2 = clock2.Add(4 * time.Hour)
	clock2Mu.Unlock()
	got, err = src2.Get(context.Background())
	if err != nil || got.Keys[0].Kid != "old" {
		t.Fatalf("unlimited max stale should keep last good: %+v err=%v", got, err)
	}
}

func TestNewRefreshingJWKS_MaxStaleAgeBounds(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "k")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)
	_, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:      srv.Client(),
		URI:         srv.URL,
		TTL:         30 * time.Second,
		MaxStaleAge: 30 * time.Second, // below min
		Logf:        func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("below min max-stale must fail at construction")
	}
	_, err = auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:      srv.Client(),
		URI:         srv.URL,
		TTL:         30 * time.Second,
		MaxStaleAge: 48 * time.Hour, // above max
		Logf:        func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("above max max-stale must fail at construction")
	}
}
