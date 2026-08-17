package jenkins

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Regression: after the open period elapses, allow() must admit exactly one
// half-open probe. A second concurrent allow() while the probe is in flight
// must fail closed with ErrCircuitOpen; otherwise a thundering herd of queued
// requests all strike a possibly-still-down Jenkins at once (NET-003).
func TestCircuitBreaker_HalfOpenAdmitsSingleProbe(t *testing.T) {
	t.Parallel()
	res := NewResilience(ResilienceConfig{
		CircuitFailureThreshold: 1,
		CircuitOpenDuration:     time.Hour,
	})
	res.onFailure() // threshold 1 → open
	if st := res.State(); st.State != "open" {
		t.Fatalf("state = %s, want open", st.State)
	}

	// Advance past the open period.
	now := res.now()
	res.now = func() time.Time { return now.Add(2 * time.Hour) }

	if _, err := res.allow(); err != nil {
		t.Fatalf("first half-open probe must be admitted: %v", err)
	}
	if st := res.State(); st.State != "half-open" {
		t.Fatalf("state = %s, want half-open", st.State)
	}
	// Second concurrent caller must be rejected while the probe is in flight.
	if _, err := res.allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("concurrent probe during half-open = %v, want ErrCircuitOpen", err)
	}

	// Probe success closes the breaker; subsequent calls flow again.
	res.onSuccess()
	if _, err := res.allow(); err != nil {
		t.Fatalf("allow after probe success: %v", err)
	}
	if st := res.State(); st.State != "closed" {
		t.Fatalf("state = %s, want closed", st.State)
	}
}

// Regression: a failed half-open probe re-opens the breaker; after the next
// open period a fresh probe is admitted (single-probe gating must not wedge).
func TestCircuitBreaker_HalfOpenProbeFailureReopens(t *testing.T) {
	t.Parallel()
	res := NewResilience(ResilienceConfig{
		CircuitFailureThreshold: 1,
		CircuitOpenDuration:     time.Hour,
	})
	res.onFailure() // open

	base := res.now()
	res.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, err := res.allow(); err != nil {
		t.Fatalf("half-open probe: %v", err)
	}
	res.onFailure() // probe failed → re-open
	if st := res.State(); st.State != "open" {
		t.Fatalf("state after failed probe = %s, want open", st.State)
	}
	// Still inside the new open window: reject.
	if _, err := res.allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("allow during re-opened window = %v, want ErrCircuitOpen", err)
	}
	// After the new open period, a fresh probe is admitted.
	res.now = func() time.Time { return base.Add(4 * time.Hour) }
	if _, err := res.allow(); err != nil {
		t.Fatalf("probe after second open period: %v", err)
	}
}

// Regression (review follow-up): single-probe half-open gating must not wedge.
// Early exit paths AFTER allow() admits the probe (auth provider failure,
// backoff sleep abort, body-wrap error) previously left halfOpen=true forever
// — every later call returned ErrCircuitOpen and the breaker never recovered.
// The probe owner now releases the slot on all exit paths (defer onProbeDone).
func TestCircuitBreaker_ProbeSlotReleasedOnEarlyExits(t *testing.T) {
	t.Parallel()
	res := NewResilience(ResilienceConfig{
		CircuitFailureThreshold: 1,
		CircuitOpenDuration:     time.Hour,
	})
	res.onFailure() // open
	now := res.now()
	res.now = func() time.Time { return now.Add(2 * time.Hour) }

	// Probe admitted via a call that fails in applyAuth (before any Do).
	c := &Client{
		URL:    "http://127.0.0.1:9",
		Client: &http.Client{},
		AuthProvider: func() (string, string, AuthScheme, error) {
			return "", "", "", errors.New("refresh failed")
		},
	}
	c.res = res
	if _, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil); err == nil {
		t.Fatal("auth failure expected")
	}
	// The probe slot must be free again: a new probe is admitted.
	if _, err := res.allow(); err != nil {
		t.Fatalf("probe slot leaked after early exit: %v", err)
	}
	res.onProbeDone() // release the test's probe
	if _, err := res.allow(); err != nil {
		t.Fatalf("probe slot not reusable: %v", err)
	}
}

// Regression: caller-side context cancellation is not a Jenkins health signal.
// A cancelled in-flight request must not advance the circuit-breaker failure
// counter (previously every cancel counted as a 5xx-class failure, so a user
// cancelling N consecutive requests opened the breaker on a healthy Jenkins).
func TestCallJenkins_CallerCancelDoesNotTripCircuit(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	res := NewResilience(ResilienceConfig{
		MaxRetries:              0,
		CircuitFailureThreshold: 2,
		CircuitOpenDuration:     time.Hour,
	})
	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	c.res = res

	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // caller hangs up before the request runs
		_, err := c.CallJenkins(ctx, c.Client, http.MethodGet, "/api/json", nil, nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("attempt %d: err = %v, want context.Canceled", i, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("cancelled requests must not reach the wire; hits=%d", hits.Load())
	}
	if got := res.State().ConsecutiveFailures; got != 0 {
		t.Fatalf("caller cancellations counted as circuit failures: %d", got)
	}
	if st := res.State(); st.State != "closed" {
		t.Fatalf("circuit state = %s, want closed after pure caller cancels", st.State)
	}
}

// Regression: a caller-cancelled half-open probe must release the probe slot
// (onAbort) instead of counting as a failure that re-opens the breaker or
// wedging the half-open state forever.
func TestCallJenkins_CancelledHalfOpenProbeReleasesSlot(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	res := NewResilience(ResilienceConfig{
		MaxRetries:              0,
		CircuitFailureThreshold: 1,
		CircuitOpenDuration:     time.Hour,
	})
	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	c.res = res

	// Open the breaker with a real 5xx.
	ctx := context.Background()
	resp, err := c.CallJenkins(ctx, c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatalf("setup request: %v", err)
	}
	_ = resp.Body.Close()
	// Force the breaker open directly (threshold 1 via 503 path needs a failing
	// server; drive the state machine instead for determinism).
	res.onFailure()
	if st := res.State(); st.State != "open" {
		t.Fatalf("state = %s, want open", st.State)
	}

	// Advance past the open period and admit the probe via a cancelled request.
	now := res.now()
	res.now = func() time.Time { return now.Add(2 * time.Hour) }
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.CallJenkins(cancelledCtx, c.Client, http.MethodGet, "/api/json", nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	// The cancelled probe must neither re-open the breaker nor leave the
	// half-open slot stuck: a follow-up request (healthy server) proceeds.
	resp, err = c.CallJenkins(ctx, c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatalf("request after cancelled probe must proceed: %v", err)
	}
	_ = resp.Body.Close()
	if st := res.State(); st.State != "closed" {
		t.Fatalf("state = %s, want closed after healthy probe", st.State)
	}
}

// Regression: concurrent requests on the AuthProvider (OIDC refresh) path raced
// on Client.User/Token/AuthScheme — per-request write-back vs the read of the
// static fields. Run with -race: before the fix the detector flags the
// write/read pair in applyAuth. Also asserts the sync'd fields keep their
// documented post-call values.
func TestCallJenkins_AuthProviderConcurrentNoRace(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	var calls atomic.Int64
	c := &Client{
		URL:    srv.URL,
		User:   "stale",
		Token:  "stale",
		Client: srv.Client(),
		AuthProvider: func() (user, secret string, scheme AuthScheme, err error) {
			calls.Add(1)
			return "alice", "fresh-token", AuthSchemeBasic, nil
		},
	}

	const workers = 8
	const perWorker = 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
				if err != nil {
					t.Errorf("CallJenkins: %v", err)
					return
				}
				_ = resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	if calls.Load() != workers*perWorker {
		t.Fatalf("provider calls = %d, want %d", calls.Load(), workers*perWorker)
	}
	// Documented write-back still holds after concurrent refresh.
	if c.User != "alice" || c.Token != "fresh-token" || c.AuthScheme != AuthSchemeBasic {
		t.Fatalf("client fields not synced from provider: %+v", c.AuthScheme)
	}
}
