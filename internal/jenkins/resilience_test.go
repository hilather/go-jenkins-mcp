package jenkins

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryPolicyClassify(t *testing.T) {
	cases := []struct {
		method string
		status int
		err    error
		want   bool
	}{
		{http.MethodGet, 503, nil, true},
		{http.MethodGet, 429, nil, true},
		{http.MethodGet, 502, nil, true},
		{http.MethodHead, 504, nil, true},
		{http.MethodGet, 200, nil, false},
		{http.MethodGet, 404, nil, false},
		{http.MethodGet, 500, nil, false}, // 500 not in classifyRetryStatus set
		{http.MethodPost, 503, nil, false},
		{http.MethodPost, 0, errors.New("dial"), false},
		{http.MethodGet, 0, errors.New("dial"), true},
		{http.MethodGet, 0, context.Canceled, false},
		{http.MethodGet, 0, ErrCrossOrigin, false},
	}
	for _, tc := range cases {
		got, reason := RetryPolicyClassify(tc.method, tc.status, tc.err)
		if got != tc.want {
			t.Errorf("method=%s status=%d err=%v: got %v (%s), want %v",
				tc.method, tc.status, tc.err, got, reason, tc.want)
		}
	}
}

// TestIsIdempotentRetryMethod documents NET-003: only GET/HEAD auto-retry.
func TestIsIdempotentRetryMethod(t *testing.T) {
	t.Parallel()
	for _, m := range []string{http.MethodGet, http.MethodHead, "get", "HEAD", " Get "} {
		if !IsIdempotentRetryMethod(m) {
			t.Errorf("IsIdempotentRetryMethod(%q) = false, want true", m)
		}
	}
	for _, m := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
		"POST", "post", "", "OPTIONS", "TRACE", "CONNECT",
	} {
		if IsIdempotentRetryMethod(m) {
			t.Errorf("IsIdempotentRetryMethod(%q) = true, want false (no auto-retry)", m)
		}
	}
}

func TestCallJenkins_GETRetriesOn503(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("unavailable"))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	res := NewResilience(ResilienceConfig{
		MaxRetries:       3,
		MaxJSONBodyBytes: 1 << 20,
		InitialBackoff:   time.Millisecond,
		MaxBackoff:       5 * time.Millisecond,
	})
	// Deterministic zero jitter for speed.
	res.intn = func(n int64) int64 { return 0 }
	res.sleep = func(ctx context.Context, d time.Duration) error { return nil }
	c.res = res

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d, want 3", hits.Load())
	}
}

func TestCallJenkins_GETHonorsRetryAfter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	var slept time.Duration
	res := NewResilience(ResilienceConfig{
		MaxRetries:       2,
		MaxJSONBodyBytes: 1 << 20,
		InitialBackoff:   time.Hour, // would be huge without Retry-After path
		MaxBackoff:       5 * time.Second,
	})
	res.sleep = func(ctx context.Context, d time.Duration) error {
		slept = d
		return nil
	}
	c.res = res

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if slept != 2*time.Second {
		t.Fatalf("slept = %v, want 2s from Retry-After", slept)
	}
}

func TestCallJenkins_POSTNoRetryOn503(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	c.WithResilience(ResilienceConfig{
		MaxRetries:       5,
		MaxJSONBodyBytes: 1 << 20,
		InitialBackoff:   time.Millisecond,
	})

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/job/x/build", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("POST hits = %d, want 1 (no auto-retry)", hits.Load())
	}
}

func TestCallJenkins_BodyLimitExcess(t *testing.T) {
	// 200 bytes of JSON-ish payload; limit to 50.
	payload := strings.Repeat("a", 200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	c.WithResilience(ResilienceConfig{
		MaxRetries:       0,
		MaxJSONBodyBytes: 50,
	})

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("ReadAll err = %v, want ErrBodyTooLarge", err)
	}
}

func TestCallJenkins_LogPathSkipsJSONBodyLimit(t *testing.T) {
	// Progressive path uses closeConn=true → no JSON MaxJSONBodyBytes wrapper.
	// Application caps remain LOG-001 (readLimited / request length).
	payload := strings.Repeat("L", 1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Text-Size", "1000")
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client(), LogsClient: srv.Client()}
	// Tiny JSON limit would break logs if wrongly applied to progressive bodies.
	c.WithResilience(ResilienceConfig{
		MaxRetries:       0,
		MaxJSONBodyBytes: 10,
	})

	resp, err := c.callJenkins(context.Background(), c.LogsClient, http.MethodGet,
		"/job/demo/1/logText/progressiveText?start=0", nil,
		map[string]string{"Accept": "text/plain"}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Without limitedBody, can read past MaxJSONBodyBytes (10).
	data, err := io.ReadAll(io.LimitReader(resp.Body, 100))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 100 {
		t.Fatalf("len = %d, want 100 (log path not capped by MaxJSONBodyBytes)", len(data))
	}
}

// Regression OBS Wave 27: onFailure fires onCircuitOpen once per open episode (fake resilience).
func TestCircuitBreaker_OpenHookCountsOnce(t *testing.T) {
	t.Parallel()
	var opens atomic.Int32
	res := NewResilience(ResilienceConfig{
		CircuitFailureThreshold: 3,
		CircuitOpenDuration:     time.Hour,
	})
	res.onCircuitOpen = func() { opens.Add(1) }

	res.onFailure() // 1 — still closed
	res.onFailure() // 2 — still closed
	if opens.Load() != 0 {
		t.Fatalf("opens before threshold = %d", opens.Load())
	}
	res.onFailure() // 3 — open
	if opens.Load() != 1 {
		t.Fatalf("opens at threshold = %d want 1", opens.Load())
	}
	// Already open: further failures must not re-count.
	res.onFailure()
	res.onFailure()
	if opens.Load() != 1 {
		t.Fatalf("opens while already open = %d want 1", opens.Load())
	}
	if st := res.State(); st.State != "open" {
		t.Fatalf("state = %s", st.State)
	}

	// Half-open probe failure re-opens and counts again.
	now := res.now()
	res.now = func() time.Time { return now.Add(2 * time.Hour) }
	if err := res.allow(); err != nil {
		t.Fatalf("allow half-open: %v", err)
	}
	if st := res.State(); st.State != "half-open" {
		t.Fatalf("want half-open, got %s", st.State)
	}
	res.onFailure()
	if opens.Load() != 2 {
		t.Fatalf("opens after half-open fail = %d want 2", opens.Load())
	}
}

func TestCircuitBreaker_OpensAfterFailures(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	res := NewResilience(ResilienceConfig{
		MaxRetries:              0, // one attempt per CallJenkins
		MaxJSONBodyBytes:        1 << 20,
		CircuitFailureThreshold: 3,
		CircuitOpenDuration:     time.Hour,
	})
	c.res = res

	for i := 0; i < 3; i++ {
		resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	st := c.CircuitState()
	if st.State != "open" {
		t.Fatalf("state = %s, want open (failures=%d)", st.State, st.ConsecutiveFailures)
	}

	// Next call fails fast without hitting server.
	before := hits.Load()
	_, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("err = %v, want ErrCircuitOpen", err)
	}
	if hits.Load() != before {
		t.Fatalf("breaker open still hit server: hits %d → %d", before, hits.Load())
	}
}

func TestCircuitBreaker_RecoversAfterOpenDuration(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	now := time.Now()
	// Wave 49: normalize clamps open duration to ≥ MinCircuitOpenDuration (1s).
	res := NewResilience(ResilienceConfig{
		MaxRetries:              0,
		MaxJSONBodyBytes:        1 << 20,
		CircuitFailureThreshold: 1,
		CircuitOpenDuration:     MinCircuitOpenDuration,
	})
	res.now = func() time.Time { return now }
	c.res = res

	// Force open via onFailure path with 502 from a prior server — inject state.
	res.onFailure()
	if c.CircuitState().State != "open" {
		t.Fatalf("want open, got %s", c.CircuitState().State)
	}

	// Advance clock past open duration (virtual clock; no wall sleep).
	now = now.Add(MinCircuitOpenDuration + time.Millisecond)
	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if c.CircuitState().State != "closed" {
		t.Fatalf("after success state = %s", c.CircuitState().State)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestLimitedBody_ExactSizeOK(t *testing.T) {
	payload := []byte("exact!")
	rc := io.NopCloser(strings.NewReader(string(payload)))
	lb := newLimitedBody(rc, int64(len(payload)))
	data, err := io.ReadAll(lb)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("data = %q", data)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d, ok := parseRetryAfter("3", now)
	if !ok || d != 3*time.Second {
		t.Fatalf("seconds: %v %v", d, ok)
	}
	// HTTP-date in the future
	future := now.Add(7 * time.Second).UTC().Format(http.TimeFormat)
	d, ok = parseRetryAfter(future, now)
	if !ok || d < 6*time.Second || d > 8*time.Second {
		t.Fatalf("http-date: %v %v", d, ok)
	}
	_, ok = parseRetryAfter("not-a-date", now)
	if ok {
		t.Fatal("expected parse failure")
	}
}

func TestConcurrencySemaphore(t *testing.T) {
	block := make(chan struct{})
	entered := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-block
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: "t", Client: srv.Client()}
	c.WithResilience(ResilienceConfig{
		MaxRetries:       0,
		MaxJSONBodyBytes: 1 << 20,
		MaxConcurrent:    1,
	})

	ctx := context.Background()
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			resp, err := c.CallJenkins(ctx, c.Client, http.MethodGet, "/api/json", nil, nil)
			if resp != nil {
				_ = resp.Body.Close()
			}
			done <- err
		}()
	}

	// Only one should enter the handler while block is closed.
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not enter")
	}
	select {
	case <-entered:
		t.Fatal("second request entered while MaxConcurrent=1")
	case <-time.After(50 * time.Millisecond):
		// expected: second waits on semaphore
	}
	close(block)
	// Drain second entry and both completions.
	<-entered
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestResilienceExportedDefaults(t *testing.T) {
	t.Parallel()
	if DefaultMaxJSONBodyBytes != 32<<20 {
		t.Fatalf("DefaultMaxJSONBodyBytes=%d want 32MiB", DefaultMaxJSONBodyBytes)
	}
	if AbsoluteMaxJSONBodyBytes != 128<<20 {
		t.Fatalf("AbsoluteMaxJSONBodyBytes=%d want 128MiB", AbsoluteMaxJSONBodyBytes)
	}
	if AbsoluteMaxJSONBodyBytes < DefaultMaxJSONBodyBytes {
		t.Fatalf("AbsoluteMaxJSONBodyBytes %d < DefaultMaxJSONBodyBytes %d",
			AbsoluteMaxJSONBodyBytes, DefaultMaxJSONBodyBytes)
	}
	if DefaultMaxRetries != 2 {
		t.Fatalf("DefaultMaxRetries=%d want 2", DefaultMaxRetries)
	}
	if DefaultMaxRetries < 0 {
		t.Fatal("DefaultMaxRetries must be non-negative (0 disables auto-retry)")
	}
	if DefaultCircuitFailureThreshold != 5 {
		t.Fatalf("DefaultCircuitFailureThreshold=%d want 5", DefaultCircuitFailureThreshold)
	}
	if DefaultCircuitFailureThreshold <= 0 {
		t.Fatal("DefaultCircuitFailureThreshold must be positive")
	}
	// Wave 48: absolute circuit ceiling + exported open duration.
	if AbsoluteMaxRetries != 10 {
		t.Fatalf("AbsoluteMaxRetries=%d want 10", AbsoluteMaxRetries)
	}
	if AbsoluteMaxRetries < DefaultMaxRetries {
		t.Fatalf("AbsoluteMaxRetries %d < DefaultMaxRetries %d", AbsoluteMaxRetries, DefaultMaxRetries)
	}
	if AbsoluteMaxCircuitFailureThreshold != 50 {
		t.Fatalf("AbsoluteMaxCircuitFailureThreshold=%d want 50", AbsoluteMaxCircuitFailureThreshold)
	}
	if AbsoluteMaxCircuitFailureThreshold < DefaultCircuitFailureThreshold {
		t.Fatalf("AbsoluteMaxCircuitFailureThreshold %d < DefaultCircuitFailureThreshold %d",
			AbsoluteMaxCircuitFailureThreshold, DefaultCircuitFailureThreshold)
	}
	if DefaultCircuitOpenDuration != 15*time.Second {
		t.Fatalf("DefaultCircuitOpenDuration=%v want 15s", DefaultCircuitOpenDuration)
	}
	if DefaultCircuitOpenDuration <= 0 {
		t.Fatal("DefaultCircuitOpenDuration must be positive")
	}
	// Wave 50: MaxConcurrent default unlimited + absolute fail-closed ceiling.
	if DefaultMaxConcurrent != 0 {
		t.Fatalf("DefaultMaxConcurrent=%d want 0 (unlimited)", DefaultMaxConcurrent)
	}
	if AbsoluteMaxConcurrent != 256 {
		t.Fatalf("AbsoluteMaxConcurrent=%d want 256", AbsoluteMaxConcurrent)
	}
	if AbsoluteMaxConcurrent <= 0 {
		t.Fatal("AbsoluteMaxConcurrent must be positive")
	}
	if DefaultMaxConcurrent > AbsoluteMaxConcurrent {
		t.Fatalf("DefaultMaxConcurrent %d > AbsoluteMaxConcurrent %d",
			DefaultMaxConcurrent, AbsoluteMaxConcurrent)
	}
	cfg := DefaultResilienceConfig()
	if cfg.MaxJSONBodyBytes != DefaultMaxJSONBodyBytes {
		t.Fatalf("DefaultResilienceConfig MaxJSONBodyBytes=%d", cfg.MaxJSONBodyBytes)
	}
	if cfg.MaxRetries != DefaultMaxRetries {
		t.Fatalf("DefaultResilienceConfig MaxRetries=%d", cfg.MaxRetries)
	}
	if cfg.CircuitFailureThreshold != DefaultCircuitFailureThreshold {
		t.Fatalf("DefaultResilienceConfig CircuitFailureThreshold=%d", cfg.CircuitFailureThreshold)
	}
	if cfg.CircuitOpenDuration != DefaultCircuitOpenDuration {
		t.Fatalf("DefaultResilienceConfig CircuitOpenDuration=%v", cfg.CircuitOpenDuration)
	}
	if cfg.MaxConcurrent != DefaultMaxConcurrent {
		t.Fatalf("DefaultResilienceConfig MaxConcurrent=%d", cfg.MaxConcurrent)
	}
}
