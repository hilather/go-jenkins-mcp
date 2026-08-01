package jenkins_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// fakeMetrics is a concurrent-safe MetricsHook for unit tests (OBS-001 / Wave 27).
type fakeMetrics struct {
	wire         atomic.Int64
	decoded      atomic.Int64
	requests     atomic.Int64
	errors       atomic.Int64
	circuitOpens atomic.Int64
}

func (f *fakeMetrics) AddWire(n int64) {
	if n > 0 {
		f.wire.Add(n)
	}
}
func (f *fakeMetrics) AddDecoded(n int64) {
	if n > 0 {
		f.decoded.Add(n)
	}
}
func (f *fakeMetrics) IncRequest()          { f.requests.Add(1) }
func (f *fakeMetrics) IncError()            { f.errors.Add(1) }
func (f *fakeMetrics) IncCircuitOpenEvent() { f.circuitOpens.Add(1) }

func TestCallJenkins_MetricsHookOK(t *testing.T) {
	t.Parallel()
	body := []byte(`{"ok":true}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	fm := &fakeMetrics{}
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "u",
		Token:  "t",
		Client: srv.Client(),
	}
	c.WithResilience(jenkins.ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})
	c.WithMetrics(fm)

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("body=%q", got)
	}
	if fm.requests.Load() != 1 {
		t.Fatalf("requests=%d want 1", fm.requests.Load())
	}
	if fm.errors.Load() != 0 {
		t.Fatalf("errors=%d want 0", fm.errors.Load())
	}
	if fm.wire.Load() < int64(len(body)) || fm.decoded.Load() < int64(len(body)) {
		t.Fatalf("wire=%d decoded=%d want ≥%d", fm.wire.Load(), fm.decoded.Load(), len(body))
	}
}

func TestCallJenkins_MetricsHookHTTPError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	fm := &fakeMetrics{}
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "u",
		Token:  "t",
		Client: srv.Client(),
	}
	c.WithResilience(jenkins.ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})
	c.WithMetrics(fm)

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/missing", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if fm.requests.Load() != 1 {
		t.Fatalf("requests=%d want 1", fm.requests.Load())
	}
	if fm.errors.Load() != 1 {
		t.Fatalf("errors=%d want 1 (status 404)", fm.errors.Load())
	}
}

func TestCallJenkins_MetricsHookTransportError(t *testing.T) {
	t.Parallel()
	// Closed server → connection refused / transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	fm := &fakeMetrics{}
	c := &jenkins.Client{
		URL:    url,
		User:   "u",
		Token:  "t",
		Client: http.DefaultClient,
	}
	c.WithResilience(jenkins.ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})
	c.WithMetrics(fm)

	_, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if fm.requests.Load() != 1 {
		t.Fatalf("requests=%d want 1", fm.requests.Load())
	}
	if fm.errors.Load() != 1 {
		t.Fatalf("errors=%d want 1", fm.errors.Load())
	}
}

func TestCallJenkins_NilMetricsHook(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "u",
		Token:  "t",
		Client: srv.Client(),
	}
	c.WithResilience(jenkins.ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})
	// Explicit nil is a no-op (must not panic).
	c.WithMetrics(nil)

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}

// Regression OBS Wave 27: circuit open transitions increment MetricsHook once per open episode.
func TestCircuitBreaker_MetricsOpenEvents(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	fm := &fakeMetrics{}
	c := &jenkins.Client{
		URL:    srv.URL,
		User:   "u",
		Token:  "t",
		Client: srv.Client(),
	}
	c.WithResilience(jenkins.ResilienceConfig{
		MaxRetries:              0,
		MaxJSONBodyBytes:        1 << 20,
		CircuitFailureThreshold: 3,
		CircuitOpenDuration:     time.Hour,
	})
	c.WithMetrics(fm)

	for i := 0; i < 3; i++ {
		resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if st := c.CircuitState(); st.State != "open" {
		t.Fatalf("state=%s want open", st.State)
	}
	if got := fm.circuitOpens.Load(); got != 1 {
		t.Fatalf("circuit open events=%d want 1 (single transition into open)", got)
	}

	// Further open-blocked calls must not fire another open event.
	_, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err == nil {
		t.Fatal("expected ErrCircuitOpen")
	}
	if got := fm.circuitOpens.Load(); got != 1 {
		t.Fatalf("after blocked call open events=%d want still 1", got)
	}
}

// Transport failure at threshold 1 still counts a single open event (MetricsHook wired).
func TestCircuitBreaker_MetricsOpenEvents_TransportFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	fm := &fakeMetrics{}
	c := &jenkins.Client{
		URL:    url,
		User:   "u",
		Token:  "t",
		Client: http.DefaultClient,
	}
	c.WithResilience(jenkins.ResilienceConfig{
		CircuitFailureThreshold: 1,
		CircuitOpenDuration:     time.Hour,
		MaxRetries:              0,
		MaxJSONBodyBytes:        1 << 20,
	})
	c.WithMetrics(fm)

	_, _ = c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if c.CircuitState().State != "open" {
		t.Fatalf("want open after transport failure, got %s", c.CircuitState().State)
	}
	if got := fm.circuitOpens.Load(); got != 1 {
		t.Fatalf("open events=%d want 1", got)
	}
	// Nil hook rebind must not panic on further open transitions.
	c.WithMetrics(nil)
}

func TestWithMetrics_FansOutExistingByteCounters(t *testing.T) {
	t.Parallel()
	body := []byte("hello-fanout")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	atomicBC := &jenkins.AtomicByteCounters{}
	fm := &fakeMetrics{}
	c, err := jenkins.NewClientWithTransport(srv.URL, "u", "t", jenkins.TransportConfig{
		ByteCounters:          atomicBC,
		APIClientTimeout:      0,
		LogsClientTimeout:     0,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.WithResilience(jenkins.ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})
	c.WithMetrics(fm)

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if atomicBC.Wire.Load() < int64(len(body)) {
		t.Fatalf("atomic wire=%d", atomicBC.Wire.Load())
	}
	if fm.wire.Load() < int64(len(body)) {
		t.Fatalf("hook wire=%d", fm.wire.Load())
	}
	if fm.requests.Load() != 1 {
		t.Fatalf("requests=%d", fm.requests.Load())
	}
}
