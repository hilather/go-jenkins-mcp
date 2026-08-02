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

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// QA-002 expand: deterministic Jenkins HTTP fault injection (no live Jenkins).
// Complements store/archive/logmirror chaos for network-facing client behavior.

const chaosSecretToken = "chaos-secret-token-NEVER-LEAK"

// TestChaosHTTP_TruncatedProgressiveLog_NoPanic ensures mid-stream close / short
// progressive bodies neither panic nor invent unbounded buffers; Offset/HasMore
// stay consistent with returned bytes and X-Text-Size when present.
func TestChaosHTTP_TruncatedProgressiveLog_NoPanic(t *testing.T) {
	t.Parallel()

	const partial = "line1\nline2\npartial-tail"
	const advertisedTotal = 10000

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.Contains(r.URL.Path, "/logText/progressiveText") {
			http.NotFound(w, r)
			return
		}
		// Advertise a large total then close after a short body (truncated progressive).
		w.Header().Set("X-Text-Size", "10000")
		w.Header().Set("X-More-Data", "true")
		w.Header().Set("Content-Type", "text/plain;charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(partial))
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer srv.Close()

	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      chaosSecretToken,
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	// Must not panic; partial success or clean error both acceptable.
	logs, err := c.GetBuildLogs(context.Background(), "demo", 1, 0, 8192)
	if err != nil {
		// Transport/body errors are OK for chaos; secret must never appear.
		assertNoSecretLeak(t, err.Error())
		return
	}
	if logs == nil {
		t.Fatal("nil logs without error")
	}
	if logs.Offset != 0 {
		t.Fatalf("Offset = %d, want 0", logs.Offset)
	}
	if logs.Length != len(logs.Logs) {
		t.Fatalf("Length=%d != len(Logs)=%d", logs.Length, len(logs.Logs))
	}
	if logs.Logs != partial {
		t.Fatalf("Logs = %q, want partial body %q", logs.Logs, partial)
	}
	// X-Text-Size and X-More-Data should surface more data remaining.
	if logs.TotalSize != advertisedTotal && logs.TotalSize != len(partial) {
		t.Fatalf("TotalSize=%d want %d or partial len", logs.TotalSize, advertisedTotal)
	}
	if logs.TotalSize == advertisedTotal && !logs.HasMore {
		t.Fatal("HasMore=false despite TotalSize >> returned length")
	}
	if hits.Load() < 1 {
		t.Fatal("expected at least one progressive request")
	}
	assertNoSecretLeak(t, logs.Logs)
}

// TestChaosHTTP_ProgressiveMidStreamReset covers abrupt TCP close after headers
// with zero body — client must error or return empty slice, never panic.
func TestChaosHTTP_ProgressiveMidStreamReset(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Text-Size", "5000")
		w.WriteHeader(http.StatusOK)
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close() // drop before any body bytes
			}
		}
	}))
	defer srv.Close()

	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      chaosSecretToken,
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	logs, err := c.GetBuildLogs(context.Background(), "demo", 2, 0, 1024)
	if err != nil {
		assertNoSecretLeak(t, err.Error())
		return
	}
	// Empty body with headers is acceptable: zero-length slice, HasMore from size.
	if logs == nil {
		t.Fatal("nil logs without error")
	}
	if logs.Length != len(logs.Logs) {
		t.Fatalf("Length mismatch: %d vs %d", logs.Length, len(logs.Logs))
	}
}

// TestChaosHTTP_SlowHandlerCancelledViaContext proves CallJenkins / progressive
// fetch honor context cancel without hanging (no multi-second sleeps).
func TestChaosHTTP_SlowHandlerCancelledViaContext(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		// Block until client cancels the request context.
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: chaosSecretToken, Client: srv.Client()}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		resp, err := c.CallJenkins(ctx, c.Client, http.MethodGet, "/api/json", nil, nil)
		if resp != nil {
			_ = resp.Body.Close()
		}
		errCh <- err
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("handler never entered")
	}
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error after cancel")
		}
		if !errors.Is(err, context.Canceled) {
			// Transport may wrap cancel; still must classify as cancelled.
			if apperr.CodeOf(err) != apperr.CodeCancelled && !strings.Contains(strings.ToLower(err.Error()), "cancel") {
				t.Fatalf("err = %v, want context.Canceled-ish", err)
			}
		}
		assertNoSecretLeak(t, err.Error())
	case <-time.After(2 * time.Second):
		t.Fatal("CallJenkins did not return after cancel (possible goroutine leak path)")
	}
}

// TestChaosHTTP_ProgressiveFetchCancelled covers GetBuildLogs cancel mid-hang.
func TestChaosHTTP_ProgressiveFetchCancelled(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      chaosSecretToken,
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := c.GetBuildLogs(ctx, "demo", 9, 0, 4096)
		errCh <- err
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("progressive handler never entered")
	}
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected cancel error from GetBuildLogs")
		}
		assertNoSecretLeak(t, err.Error())
	case <-time.After(2 * time.Second):
		t.Fatal("GetBuildLogs hung after cancel")
	}
}

// TestChaosHTTP_WrongContentLengthAndEmptyJSON_FailClosed ensures JSON endpoints
// reject empty/truncated bodies with stable failure surface and no secret leakage.
func TestChaosHTTP_WrongContentLengthAndEmptyJSON_FailClosed(t *testing.T) {
	t.Parallel()

	t.Run("empty_body_whoami", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// empty body
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, User: "u", Token: chaosSecretToken, Client: srv.Client()}
		c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

		_, err := c.WhoAmI(context.Background())
		if err == nil {
			t.Fatal("expected error on empty whoAmI JSON")
		}
		assertNoSecretLeak(t, err.Error())
		// Fail closed: do not invent identity.
		if strings.Contains(err.Error(), chaosSecretToken) {
			t.Fatal("secret leaked")
		}
	})

	t.Run("wrong_content_length_truncation", func(t *testing.T) {
		// Overstate Content-Length, write a short invalid JSON prefix, then hard-close.
		// Client must fail closed promptly (no multi-second hang).
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "500")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"partial":`))
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
		}))
		defer srv.Close()

		hc := srv.Client()
		if tr, ok := hc.Transport.(*http.Transport); ok {
			tr = tr.Clone()
			tr.DisableKeepAlives = true
			hc.Transport = tr
		}
		c := &Client{URL: srv.URL, User: "u", Token: chaosSecretToken, Client: hc}
		c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := c.WhoAmI(ctx)
		if err == nil {
			t.Fatal("expected error on wrong Content-Length / truncated JSON")
		}
		assertNoSecretLeak(t, err.Error())
	})

	t.Run("empty_test_report_upstream_protocol", func(t *testing.T) {
		// Path that maps decode failure to apperr.CodeUpstreamProtocol.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/testReport/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("")) // empty → invalid JSON
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		c := &Client{URL: srv.URL, User: "u", Token: chaosSecretToken, Client: srv.Client()}
		c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})
		// Skip capability probe: seed JUnit present.
		c.capCache = &CapabilitySet{
			JenkinsVersion: "2.462.3",
			HasJUnit:       true,
			Source:         CapabilitySourceCache,
			Fresh:          true,
			FetchedAt:      time.Now(),
			ExpiresAt:      time.Now().Add(time.Hour),
		}
		c.capCacheUntil = time.Now().Add(time.Hour)

		_, err := c.GetTestReport(context.Background(), "demo", 1, 10)
		if err == nil {
			t.Fatal("expected upstream_protocol on empty test report JSON")
		}
		if apperr.CodeOf(err) != apperr.CodeUpstreamProtocol {
			t.Fatalf("code = %s, want %s (%v)", apperr.CodeOf(err), apperr.CodeUpstreamProtocol, err)
		}
		assertNoSecretLeak(t, err.Error())
		assertNoSecretLeak(t, apperr.ModelMessage(err))
	})
}

// TestChaosHTTP_ConnectionResetOnMutationPOST_NoAutoRetry asserts StartJob /
// StopBuild POST paths are not auto-retried after connection reset (duplicate
// create/stop safety). GET retries remain covered in resilience_test.
func TestChaosHTTP_ConnectionResetOnMutationPOST_NoAutoRetry(t *testing.T) {
	t.Parallel()

	var postHits atomic.Int32
	var getHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHits.Add(1)
			// Crumb endpoint: claim disabled so StartJob proceeds to POST.
			if strings.Contains(r.URL.Path, "crumbIssuer") {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{}`)
		case http.MethodPost:
			postHits.Add(1)
			// Connection reset during mutation POST.
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
			// Fallback: close without response status.
			panic(http.ErrAbortHandler)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: chaosSecretToken, Client: srv.Client()}
	// High MaxRetries would only apply to GET; POST must stay at 1 attempt.
	c.WithResilience(ResilienceConfig{
		MaxRetries:       5,
		MaxJSONBodyBytes: 1 << 20,
		InitialBackoff:   time.Millisecond,
		MaxBackoff:       5 * time.Millisecond,
	})
	// Zero jitter / instant sleep if any GET retry path is taken.
	if c.res != nil {
		c.res.intn = func(n int64) int64 { return 0 }
		c.res.sleep = func(ctx context.Context, d time.Duration) error { return nil }
	}

	_, err := c.StartJob(context.Background(), "demo", map[string]any{"BRANCH": "main"})
	if err == nil {
		t.Fatal("expected StartJob error on connection reset")
	}
	assertNoSecretLeak(t, err.Error())
	if postHits.Load() != 1 {
		t.Fatalf("StartJob POST hits = %d, want 1 (no auto-retry of mutations)", postHits.Load())
	}

	// StopBuild likewise.
	postHits.Store(0)
	_, err = c.StopBuild(context.Background(), "demo", 7)
	if err == nil {
		t.Fatal("expected StopBuild error on connection reset")
	}
	assertNoSecretLeak(t, err.Error())
	if postHits.Load() != 1 {
		t.Fatalf("StopBuild POST hits = %d, want 1", postHits.Load())
	}
}

// TestChaosHTTP_GET429ThenSuccess_RetriesButPOSTDoesNot documents NET-003:
// resilience retries idempotent GET (honoring Retry-After); POST is never retried.
func TestChaosHTTP_GET429ThenSuccess_RetriesButPOSTDoesNot(t *testing.T) {
	t.Parallel()

	var getHits atomic.Int32
	var postHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postHits.Add(1)
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		n := getHits.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, User: "u", Token: chaosSecretToken, Client: srv.Client()}
	res := NewResilience(ResilienceConfig{
		MaxRetries:       2,
		MaxJSONBodyBytes: 1 << 20,
		InitialBackoff:   time.Millisecond,
		MaxBackoff:       10 * time.Millisecond,
	})
	res.intn = func(n int64) int64 { return 0 }
	res.sleep = func(ctx context.Context, d time.Duration) error { return nil }
	c.res = res

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatalf("GET after 429: %v", err)
	}
	_ = resp.Body.Close()
	if getHits.Load() < 2 {
		t.Fatalf("GET hits = %d, want >= 2 (retry after 429)", getHits.Load())
	}

	resp, err = c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/job/x/build", nil, nil)
	if err != nil {
		// POST returns response without transport error on 503.
		t.Fatalf("POST: unexpected transport err %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if postHits.Load() != 1 {
		t.Fatalf("POST hits = %d, want 1 (mutations never auto-retried)", postHits.Load())
	}
}

func assertNoSecretLeak(t *testing.T, s string) {
	t.Helper()
	if s == "" {
		return
	}
	// Credential material and common auth wire forms must never appear in errors/logs.
	for _, needle := range []string{
		chaosSecretToken,
		"secret-token",
		"Authorization:",
		"Basic ",
		"Bearer ",
	} {
		if strings.Contains(s, needle) {
			t.Fatalf("possible secret leak in %q (matched %q)", s, needle)
		}
	}
}
