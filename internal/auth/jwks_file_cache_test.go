package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
)

func TestJWKSCachePathConfiguredFromEnviron(t *testing.T) {
	t.Parallel()
	if auth.JWKSCachePathConfiguredFromEnviron(func(string) string { return "" }) {
		t.Fatal("empty path → false")
	}
	if !auth.JWKSCachePathConfiguredFromEnviron(func(k string) string {
		if k == auth.EnvHTTPJWKSCachePath {
			return "/var/lib/jenkins-mcp/jwks.json"
		}
		return ""
	}) {
		t.Fatal("non-empty path → true")
	}
	// Path value must never be the return of the bool helper (compile-time bool).
}

func TestJWKSCachePathFromEnviron(t *testing.T) {
	t.Parallel()
	p, err := auth.JWKSCachePathFromEnviron(func(string) string { return "" })
	if err != nil || p != "" {
		t.Fatalf("empty: %q err=%v", p, err)
	}
	p, err = auth.JWKSCachePathFromEnviron(func(k string) string {
		if k == auth.EnvHTTPJWKSCachePath {
			return "  /tmp/jwks-cache.json  "
		}
		return ""
	})
	if err != nil || p != "/tmp/jwks-cache.json" {
		t.Fatalf("trimmed: %q err=%v", p, err)
	}
	if _, err := auth.JWKSCachePathFromEnviron(func(k string) string {
		if k == auth.EnvHTTPJWKSCachePath {
			return "."
		}
		return ""
	}); err == nil {
		t.Fatal("invalid path must fail closed")
	}
}

func TestRefreshingJWKS_FileCache_WriteRead(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "file-kid-1")
	path := filepath.Join(t.TempDir(), "jwks-cache.json")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)

	var clockMu sync.Mutex
	now := time.Unix(1_700_100_000, 0).UTC()
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    srv.Client(),
		URI:       srv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Now:       nowFn,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !src.CachePathConfigured() {
		t.Fatal("CachePathConfigured should be true")
	}

	// File written on successful initial fetch.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected cache file: %v", err)
	}
	if !strings.Contains(string(raw), "file-kid-1") {
		t.Fatalf("want kid in file: %s", raw)
	}
	// Mode 0600 (ignore umask edge on some FS; require owner-only write at least).
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache file must not be group/other accessible: %o", st.Mode().Perm())
	}

	// Second process: network down → init from file.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)

	src2, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    down.Client(),
		URI:       down.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Now:       nowFn,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("init from file should succeed: %v", err)
	}
	got, err := src2.Get(context.Background())
	if err != nil || got == nil || got.Keys[0].Kid != "file-kid-1" {
		t.Fatalf("file fallback Get: %+v err=%v", got, err)
	}
}

func TestRefreshingJWKS_FileCache_CorruptFailClosed(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "corrupt-jwks.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Network fails + corrupt file → init fail closed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	_, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    srv.Client(),
		URI:       srv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Logf:      func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("corrupt file must not satisfy init when fetch fails")
	}

	// Good init then corrupt file: refresh fail keeps memory last good.
	_, j1 := testRSAJWKS(t, "mem-keep")
	var mu sync.Mutex
	fail := false
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		shouldFail := fail
		mu.Unlock()
		if shouldFail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(good.Close)

	path2 := filepath.Join(t.TempDir(), "later-corrupt.json")
	var clockMu sync.Mutex
	now := time.Unix(1_700_200_000, 0)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    good.Client(),
		URI:       good.URL,
		TTL:       30 * time.Second,
		CachePath: path2,
		Now:       nowFn,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Poison the file after successful write.
	if err := os.WriteFile(path2, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	clockMu.Lock()
	now = now.Add(40 * time.Second)
	clockMu.Unlock()

	got, err := src.Get(context.Background())
	if err != nil {
		t.Fatalf("memory stale-if-error after corrupt file: %v", err)
	}
	if got.Keys[0].Kid != "mem-keep" {
		t.Fatalf("want mem-keep: %+v", got)
	}
}

func TestRefreshingJWKS_FileCache_MaxStaleRespected(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "stale-kid")
	path := filepath.Join(t.TempDir(), "stale-jwks.json")

	// Pre-write a snapshot with old fetched_at via a successful process then
	// freeze clock far past max stale for a second process with network down.
	var clockMu sync.Mutex
	now := time.Unix(1_700_300_000, 0).UTC()
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:      srv.Client(),
		URI:         srv.URL,
		TTL:         30 * time.Second,
		MaxStaleAge: 2 * time.Minute,
		CachePath:   path,
		Now:         nowFn,
		Logf:        func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = src

	// Advance past max stale; network fails → init must fail closed (file too old).
	clockMu.Lock()
	now = now.Add(3 * time.Minute)
	clockMu.Unlock()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)

	_, err = auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:      down.Client(),
		URI:         down.URL,
		TTL:         30 * time.Second,
		MaxStaleAge: 2 * time.Minute,
		CachePath:   path,
		Now:         nowFn,
		Logf:        func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("file snapshot past MaxStaleAge must fail closed on init")
	}
}

func TestRefreshingJWKS_FileCache_GetPrefersFileOnRefreshFail(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "v1")
	_, j2 := testRSAJWKS(t, "v2")
	path := filepath.Join(t.TempDir(), "share-jwks.json")

	var clockMu sync.Mutex
	now := time.Unix(1_700_400_000, 0).UTC()
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	// Reader process starts with v1 from network (writes v1 to file).
	var mu sync.Mutex
	doc := j1
	readerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cur := doc
		mu.Unlock()
		if cur == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(cur)
	}))
	t.Cleanup(readerSrv.Close)

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    readerSrv.Client(),
		URI:       readerSrv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Now:       nowFn,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Get(context.Background())
	if err != nil || got.Keys[0].Kid != "v1" {
		t.Fatalf("initial mem v1: %+v err=%v", got, err)
	}

	// Peer process publishes newer v2 into the shared file (same-host lite).
	clockMu.Lock()
	now = now.Add(10 * time.Second)
	clockMu.Unlock()
	writerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(j2)
	}))
	t.Cleanup(writerSrv.Close)
	writer, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    writerSrv.Client(),
		URI:       writerSrv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Now:       nowFn,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = writer

	// Reader outage + TTL expire → Get should pick file v2 from peer.
	mu.Lock()
	doc = nil
	mu.Unlock()
	clockMu.Lock()
	now = now.Add(40 * time.Second)
	clockMu.Unlock()

	got, err = src.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Keys[0].Kid != "v2" {
		t.Fatalf("want file v2 on refresh fail, got %q", got.Keys[0].Kid)
	}
}

// Regression: on refresh failure, an older same-host file snapshot must not
// replace newer in-memory keys (would re-surface rotated-out kids).
func TestRefreshingJWKS_FileCache_GetDoesNotRegressToOlderFile(t *testing.T) {
	t.Parallel()
	_, jNew := testRSAJWKS(t, "mem-new")
	_, jOld := testRSAJWKS(t, "file-old")
	path := filepath.Join(t.TempDir(), "older-file-jwks.json")

	var clockMu sync.Mutex
	now := time.Unix(1_700_450_000, 0).UTC()
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	// Plant an older public JWKS snapshot on disk (rotated-out kid only).
	oldAt := now.Add(-2 * time.Minute)
	raw, err := json.Marshal(map[string]any{
		"version":    1,
		"fetched_at": oldAt.UTC().Format(time.RFC3339),
		"keys":       jOld.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	// Process starts with newer keys from network (memory ahead of file).
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(jNew)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    srv.Client(),
		URI:       srv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Now:       nowFn,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Get(context.Background())
	if err != nil || got.Keys[0].Kid != "mem-new" {
		t.Fatalf("initial memory want mem-new: %+v err=%v", got, err)
	}

	// Overwrite file with the older snapshot again (peer lag / failed peer write).
	// Successful init may have persisted mem-new; force file back to old keys.
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	// TTL expire + network fail: must keep memory mem-new, not regress to file-old.
	clockMu.Lock()
	now = now.Add(40 * time.Second)
	clockMu.Unlock()
	got, err = src.Get(context.Background())
	if err != nil {
		t.Fatalf("stale-if-error memory path: %v", err)
	}
	if got.Keys[0].Kid != "mem-new" {
		t.Fatalf("Regression: older file must not replace newer memory keys; got kid=%q want mem-new", got.Keys[0].Kid)
	}
}

func TestRefreshingJWKS_FileCache_InvalidPathFailClosed(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "k")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)
	_, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    srv.Client(),
		URI:       srv.URL,
		TTL:       30 * time.Second,
		CachePath: ".",
		Logf:      func(string, ...any) {},
	})
	if err == nil {
		t.Fatal("invalid CachePath must fail closed at construct")
	}
}

func TestRefreshingJWKS_FileCache_ConcurrentGet(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "conc")
	path := filepath.Join(t.TempDir(), "conc-jwks.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(j1)
	}))
	t.Cleanup(srv.Close)

	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    srv.Client(),
		URI:       srv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Logf:      func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, gerr := src.Get(context.Background())
			if gerr != nil {
				errCh <- gerr
				return
			}
			if got == nil || len(got.Keys) == 0 || got.Keys[0].Kid != "conc" {
				errCh <- fmt.Errorf("bad snapshot")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		if e != nil {
			t.Fatal(e)
		}
	}
	// File still readable after concurrent Gets.
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "conc") {
		t.Fatalf("file after concurrent: err=%v body=%s", err, raw)
	}
}

func TestRefreshingJWKS_FileCache_LogsSecretFree(t *testing.T) {
	t.Parallel()
	_, j1 := testRSAJWKS(t, "log-kid")
	path := filepath.Join(t.TempDir(), "secret-path-canary-NEVER-IN-LOG", "jwks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(j1)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	var clockMu sync.Mutex
	now := time.Unix(1_700_500_000, 0)
	var logBuf strings.Builder
	var logMu sync.Mutex
	src, err := auth.NewRefreshingJWKS(context.Background(), auth.RefreshingJWKSConfig{
		Client:    srv.Client(),
		URI:       srv.URL,
		TTL:       30 * time.Second,
		CachePath: path,
		Now: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		},
		Logf: func(format string, args ...any) {
			logMu.Lock()
			defer logMu.Unlock()
			logBuf.WriteString(strings.TrimSpace(format) + "\n")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Trigger refresh fail (stale-if-error path may log).
	clockMu.Lock()
	now = now.Add(40 * time.Second)
	clockMu.Unlock()
	_, _ = src.Get(context.Background())

	logMu.Lock()
	logged := logBuf.String()
	logMu.Unlock()
	if strings.Contains(logged, "secret-path-canary-NEVER-IN-LOG") {
		t.Fatalf("Regression: cache path leaked into log: %q", logged)
	}
	if strings.Contains(logged, j1.Keys[0].N) {
		t.Fatalf("Regression: modulus in log: %q", logged)
	}
}
