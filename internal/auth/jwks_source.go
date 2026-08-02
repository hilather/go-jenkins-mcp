package auth

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"golang.org/x/sync/singleflight"
)

// JWKS refresh TTL and max-stale bounds for HOST-001 continuous rotation foundation.
// Default refresh 5m; env JENKINS_MCP_HTTP_JWKS_REFRESH_TTL feeds ParseJWKSRefreshTTL.
// Max-stale default 0 (unlimited stale-if-error); env JENKINS_MCP_HTTP_JWKS_MAX_STALE
// feeds ParseJWKSMaxStaleAge (process-local age; optional same-host file share via
// JENKINS_MCP_HTTP_JWKS_CACHE_PATH — multi-pod external JWKS residual).
const (
	// DefaultJWKSRefreshTTL is used when refresh TTL is empty/zero.
	DefaultJWKSRefreshTTL = 5 * time.Minute
	// MinJWKSRefreshTTL is the shortest allowed refresh interval (fail closed below).
	MinJWKSRefreshTTL = 30 * time.Second
	// MaxJWKSRefreshTTL is the longest allowed refresh interval (fail closed above).
	MaxJWKSRefreshTTL = time.Hour
	// MinJWKSMaxStaleAge is the shortest allowed max-stale when set (fail closed below).
	// Zero remains valid as "unlimited" (default residual).
	MinJWKSMaxStaleAge = time.Minute
	// MaxJWKSMaxStaleAge is the longest allowed max-stale (fail closed above).
	MaxJWKSMaxStaleAge = 24 * time.Hour
)

// EnvHTTPJWKSRefreshTTL is the serve env for HTTP JWKS refresh TTL
// (secret-free duration string, e.g. "5m", "30s").
const EnvHTTPJWKSRefreshTTL = "JENKINS_MCP_HTTP_JWKS_REFRESH_TTL"

// EnvHTTPJWKSMaxStale is the serve env for HTTP JWKS max stale age after a
// failed refresh (secret-free Go duration). Empty/zero → unlimited stale-if-error
// (default residual). When set (min 1m, max 24h), Get fails closed once the last
// good snapshot age exceeds the bound. Age is from the in-memory or file snapshot
// used; multi-pod external JWKS still residual.
const EnvHTTPJWKSMaxStale = "JENKINS_MCP_HTTP_JWKS_MAX_STALE"

// JWKSSource supplies a JWKS snapshot for each JWT validation.
// Implementations may refresh; callers must call Get on every validation so
// rotated kids are visible after refresh (HOST-001 foundation).
//
// Residual: multi-pod / multi-region external JWKS HA and live Entra JWKS under
// load are not claimed. Optional same-host file snapshot
// (JENKINS_MCP_HTTP_JWKS_CACHE_PATH) is HOST-001/HOST-008 Done* lite only.
// MaxStaleAge applies to snapshot age (memory or file); it is not multi-pod HA.
type JWKSSource interface {
	Get(ctx context.Context) (*JWKS, error)
}

// StaticJWKS is a fixed JWKS snapshot (tests and callers without refresh).
type StaticJWKS struct {
	Set *JWKS
}

// NewStaticJWKS wraps a non-empty JWKS as a JWKSSource. Empty/nil → nil
// interface (not a typed-nil *StaticJWKS, which would break `source == nil`).
func NewStaticJWKS(set *JWKS) JWKSSource {
	if set == nil || len(set.Keys) == 0 {
		return nil
	}
	return &StaticJWKS{Set: set}
}

// Get returns the fixed set (ignores ctx except cancellation).
func (s *StaticJWKS) Get(ctx context.Context) (*JWKS, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "jwks get cancelled", err)
	}
	if s == nil || s.Set == nil || len(s.Set.Keys) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "jwks has no keys")
	}
	return s.Set, nil
}

// jwksSnapshot is an immutable view swapped under atomic.Pointer.
type jwksSnapshot struct {
	set       *JWKS
	fetchedAt time.Time
}

// RefreshingJWKS fetches JWKS with TTL-based refresh and stale-if-error.
// Initial fetch is fail-closed via NewRefreshingJWKS unless an optional
// same-host file snapshot (CachePath) supplies a fresh enough public-key set.
// Subsequent refresh failures keep the last good set (memory and/or file) and
// log a non-secret error.
//
// Optional MaxStaleAge: when >0 and the snapshot in use is older than that age
// after a failed refresh, Get fails closed. Zero (default) means unlimited
// stale-if-error.
//
// Optional CachePath (JENKINS_MCP_HTTP_JWKS_CACHE_PATH): same-host multi-process
// public JWKS snapshot (flock + 0600). Not multi-pod external JWKS HA.
type RefreshingJWKS struct {
	client *http.Client
	uri    string
	ttl    time.Duration
	// maxStale optional fail-closed after prolonged outage (0 = unlimited stale).
	maxStale time.Duration
	// file optional same-host public JWKS snapshot cache (nil = memory-only).
	file *jwksFileCache

	nowFn func() time.Time
	logf  func(format string, args ...any)

	snap atomic.Pointer[jwksSnapshot]
	sf   singleflight.Group

	bgMu     sync.Mutex
	bgCancel context.CancelFunc
}

// RefreshingJWKSConfig configures NewRefreshingJWKS.
type RefreshingJWKSConfig struct {
	// Client performs JWKS HTTP GET. Nil → DefaultClient with DefaultJWKSTimeout.
	Client *http.Client
	// URI is the JWKS document URL (secret-free; no embedded credentials).
	URI string
	// TTL is the refresh interval. 0 → DefaultJWKSRefreshTTL. Out-of-bounds
	// values should be rejected by ParseJWKSRefreshTTL before construction.
	TTL time.Duration
	// MaxStaleAge optional; 0 keeps last good forever on refresh failure.
	// Non-zero must be in [MinJWKSMaxStaleAge, MaxJWKSMaxStaleAge] (ParseJWKSMaxStaleAge).
	// Applies to memory and optional file snapshot age.
	MaxStaleAge time.Duration
	// CachePath optional same-host multi-process JWKS snapshot file (public keys
	// only). Empty → memory-only. Invalid path fails construction. Env:
	// JENKINS_MCP_HTTP_JWKS_CACHE_PATH. Not multi-pod external JWKS HA.
	CachePath string
	// Now overrides time.Now (tests).
	Now func() time.Time
	// Logf logs non-secret refresh failures. Nil → log.Printf.
	// Never pass tokens or JWKS key material into format args from callers.
	Logf func(format string, args ...any)
}

// ParseJWKSRefreshTTL parses a Go duration for JWKS refresh TTL.
//
// Rules (fail closed — never clamp silently):
//   - empty / whitespace → DefaultJWKSRefreshTTL
//   - unparseable → error
//   - zero duration → DefaultJWKSRefreshTTL
//   - negative → error
//   - < MinJWKSRefreshTTL (30s) → error
//   - > MaxJWKSRefreshTTL (1h) → error
func ParseJWKSRefreshTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultJWKSRefreshTTL, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid JWKS refresh TTL (use Go duration, e.g. 30s, 5m): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"JWKS refresh TTL must not be negative")
	}
	if d == 0 {
		return DefaultJWKSRefreshTTL, nil
	}
	if d < MinJWKSRefreshTTL {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"JWKS refresh TTL is below minimum "+MinJWKSRefreshTTL.String()+" (got "+d.String()+")")
	}
	if d > MaxJWKSRefreshTTL {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"JWKS refresh TTL exceeds maximum "+MaxJWKSRefreshTTL.String()+" (got "+d.String()+")")
	}
	return d, nil
}

// ParseJWKSMaxStaleAge parses a Go duration for JWKS max stale age.
//
// Rules (fail closed — never clamp silently):
//   - empty / whitespace → 0 (unlimited stale-if-error residual)
//   - unparseable → error
//   - zero duration → 0 (unlimited)
//   - negative → error
//   - non-zero < MinJWKSMaxStaleAge (1m) → error
//   - > MaxJWKSMaxStaleAge (24h) → error
//
// Secret-free: raw value is a duration string only (never tokens/key material).
func ParseJWKSMaxStaleAge(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid JWKS max stale age (use Go duration, e.g. 1m, 15m, 24h; empty/0 = unlimited): "+raw)
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"JWKS max stale age must not be negative")
	}
	if d == 0 {
		return 0, nil
	}
	if d < MinJWKSMaxStaleAge {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"JWKS max stale age is below minimum "+MinJWKSMaxStaleAge.String()+" (got "+d.String()+")")
	}
	if d > MaxJWKSMaxStaleAge {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"JWKS max stale age exceeds maximum "+MaxJWKSMaxStaleAge.String()+" (got "+d.String()+")")
	}
	return d, nil
}

// NewRefreshingJWKS performs the initial JWKS fetch (fail closed) and returns
// a source that refreshes on TTL with stale-if-error. When CachePath is set and
// the network fetch fails, a fresh enough file snapshot may satisfy init
// (same-host lite); corrupt/missing/stale file → fail closed.
func NewRefreshingJWKS(ctx context.Context, cfg RefreshingJWKSConfig) (*RefreshingJWKS, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "jwks source init cancelled", err)
	}
	uri := strings.TrimSpace(cfg.URI)
	if uri == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "jwks_uri is required")
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultJWKSTimeout}
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultJWKSRefreshTTL
	}
	// Construction still rejects absurd values if caller skipped ParseJWKSRefreshTTL.
	if ttl < MinJWKSRefreshTTL || ttl > MaxJWKSRefreshTTL {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"JWKS refresh TTL out of bounds (min "+MinJWKSRefreshTTL.String()+
				" max "+MaxJWKSRefreshTTL.String()+")")
	}
	maxStale := cfg.MaxStaleAge
	if maxStale < 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"JWKS max stale age must not be negative")
	}
	// Non-zero max-stale must stay in documented bounds (caller may skip Parse).
	if maxStale > 0 && (maxStale < MinJWKSMaxStaleAge || maxStale > MaxJWKSMaxStaleAge) {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"JWKS max stale age out of bounds (min "+MinJWKSMaxStaleAge.String()+
				" max "+MaxJWKSMaxStaleAge.String()+"; 0 = unlimited)")
	}

	var file *jwksFileCache
	if strings.TrimSpace(cfg.CachePath) != "" {
		fc, ferr := newJWKSFileCache(cfg.CachePath)
		if ferr != nil {
			return nil, ferr
		}
		file = fc
	}

	r := &RefreshingJWKS{
		client:   client,
		uri:      uri,
		ttl:      ttl,
		maxStale: maxStale,
		file:     file,
		nowFn:    cfg.Now,
		logf:     cfg.Logf,
	}
	if r.logf == nil {
		r.logf = log.Printf
	}

	set, err := FetchJWKS(ctx, client, uri)
	if err != nil {
		// Optional same-host file fallback (HOST-001/HOST-008 lite).
		if fileSet, fileAt, ok := r.loadFileSnapshot(); ok {
			r.snap.Store(&jwksSnapshot{set: fileSet, fetchedAt: fileAt})
			r.logf("jwks initial fetch failed; using file snapshot (stale-if-error same-host lite; no secrets): %v", err)
			return r, nil
		}
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol,
			"HTTP JWT JWKS initial fetch failed (fail closed)", err)
	}
	fetchedAt := r.now()
	r.snap.Store(&jwksSnapshot{set: set, fetchedAt: fetchedAt})
	r.persistSnapshot(set, fetchedAt)
	return r, nil
}

func (r *RefreshingJWKS) now() time.Time {
	if r != nil && r.nowFn != nil {
		return r.nowFn()
	}
	return time.Now()
}

// TTL returns the configured refresh interval.
func (r *RefreshingJWKS) TTL() time.Duration {
	if r == nil {
		return DefaultJWKSRefreshTTL
	}
	return r.ttl
}

// MaxStaleAge returns the configured max stale age (0 = unlimited stale-if-error).
func (r *RefreshingJWKS) MaxStaleAge() time.Duration {
	if r == nil {
		return 0
	}
	return r.maxStale
}

// CachePathConfigured reports whether a same-host JWKS file cache path is set
// (secret-free residual bool; never returns the path value).
func (r *RefreshingJWKS) CachePathConfigured() bool {
	return r != nil && r.file != nil && r.file.path != ""
}

// URI returns the configured JWKS URL (secret-free).
func (r *RefreshingJWKS) URI() string {
	if r == nil {
		return ""
	}
	return r.uri
}

// FetchedAt returns the last successful fetch time (zero if none).
func (r *RefreshingJWKS) FetchedAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	s := r.snap.Load()
	if s == nil {
		return time.Time{}
	}
	return s.fetchedAt
}

// Snapshot returns the current JWKS without triggering a refresh.
// For diagnostics/tests; validation paths must use Get.
func (r *RefreshingJWKS) Snapshot() *JWKS {
	if r == nil {
		return nil
	}
	s := r.snap.Load()
	if s == nil {
		return nil
	}
	return s.set
}

// Get returns a JWKS snapshot. When the TTL has elapsed, attempts a refresh
// (singleflight). Refresh failure prefers a same-host file snapshot only when it
// is at least as new as last good memory; otherwise keeps last good in memory
// (stale-if-error) unless MaxStaleAge is exceeded. Cancelled context fails
// closed without clearing cache.
//
// Safe on a nil *RefreshingJWKS receiver (typed-nil interface edge): returns error.
func (r *RefreshingJWKS) Get(ctx context.Context) (*JWKS, error) {
	if r == nil {
		return nil, apperr.New(apperr.CodeInternal, "jwks source is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "jwks get cancelled", err)
	}
	s := r.snap.Load()
	if s == nil || s.set == nil || len(s.set.Keys) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "jwks has no keys")
	}
	age := r.now().Sub(s.fetchedAt)
	if age < r.ttl {
		return s.set, nil
	}

	// TTL expired: try refresh (coalesced).
	v, err, _ := r.sf.Do("refresh", func() (any, error) {
		// Re-check under singleflight: another caller may have refreshed.
		cur := r.snap.Load()
		if cur != nil && r.now().Sub(cur.fetchedAt) < r.ttl {
			return cur.set, nil
		}
		fetchCtx := ctx
		// Prefer a short dedicated timeout when parent has none (avoid hanging serve).
		if _, ok := fetchCtx.Deadline(); !ok {
			var cancel context.CancelFunc
			fetchCtx, cancel = context.WithTimeout(context.Background(), DefaultJWKSTimeout)
			defer cancel()
		}
		set, ferr := FetchJWKS(fetchCtx, r.client, r.uri)
		if ferr != nil {
			return nil, ferr
		}
		fetchedAt := r.now()
		r.snap.Store(&jwksSnapshot{set: set, fetchedAt: fetchedAt})
		r.persistSnapshot(set, fetchedAt)
		return set, nil
	})
	if err != nil {
		// Caller cancellation wins over stale-if-error (fail closed for this request).
		if cerr := ctx.Err(); cerr != nil {
			return nil, apperr.Wrap(apperr.CodeCancelled, "jwks get cancelled", cerr)
		}
		// Prefer same-host file snapshot only when it is at least as new as last
		// good memory (multi-process share lite). An older file must not regress
		// keys: that can re-surface rotated-out kids after a successful memory
		// refresh (security) or drop newly rotated kids (availability).
		if fileSet, fileAt, ok := r.loadFileSnapshot(); ok {
			if s == nil || !fileAt.Before(s.fetchedAt) {
				r.snap.Store(&jwksSnapshot{set: fileSet, fetchedAt: fileAt})
				r.logf("jwks refresh failed; using file snapshot (stale-if-error same-host lite; no secrets): %v", err)
				return fileSet, nil
			}
			// File older than memory: fall through to memory stale-if-error.
		}
		// Stale-if-error: keep last good unless max stale exceeded.
		// Logs are secret-free: no tokens, no JWKS n/e material, no URI query secrets, no path.
		if r.maxStale > 0 && age > r.maxStale {
			r.logf("jwks refresh failed and max stale age exceeded (fail closed; no secrets): age=%s max=%s err=%v",
				age.Round(time.Second), r.maxStale, err)
			return nil, apperr.Wrap(apperr.CodeAuthentication,
				"jwks refresh failed and max stale age exceeded", err)
		}
		r.logf("jwks refresh failed (stale-if-error; no secrets): %v", err)
		// Return last good snapshot (still non-nil from pre-check).
		return s.set, nil
	}
	set, _ := v.(*JWKS)
	if set == nil || len(set.Keys) == 0 {
		return nil, apperr.New(apperr.CodeAuthentication, "jwks has no keys")
	}
	return set, nil
}

// ForceRefresh fetches immediately and replaces the snapshot on success.
// On failure the previous snapshot is retained (stale-if-error). Used by tests.
func (r *RefreshingJWKS) ForceRefresh(ctx context.Context) error {
	if r == nil {
		return apperr.New(apperr.CodeInternal, "jwks source is nil")
	}
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "jwks refresh cancelled", err)
	}
	_, err, _ := r.sf.Do("refresh", func() (any, error) {
		set, ferr := FetchJWKS(ctx, r.client, r.uri)
		if ferr != nil {
			return nil, ferr
		}
		fetchedAt := r.now()
		r.snap.Store(&jwksSnapshot{set: set, fetchedAt: fetchedAt})
		r.persistSnapshot(set, fetchedAt)
		return set, nil
	})
	if err != nil {
		r.logf("jwks force refresh failed (stale-if-error; no secrets): %v", err)
	}
	return err
}

// persistSnapshot best-effort writes the public JWKS snapshot to the optional
// same-host file cache. Never fails the caller; never logs key material or path.
func (r *RefreshingJWKS) persistSnapshot(set *JWKS, fetchedAt time.Time) {
	if r == nil || r.file == nil || set == nil || len(set.Keys) == 0 {
		return
	}
	if err := r.file.save(set, fetchedAt); err != nil {
		// Secret-free: error string only (no path, no key material).
		r.logf("jwks file cache write failed (best-effort; no secrets): %v", err)
	}
}

// loadFileSnapshot returns a usable file snapshot when configured and fresh
// enough under MaxStaleAge. Corrupt/missing/stale → miss (ok=false).
// Never logs key material or path.
func (r *RefreshingJWKS) loadFileSnapshot() (set *JWKS, fetchedAt time.Time, ok bool) {
	if r == nil || r.file == nil {
		return nil, time.Time{}, false
	}
	set, at, found, err := r.file.load()
	if err != nil {
		// Fail closed on corrupt: miss (do not use). Secret-free log only.
		r.logf("jwks file cache read failed (miss; no secrets): %v", err)
		return nil, time.Time{}, false
	}
	if !found || set == nil || len(set.Keys) == 0 {
		return nil, time.Time{}, false
	}
	if !jwksSnapshotFreshEnough(at, r.now(), r.maxStale) {
		r.logf("jwks file cache snapshot exceeds max stale age (miss; no secrets)")
		return nil, time.Time{}, false
	}
	return set, at, true
}

// StartBackground starts a ticker that refreshes JWKS every TTL until ctx is
// cancelled or StopBackground is called. Optional; Get already refreshes
// on-demand when TTL elapses. Safe to call once; subsequent calls are no-ops
// until StopBackground.
func (r *RefreshingJWKS) StartBackground(ctx context.Context) {
	if r == nil {
		return
	}
	r.bgMu.Lock()
	defer r.bgMu.Unlock()
	if r.bgCancel != nil {
		return
	}
	bgCtx, cancel := context.WithCancel(ctx)
	r.bgCancel = cancel
	ttl := r.ttl
	go func() {
		t := time.NewTicker(ttl)
		defer t.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-t.C:
				// Ignore error: ForceRefresh already logs + keeps stale.
				_ = r.ForceRefresh(bgCtx)
			}
		}
	}()
}

// StopBackground cancels the optional background refresher.
func (r *RefreshingJWKS) StopBackground() {
	if r == nil {
		return
	}
	r.bgMu.Lock()
	defer r.bgMu.Unlock()
	if r.bgCancel != nil {
		r.bgCancel()
		r.bgCancel = nil
	}
}

// Ensure RefreshingJWKS and StaticJWKS implement JWKSSource.
var (
	_ JWKSSource = (*RefreshingJWKS)(nil)
	_ JWKSSource = (*StaticJWKS)(nil)
)
