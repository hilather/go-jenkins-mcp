package auth

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"golang.org/x/sync/singleflight"
)

// JWKS refresh TTL bounds for HOST-001 continuous rotation foundation.
// Default 5m; env JENKINS_MCP_HTTP_JWKS_REFRESH_TTL (cmd) feeds ParseJWKSRefreshTTL.
const (
	// DefaultJWKSRefreshTTL is used when refresh TTL is empty/zero.
	DefaultJWKSRefreshTTL = 5 * time.Minute
	// MinJWKSRefreshTTL is the shortest allowed refresh interval (fail closed below).
	MinJWKSRefreshTTL = 30 * time.Second
	// MaxJWKSRefreshTTL is the longest allowed refresh interval (fail closed above).
	MaxJWKSRefreshTTL = time.Hour
)

// EnvHTTPJWKSRefreshTTL is the serve env for HTTP JWKS refresh TTL
// (secret-free duration string, e.g. "5m", "30s").
const EnvHTTPJWKSRefreshTTL = "JENKINS_MCP_HTTP_JWKS_REFRESH_TTL"

// JWKSSource supplies a JWKS snapshot for each JWT validation.
// Implementations may refresh; callers must call Get on every validation so
// rotated kids are visible after refresh (HOST-001 foundation).
//
// Residual: multi-region / multi-instance shared JWKS cache, fail-closed max
// stale age after prolonged IdP outage, and live Entra JWKS under load are not
// claimed by this offline foundation.
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
// Initial fetch is fail-closed via NewRefreshingJWKS. Subsequent refresh
// failures keep the last good set and log a non-secret error.
//
// Optional MaxStaleAge: when >0 and last successful fetch is older than that
// age after a failed refresh, Get fails closed. Zero (default) means unlimited
// stale-if-error (residual: operators may want a hard max-stale later).
type RefreshingJWKS struct {
	client *http.Client
	uri    string
	ttl    time.Duration
	// MaxStaleAge optional fail-closed after prolonged outage (0 = unlimited stale).
	maxStale time.Duration

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
	MaxStaleAge time.Duration
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

// NewRefreshingJWKS performs the initial JWKS fetch (fail closed) and returns
// a source that refreshes on TTL with stale-if-error.
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

	r := &RefreshingJWKS{
		client:   client,
		uri:      uri,
		ttl:      ttl,
		maxStale: cfg.MaxStaleAge,
		nowFn:    cfg.Now,
		logf:     cfg.Logf,
	}
	if r.logf == nil {
		r.logf = log.Printf
	}

	set, err := FetchJWKS(ctx, client, uri)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol,
			"HTTP JWT JWKS initial fetch failed (fail closed)", err)
	}
	r.snap.Store(&jwksSnapshot{set: set, fetchedAt: r.now()})
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
// (singleflight). Refresh failure keeps last good (stale-if-error) unless
// MaxStaleAge is exceeded. Cancelled context fails closed without clearing cache.
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
		r.snap.Store(&jwksSnapshot{set: set, fetchedAt: r.now()})
		return set, nil
	})
	if err != nil {
		// Caller cancellation wins over stale-if-error (fail closed for this request).
		if cerr := ctx.Err(); cerr != nil {
			return nil, apperr.Wrap(apperr.CodeCancelled, "jwks get cancelled", cerr)
		}
		// Stale-if-error: keep last good unless max stale exceeded.
		r.logf("jwks refresh failed (stale-if-error; no secrets): %v", err)
		if r.maxStale > 0 && age > r.maxStale {
			return nil, apperr.Wrap(apperr.CodeAuthentication,
				"jwks refresh failed and max stale age exceeded", err)
		}
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
		r.snap.Store(&jwksSnapshot{set: set, fetchedAt: r.now()})
		return set, nil
	})
	if err != nil {
		r.logf("jwks force refresh failed (stale-if-error; no secrets): %v", err)
	}
	return err
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
