package jenkins

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default resilience knobs (NET-003).
const (
	// DefaultMaxJSONBodyBytes is the hard decoded-body cap for non-log API paths
	// (32 MiB). Operators may raise via --max-json-body-bytes /
	// JENKINS_MCP_MAX_JSON_BODY_BYTES up to AbsoluteMaxJSONBodyBytes.
	DefaultMaxJSONBodyBytes int64 = 32 << 20 // 32 MiB
	// AbsoluteMaxJSONBodyBytes is the process absolute fail-closed ceiling for
	// MaxJSONBodyBytes (Wave 46 Track A / NET-003). Oversize flag/env is rejected
	// at serve start (not clamped silently). normalizeResilienceConfig clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	AbsoluteMaxJSONBodyBytes int64 = 128 << 20 // 128 MiB
	// DefaultMaxRetries is extra GET/HEAD attempts after the first (total
	// attempts = 1 + MaxRetries). Exported for operator_caps / diagnostics.
	// Operators may set via --max-retries / JENKINS_MCP_MAX_RETRIES; explicit 0
	// disables auto-retry for GET/HEAD. POST/PUT/PATCH/DELETE never auto-retry.
	DefaultMaxRetries = 2
	// AbsoluteMaxRetries is the process absolute fail-closed ceiling for
	// MaxRetries (Wave 47 Track A / NET-003). Oversize flag/env is rejected at
	// serve start (not clamped silently). normalizeResilienceConfig clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	AbsoluteMaxRetries = 10
	// DefaultCircuitFailureThreshold opens the breaker after N consecutive
	// 5xx/transport failures. Exported for operator_caps / diagnostics.
	// Operators may set via --circuit-failure-threshold /
	// JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD; explicit 0 means default (cannot
	// disable the circuit by 0 — fail-closed safety).
	DefaultCircuitFailureThreshold = 5
	// AbsoluteMaxCircuitFailureThreshold is the process absolute fail-closed
	// ceiling for CircuitFailureThreshold (Wave 48 Track A / NET-003). Oversize
	// flag/env is rejected at serve start (not clamped silently).
	// normalizeResilienceConfig clamps library callers that bypass Resolve as
	// belt-and-suspenders.
	AbsoluteMaxCircuitFailureThreshold = 50
	// DefaultCircuitOpenDuration is how long the breaker stays open before a
	// half-open probe (15s). Operators may set via --circuit-open-duration /
	// JENKINS_MCP_CIRCUIT_OPEN_DURATION; explicit 0/"0s" means default (cannot
	// disable the open period to 0 — fail-closed safety).
	DefaultCircuitOpenDuration = 15 * time.Second
	// MinCircuitOpenDuration is the shortest allowed circuit open period
	// (Wave 49 Track A / NET-003). Below this, Resolve fails closed at serve
	// start (not clamped silently). normalizeResilienceConfig clamps library
	// callers that bypass Resolve as belt-and-suspenders.
	MinCircuitOpenDuration = 1 * time.Second
	// AbsoluteMaxCircuitOpenDuration is the process absolute fail-closed
	// ceiling for CircuitOpenDuration (Wave 49 Track A / NET-003). Oversize
	// flag/env is rejected at serve start (not clamped silently).
	// normalizeResilienceConfig clamps library callers that bypass Resolve as
	// belt-and-suspenders.
	AbsoluteMaxCircuitOpenDuration = 5 * time.Minute
	// DefaultMaxConcurrent is the default per-client concurrency semaphore
	// (0 = unlimited). Operators may set via --max-concurrent /
	// JENKINS_MCP_MAX_CONCURRENT; explicit 0 means unlimited concurrency
	// (contrast MaxRetries where 0 disables GET/HEAD auto-retry).
	DefaultMaxConcurrent = 0
	// AbsoluteMaxConcurrent is the process absolute fail-closed ceiling for
	// MaxConcurrent (Wave 50 Track A / NET-003). Oversize flag/env is rejected
	// at serve start (not clamped silently). normalizeResilienceConfig clamps
	// library callers that bypass Resolve as belt-and-suspenders. Prevents
	// absurd thousands of in-flight Jenkins requests per client.
	AbsoluteMaxConcurrent = 256
	// DefaultInitialBackoff is the base delay before the first GET/HEAD retry
	// (Wave 50 Track B operator_caps honesty; Wave 51 Track A operator-tunable).
	// Operators may set via --initial-backoff / JENKINS_MCP_INITIAL_BACKOFF;
	// explicit 0/"0s" means default (cannot disable backoff base to 0).
	DefaultInitialBackoff = 100 * time.Millisecond
	// MinInitialBackoff is the shortest allowed initial backoff
	// (Wave 51 Track A / NET-003). Below this, Resolve fails closed at serve
	// start (not clamped silently). normalizeResilienceConfig clamps library
	// callers that bypass Resolve as belt-and-suspenders.
	MinInitialBackoff = 10 * time.Millisecond
	// AbsoluteMaxInitialBackoff is the process absolute fail-closed ceiling for
	// InitialBackoff (Wave 51 Track A / NET-003). Oversize flag/env is rejected
	// at serve start (not clamped silently). normalizeResilienceConfig clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	AbsoluteMaxInitialBackoff = 2 * time.Second
	// DefaultMaxBackoff caps exponential backoff and Retry-After for GET/HEAD.
	// Operators may set via --max-backoff / JENKINS_MCP_MAX_BACKOFF; explicit
	// 0/"0s" means default. After resolve at serve, MaxBackoff must be ≥
	// InitialBackoff (fail closed).
	DefaultMaxBackoff = 5 * time.Second
	// MinMaxBackoff is the shortest allowed max backoff
	// (Wave 51 Track A / NET-003). Below this, Resolve fails closed at serve
	// start (not clamped silently). normalizeResilienceConfig clamps library
	// callers that bypass Resolve as belt-and-suspenders.
	MinMaxBackoff = 100 * time.Millisecond
	// AbsoluteMaxMaxBackoff is the process absolute fail-closed ceiling for
	// MaxBackoff (Wave 51 Track A / NET-003). Oversize flag/env is rejected at
	// serve start (not clamped silently). normalizeResilienceConfig clamps
	// library callers that bypass Resolve as belt-and-suspenders.
	AbsoluteMaxMaxBackoff = 1 * time.Minute
	// Unexported aliases keep existing internal call sites stable.
	defaultMaxRetries      = DefaultMaxRetries
	defaultCircuitFailures = DefaultCircuitFailureThreshold
	defaultInitialBackoff  = DefaultInitialBackoff
	defaultMaxBackoff      = DefaultMaxBackoff
	defaultCircuitOpen     = DefaultCircuitOpenDuration
)

// EnvMaxJSONBodyBytes is the serve env for the Jenkins API JSON/decoded body
// cap (Wave 46 Track A / NET-003). CLI --max-json-body-bytes overrides when set.
// Empty/0 → DefaultMaxJSONBodyBytes. Invalid values and values above
// AbsoluteMaxJSONBodyBytes fail closed at serve start. Does not wrap progressive
// log paths (LOG-001 caps remain separate).
const EnvMaxJSONBodyBytes = "JENKINS_MCP_MAX_JSON_BODY_BYTES"

// EnvMaxRetries is the serve env for extra GET/HEAD auto-retries after the
// first attempt (Wave 47 Track A / NET-003). CLI --max-retries overrides when
// set. Empty/whitespace → DefaultMaxRetries (2). Explicit "0" means zero
// extra retries (disable auto-retry for GET/HEAD) — unlike MaxJSONBodyBytes,
// 0 does not mean "use default". Invalid/negative values and values above
// AbsoluteMaxRetries fail closed at serve start. POST never auto-retries.
const EnvMaxRetries = "JENKINS_MCP_MAX_RETRIES"

// EnvCircuitFailureThreshold is the serve env for consecutive 5xx/transport
// failures before the per-client circuit opens (Wave 48 Track A / NET-003).
// CLI --circuit-failure-threshold overrides when set. Empty/whitespace/0 →
// DefaultCircuitFailureThreshold (5). Explicit 0 cannot disable the breaker
// (fail-closed safety — maps to default). Invalid/negative values and values
// above AbsoluteMaxCircuitFailureThreshold fail closed at serve start.
const EnvCircuitFailureThreshold = "JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD"

// EnvCircuitOpenDuration is the serve env for how long the circuit stays open
// before a half-open probe (Wave 49 Track A / NET-003). CLI
// --circuit-open-duration overrides when set. Empty/whitespace/0/"0s" →
// DefaultCircuitOpenDuration (15s). Explicit 0 cannot disable the open period
// (fail-closed safety — maps to default). Invalid/negative values, values
// below MinCircuitOpenDuration (1s), and values above
// AbsoluteMaxCircuitOpenDuration (5m) fail closed at serve start.
const EnvCircuitOpenDuration = "JENKINS_MCP_CIRCUIT_OPEN_DURATION"

// EnvMaxConcurrent is the serve env for the per-client Jenkins concurrency
// semaphore (Wave 50 Track A / NET-003). CLI --max-concurrent overrides when
// set. Empty/whitespace at all layers → DefaultMaxConcurrent (0 = unlimited).
// Explicit "0" means unlimited concurrency (not default-substitution of a
// positive limit) — contrast MaxRetries where 0 disables GET/HEAD auto-retry.
// Invalid/negative values and values above AbsoluteMaxConcurrent (256) fail
// closed at serve start. POST never auto-retries regardless of concurrency.
const EnvMaxConcurrent = "JENKINS_MCP_MAX_CONCURRENT"

// EnvInitialBackoff is the serve env for the GET/HEAD retry base delay before
// the first retry (Wave 51 Track A / NET-003). CLI --initial-backoff overrides
// when set. Empty/whitespace/0/"0s" → DefaultInitialBackoff (100ms). Explicit 0
// cannot disable the base delay (fail-closed safety — maps to default).
// Invalid/negative values, values below MinInitialBackoff (10ms), and values
// above AbsoluteMaxInitialBackoff (2s) fail closed at serve start.
// After both backoffs resolve, MaxBackoff must be ≥ InitialBackoff.
const EnvInitialBackoff = "JENKINS_MCP_INITIAL_BACKOFF"

// EnvMaxBackoff is the serve env for the GET/HEAD retry backoff / Retry-After
// cap (Wave 51 Track A / NET-003). CLI --max-backoff overrides when set.
// Empty/whitespace/0/"0s" → DefaultMaxBackoff (5s). Explicit 0 cannot disable
// the cap (fail-closed safety — maps to default). Invalid/negative values,
// values below MinMaxBackoff (100ms), and values above AbsoluteMaxMaxBackoff
// (1m) fail closed at serve start. After both backoffs resolve, MaxBackoff must
// be ≥ InitialBackoff.
const EnvMaxBackoff = "JENKINS_MCP_MAX_BACKOFF"

// ErrCircuitOpen is returned when the per-client circuit breaker is open (NET-003).
var ErrCircuitOpen = errors.New("jenkins circuit breaker open")

// ErrBodyTooLarge is returned when an API response exceeds MaxJSONBodyBytes (NET-003).
var ErrBodyTooLarge = errors.New("response body exceeds configured limit")

// ResilienceConfig configures retries, body limits, throttle, and circuit breaking (NET-003).
type ResilienceConfig struct {
	// MaxJSONBodyBytes limits decoded response bodies on non-log (API) paths.
	// Log paths keep LOG-001 progressive length caps. Default 32 MiB; absolute
	// process ceiling AbsoluteMaxJSONBodyBytes (128 MiB). Operator path:
	// ResolveMaxJSONBodyBytes → positive value ≤ AbsoluteMaxJSONBodyBytes.
	MaxJSONBodyBytes int64
	// MaxRetries is extra attempts after the first for idempotent GET/HEAD only.
	// POST/PUT/PATCH/DELETE are never auto-retried (build trigger / stop safety).
	// Default DefaultMaxRetries (2); absolute process ceiling AbsoluteMaxRetries
	// (10). Operator path: ResolveMaxRetries → non-negative ≤ AbsoluteMaxRetries.
	// Explicit 0 disables auto-retry for GET/HEAD (still one attempt).
	MaxRetries int
	// InitialBackoff is the base delay before the first retry (before jitter).
	// Default DefaultInitialBackoff (100ms); min MinInitialBackoff (10ms);
	// absolute process ceiling AbsoluteMaxInitialBackoff (2s). Operator path:
	// ResolveInitialBackoff → value in [Min, AbsoluteMax]. Explicit 0 at resolve
	// means default (cannot disable base delay by 0).
	InitialBackoff time.Duration
	// MaxBackoff caps exponential backoff and Retry-After.
	// Default DefaultMaxBackoff (5s); min MinMaxBackoff (100ms); absolute process
	// ceiling AbsoluteMaxMaxBackoff (1m). Operator path: ResolveMaxBackoff →
	// value in [Min, AbsoluteMax]. Explicit 0 at resolve means default.
	// After resolve at serve, MaxBackoff must be ≥ InitialBackoff (fail closed);
	// normalizeResilienceConfig raises MaxBackoff to InitialBackoff if inverted.
	MaxBackoff time.Duration
	// MaxConcurrent is a simple per-client concurrency semaphore.
	// 0 = unlimited (default). Absolute process ceiling AbsoluteMaxConcurrent
	// (256). Operator path: ResolveMaxConcurrent → non-negative ≤ AbsoluteMax.
	// Explicit 0 means unlimited (contrast MaxRetries where 0 disables retry).
	MaxConcurrent int
	// CircuitFailureThreshold opens the breaker after N consecutive 5xx/transport
	// failures. Default DefaultCircuitFailureThreshold (5); absolute process
	// ceiling AbsoluteMaxCircuitFailureThreshold (50). Operator path:
	// ResolveCircuitFailureThreshold → positive value ≤ AbsoluteMax.
	// Explicit 0 at resolve means default (cannot disable circuit by 0).
	CircuitFailureThreshold int
	// CircuitOpenDuration is how long the breaker stays open before a half-open
	// probe. Default DefaultCircuitOpenDuration (15s); min MinCircuitOpenDuration
	// (1s); absolute process ceiling AbsoluteMaxCircuitOpenDuration (5m).
	// Operator path: ResolveCircuitOpenDuration → value in [Min, AbsoluteMax].
	// Explicit 0 at resolve means default (cannot disable open period by 0).
	CircuitOpenDuration time.Duration
}

// DefaultResilienceConfig returns production defaults for NET-003.
func DefaultResilienceConfig() ResilienceConfig {
	return ResilienceConfig{
		MaxJSONBodyBytes:        DefaultMaxJSONBodyBytes,
		MaxRetries:              DefaultMaxRetries,
		InitialBackoff:          defaultInitialBackoff,
		MaxBackoff:              defaultMaxBackoff,
		MaxConcurrent:           DefaultMaxConcurrent,
		CircuitFailureThreshold: DefaultCircuitFailureThreshold,
		CircuitOpenDuration:     defaultCircuitOpen,
	}
}

// CircuitState is a snapshot of breaker status for diagnostics/status tools.
type CircuitState struct {
	// State is "closed", "open", or "half-open".
	State               string    `json:"state"`
	ConsecutiveFailures int       `json:"consecutiveFailures"`
	OpenUntil           time.Time `json:"openUntil,omitempty"`
	FailureThreshold    int       `json:"failureThreshold"`
}

// Resilience holds mutable retry/breaker/throttle state shared by a Client.
type Resilience struct {
	cfg ResilienceConfig

	sem chan struct{} // nil if unlimited

	mu        sync.Mutex
	failures  int
	openUntil time.Time
	halfOpen  bool // probe in flight after open period

	// onCircuitOpen is called (outside the mutex) when the breaker transitions
	// into open. Wired from Client MetricsHook (OBS Wave 27); nil-safe.
	// Does not import telemetry — callback is set by Client.bindCircuitMetrics.
	onCircuitOpen func()

	// sleep is overridable in tests (default: context-aware timer).
	sleep func(ctx context.Context, d time.Duration) error
	now   func() time.Time
	// intn returns [0,n) for jitter; overridable in tests.
	intn func(n int64) int64
}

// NewResilience constructs resilience state from cfg.
func NewResilience(cfg ResilienceConfig) *Resilience {
	cfg = normalizeResilienceConfig(cfg)
	r := &Resilience{
		cfg: cfg,
		sleep: func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return nil
			}
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		now: time.Now,
		intn: func(n int64) int64 {
			if n <= 0 {
				return 0
			}
			return rand.Int63n(n)
		},
	}
	if cfg.MaxConcurrent > 0 {
		r.sem = make(chan struct{}, cfg.MaxConcurrent)
	}
	return r
}

func normalizeResilienceConfig(cfg ResilienceConfig) ResilienceConfig {
	d := DefaultResilienceConfig()
	if cfg.MaxJSONBodyBytes <= 0 {
		cfg.MaxJSONBodyBytes = d.MaxJSONBodyBytes
	}
	// Belt-and-suspenders: library callers that bypass ResolveMaxJSONBodyBytes
	// cannot install multi-GB body caps. Operator serve path fails closed in
	// Resolve (no silent clamp); normalize only clamps direct WithResilience use.
	if cfg.MaxJSONBodyBytes > AbsoluteMaxJSONBodyBytes {
		cfg.MaxJSONBodyBytes = AbsoluteMaxJSONBodyBytes
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = d.MaxRetries
	}
	// Belt-and-suspenders: library callers that bypass ResolveMaxRetries cannot
	// install absurd retry storms. Operator serve path fails closed in Resolve
	// (no silent clamp); normalize only clamps direct WithResilience use.
	// Explicit MaxRetries == 0 is preserved (disables auto-retry for GET/HEAD).
	if cfg.MaxRetries > AbsoluteMaxRetries {
		cfg.MaxRetries = AbsoluteMaxRetries
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = d.InitialBackoff
	}
	// Belt-and-suspenders: library callers that bypass ResolveInitialBackoff
	// cannot install sub-min or multi-second base delays beyond the absolute
	// ceiling. Operator serve path fails closed in Resolve (no silent clamp);
	// normalize only clamps direct WithResilience use.
	if cfg.InitialBackoff < MinInitialBackoff {
		cfg.InitialBackoff = MinInitialBackoff
	}
	if cfg.InitialBackoff > AbsoluteMaxInitialBackoff {
		cfg.InitialBackoff = AbsoluteMaxInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = d.MaxBackoff
	}
	// Belt-and-suspenders: library callers that bypass ResolveMaxBackoff cannot
	// install sub-min or multi-hour caps. Operator serve path fails closed in
	// Resolve (no silent clamp); normalize only clamps direct WithResilience use.
	if cfg.MaxBackoff < MinMaxBackoff {
		cfg.MaxBackoff = MinMaxBackoff
	}
	if cfg.MaxBackoff > AbsoluteMaxMaxBackoff {
		cfg.MaxBackoff = AbsoluteMaxMaxBackoff
	}
	// If MaxBackoff < InitialBackoff after clamps, raise MaxBackoff so retry
	// math stays sane (operator serve path fails closed instead of silent fix).
	if cfg.MaxBackoff < cfg.InitialBackoff {
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	if cfg.CircuitFailureThreshold <= 0 {
		cfg.CircuitFailureThreshold = d.CircuitFailureThreshold
	}
	// Belt-and-suspenders: library callers that bypass
	// ResolveCircuitFailureThreshold cannot install absurd thresholds that
	// effectively disable trip. Operator serve path fails closed in Resolve
	// (no silent clamp); normalize only clamps direct WithResilience use.
	if cfg.CircuitFailureThreshold > AbsoluteMaxCircuitFailureThreshold {
		cfg.CircuitFailureThreshold = AbsoluteMaxCircuitFailureThreshold
	}
	if cfg.CircuitOpenDuration <= 0 {
		cfg.CircuitOpenDuration = d.CircuitOpenDuration
	}
	// Belt-and-suspenders: library callers that bypass
	// ResolveCircuitOpenDuration cannot install sub-min or multi-hour open
	// windows. Operator serve path fails closed in Resolve (no silent clamp);
	// normalize only clamps direct WithResilience use.
	if cfg.CircuitOpenDuration < MinCircuitOpenDuration {
		cfg.CircuitOpenDuration = MinCircuitOpenDuration
	}
	if cfg.CircuitOpenDuration > AbsoluteMaxCircuitOpenDuration {
		cfg.CircuitOpenDuration = AbsoluteMaxCircuitOpenDuration
	}
	// Negative MaxConcurrent → 0 unlimited (same as default).
	if cfg.MaxConcurrent < 0 {
		cfg.MaxConcurrent = 0
	}
	// Belt-and-suspenders: library callers that bypass ResolveMaxConcurrent
	// cannot install absurd concurrency (thousands of in-flight requests).
	// Operator serve path fails closed in Resolve (no silent clamp); normalize
	// only clamps direct WithResilience use. Explicit MaxConcurrent == 0 is
	// preserved (unlimited; not remapped to a positive default).
	if cfg.MaxConcurrent > AbsoluteMaxConcurrent {
		cfg.MaxConcurrent = AbsoluteMaxConcurrent
	}
	return cfg
}

// Config returns a copy of the resilience configuration.
func (r *Resilience) Config() ResilienceConfig {
	if r == nil {
		return DefaultResilienceConfig()
	}
	return r.cfg
}

// State returns an observable circuit-breaker snapshot (NET-003).
func (r *Resilience) State() CircuitState {
	if r == nil {
		return CircuitState{State: "closed", FailureThreshold: defaultCircuitFailures}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := CircuitState{
		ConsecutiveFailures: r.failures,
		FailureThreshold:    r.cfg.CircuitFailureThreshold,
		OpenUntil:           r.openUntil,
	}
	now := r.now()
	switch {
	case !r.openUntil.IsZero() && now.Before(r.openUntil):
		st.State = "open"
	case r.halfOpen || (!r.openUntil.IsZero() && !now.Before(r.openUntil)):
		st.State = "half-open"
	default:
		st.State = "closed"
	}
	return st
}

func (r *Resilience) acquire(ctx context.Context) error {
	if r == nil || r.sem == nil {
		return nil
	}
	select {
	case r.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Resilience) release() {
	if r == nil || r.sem == nil {
		return
	}
	select {
	case <-r.sem:
	default:
	}
}

// allow returns ErrCircuitOpen when the breaker is open (no probe slot).
func (r *Resilience) allow() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.openUntil.IsZero() {
		return nil
	}
	if now.Before(r.openUntil) {
		return fmt.Errorf("%w: retry after %s", ErrCircuitOpen, r.openUntil.Sub(now).Round(time.Millisecond))
	}
	// Open period elapsed: allow one half-open probe.
	r.halfOpen = true
	return nil
}

func (r *Resilience) onSuccess() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = 0
	r.openUntil = time.Time{}
	r.halfOpen = false
}

func (r *Resilience) onFailure() {
	if r == nil {
		return
	}
	r.mu.Lock()
	now := r.now()
	alreadyOpen := !r.openUntil.IsZero() && now.Before(r.openUntil)
	r.failures++
	opened := false
	if r.halfOpen || r.failures >= r.cfg.CircuitFailureThreshold {
		r.openUntil = now.Add(r.cfg.CircuitOpenDuration)
		r.halfOpen = false
		if !alreadyOpen {
			opened = true
		}
	}
	hook := r.onCircuitOpen
	r.mu.Unlock()
	// Fire outside the mutex so hooks may call State() safely.
	if opened && hook != nil {
		hook()
	}
}

// IsIdempotentRetryMethod reports whether HTTP method is eligible for automatic
// retry under NET-003. Only GET and HEAD return true; POST/PUT/PATCH/DELETE
// and other methods never auto-retry (build trigger / stop safety).
// Pure: no network, no secrets. Used by CallJenkins and offline self-check.
func IsIdempotentRetryMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

// isIdempotentMethod is the internal alias used by CallJenkins retry paths.
func isIdempotentMethod(method string) bool {
	return IsIdempotentRetryMethod(method)
}

// classifyRetryStatus reports whether a response status is retryable for idempotent reads.
func classifyRetryStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, // 429
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
		http.StatusGatewayTimeout:     // 504
		return true
	default:
		return false
	}
}

// isCircuitFailureStatus reports 5xx that advance the breaker (not 4xx).
func isCircuitFailureStatus(code int) bool {
	return code >= 500 && code <= 599
}

// isRetryableTransportError reports network errors that may be retried.
// Cancellation and policy/origin errors are never retried.
func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, ErrCrossOrigin) || errors.Is(err, ErrCircuitOpen) ||
		errors.Is(err, ErrInvalidBaseURL) || errors.Is(err, ErrBodyTooLarge) {
		return false
	}
	return true
}

// retryBackoff returns a jittered delay for the given 1-based retry attempt.
// attempt=1 is the first retry after the initial try. Honors Retry-After when present.
func (r *Resilience) retryBackoff(attempt int, resp *http.Response) time.Duration {
	cfg := DefaultResilienceConfig()
	if r != nil {
		cfg = r.cfg
	}
	if resp != nil {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if d, ok := parseRetryAfter(ra, rNow(r)); ok {
				if d > cfg.MaxBackoff {
					d = cfg.MaxBackoff
				}
				if d < 0 {
					d = 0
				}
				return d
			}
		}
	}
	// Exponential: initial * 2^(attempt-1), full jitter in [0, base].
	base := cfg.InitialBackoff
	for i := 1; i < attempt; i++ {
		if base >= cfg.MaxBackoff/2 {
			base = cfg.MaxBackoff
			break
		}
		base *= 2
	}
	if base > cfg.MaxBackoff {
		base = cfg.MaxBackoff
	}
	if base <= 0 {
		return 0
	}
	var n int64
	if r != nil && r.intn != nil {
		n = r.intn(int64(base) + 1)
	} else {
		n = rand.Int63n(int64(base) + 1)
	}
	return time.Duration(n)
}

func rNow(r *Resilience) time.Time {
	if r != nil && r.now != nil {
		return r.now()
	}
	return time.Now()
}

// parseRetryAfter parses Retry-After as delta-seconds or HTTP-date.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
		if sec < 0 {
			return 0, true
		}
		// Clamp before the multiply: sec * time.Second overflows int64 for
		// sec > ~9.2e9 and can wrap negative (which the caller then clamps
		// to 0 — an immediate, un-backed-off retry).
		const maxSec = int64(1<<63-1) / int64(time.Second)
		if sec > maxSec {
			sec = maxSec
		}
		return time.Duration(sec) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0, true
		}
		return d, true
	}
	return 0, false
}

// drainAndClose discards a limited amount of body so the connection can be reused,
// then closes. Used between retries.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10))
	_ = resp.Body.Close()
}

// RetryPolicyClassify is exported for unit tests: whether method+status would retry.
func RetryPolicyClassify(method string, statusCode int, transportErr error) (retryable bool, reason string) {
	if transportErr != nil {
		if !isIdempotentMethod(method) {
			return false, "non-idempotent method"
		}
		if !isRetryableTransportError(transportErr) {
			return false, "non-retryable error"
		}
		return true, "transport error"
	}
	if !isIdempotentMethod(method) {
		return false, "non-idempotent method"
	}
	if classifyRetryStatus(statusCode) {
		return true, "retryable status"
	}
	return false, "status not retryable"
}
