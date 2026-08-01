package gateway

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// HOST-006: per-subject token-bucket rate limits under an optional process
// ceiling. Complements SubjectLimiter (concurrency slots).
//
// Single-process MVP only (HOST-008 multi-replica residual). Policy may only
// reduce these caps — never elevate past process absolute ceilings.
// Overlay max_tools_per_minute / max_tools_burst → LowerRate (lower only;
// empty = no change; absolute floor MinSubjectRate*).
//
// Serve wire (Done*): cmd sets tools.RegisterOptions.SubjectRateLimiter when
// --gateway is on and resolved ratePerMinute > 0 (0 = disabled residual).
// tools.addTool calls Allow when limiter and SubjectKey are set. tools does
// not import gateway (FND-004); the tools.SubjectRateLimiter interface is the
// wire surface (Allow only; LowerRate stays on *gateway.SubjectRateLimiter).

const (
	// DefaultSubjectRatePerMinute is the default sustained tool dispatches per
	// subjectKey per minute (token-bucket refill). Conservative multi-tenant
	// default; aligns order-of-magnitude with MUT-001 preview rate.
	DefaultSubjectRatePerMinute = 30
	// DefaultSubjectRateBurst is the default token-bucket capacity (burst) per
	// subject. Allows short bursts without exceeding the sustained minute rate.
	DefaultSubjectRateBurst = 10
	// AbsoluteMaxSubjectRatePerMinute is the hard per-subject sustained ceiling
	// (fail closed; operators cannot raise above this in-process).
	AbsoluteMaxSubjectRatePerMinute = 600
	// AbsoluteMaxSubjectRateBurst is the hard per-subject burst ceiling.
	AbsoluteMaxSubjectRateBurst = 120
	// MinSubjectRatePerMinute is the absolute floor when policy/env lowers the
	// live rate mid-serve (never 0 via LowerRate; 0 remains construction-only
	// disabled residual).
	MinSubjectRatePerMinute = 1
	// MinSubjectRateBurst is the absolute floor when lowering burst.
	MinSubjectRateBurst = 1
	// DefaultProcessRatePerMinute is the default process-wide sustained rate
	// when processMaxPerMinute is non-positive at construction.
	DefaultProcessRatePerMinute = 300
	// AbsoluteMaxProcessRatePerMinute is the process-wide sustained ceiling.
	AbsoluteMaxProcessRatePerMinute = 6000
	// DefaultProcessRateBurst is process-wide burst capacity when non-positive.
	DefaultProcessRateBurst = 60
	// AbsoluteMaxProcessRateBurst is the process-wide burst ceiling.
	AbsoluteMaxProcessRateBurst = 600

	// EnvSubjectRatePerMinute is optional env for per-subject sustained rate
	// (tools/min). Empty → DefaultSubjectRatePerMinute under gateway serve.
	// Explicit 0 disables the rate limiter (residual / opt-out).
	EnvSubjectRatePerMinute = "JENKINS_MCP_SUBJECT_RATE_PER_MINUTE"
	// EnvSubjectRateBurst is optional env for per-subject burst capacity.
	// Empty → DefaultSubjectRateBurst. Ignored when rate is disabled (0).
	EnvSubjectRateBurst = "JENKINS_MCP_SUBJECT_RATE_BURST"
)

// ResolveSubjectRateCaps resolves optional env overrides for NewSubjectRateLimiter.
// Empty rate env → default (enabled). Explicit 0 → disabled (ratePerMinute=0).
// Empty burst → default. Invalid (non-integer / negative) values fail closed.
// Values above absolute ceilings are accepted here and clamped by
// NewSubjectRateLimiter.
func ResolveSubjectRateCaps(ratePerMinuteEnv, burstEnv string) (ratePerMinute, burst int, err error) {
	ratePerMinute = DefaultSubjectRatePerMinute
	burst = DefaultSubjectRateBurst
	if raw := strings.TrimSpace(ratePerMinuteEnv); raw != "" {
		v, perr := strconv.Atoi(raw)
		if perr != nil || v < 0 {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvSubjectRatePerMinute+" (non-negative integer; empty = default; 0 = disabled)")
		}
		ratePerMinute = v
	}
	if raw := strings.TrimSpace(burstEnv); raw != "" {
		v, perr := strconv.Atoi(raw)
		if perr != nil || v < 0 {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvSubjectRateBurst+" (non-negative integer; empty = default)")
		}
		burst = v
	}
	return ratePerMinute, burst, nil
}

// SubjectRateEnabledFromEnviron reports whether subject rate limiting would be
// enabled under gateway serve given env (secret-free residual for admin health).
// Empty JENKINS_MCP_SUBJECT_RATE_PER_MINUTE → true (default on). Explicit 0 →
// false. Invalid parse → false (fail closed; do not claim rate is active).
// Process-local only — multi-replica shared rate is HOST-008 residual.
func SubjectRateEnabledFromEnviron(getenv func(string) string) bool {
	enabled, _, _ := SubjectRateConfigFromEnviron(getenv)
	return enabled
}

// SubjectRateConfigFromEnviron returns secret-free HOST-006 rate residual knobs
// for admin health / gateway vault (never tokens). Uses ResolveSubjectRateCaps
// on JENKINS_MCP_SUBJECT_RATE_PER_MINUTE / _RATE_BURST.
//
// Empty rate env → enabled with package defaults. Explicit rate 0 → disabled
// with ratePerMinute=0 and rateBurst=0 (burst ignored when rate off). Invalid
// parse → fail closed (false, 0, 0). Process-local only — multi-replica shared
// rate is HOST-008 residual (admin surfaces must not claim shared HA rate).
func SubjectRateConfigFromEnviron(getenv func(string) string) (enabled bool, ratePerMinute, rateBurst int) {
	if getenv == nil {
		getenv = os.Getenv
	}
	rpm, burst, err := ResolveSubjectRateCaps(
		getenv(EnvSubjectRatePerMinute),
		getenv(EnvSubjectRateBurst),
	)
	if err != nil {
		return false, 0, 0
	}
	if rpm <= 0 {
		return false, 0, 0
	}
	return true, rpm, burst
}

// subjectBucket is one token bucket (subject or process).
type subjectBucket struct {
	tokens     float64
	capacity   float64
	refillPerS float64
	last       time.Time
}

func (b *subjectBucket) refill(now time.Time) {
	if b.last.IsZero() {
		b.last = now
		return
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed <= 0 {
		return
	}
	b.tokens += elapsed * b.refillPerS
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
}

func (b *subjectBucket) take(n float64) bool {
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// SubjectRateLimiter enforces per-subject tool dispatch rate via token bucket
// under an optional process-wide rate ceiling.
//
// Keys are subjectKey strings (prefer SubjectKey / SubjectKeyParts =
// tenant|subject|profile). Never put tokens in keys. Empty subjectKey fails
// closed on Allow.
//
// Thread-safe. Process-local by default. Optional same-host multi-process share
// uses FileSubjectRateLimiter via JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH
// (HOST-008 Done* lite). Multi-pod shared rate remains residual.
type SubjectRateLimiter struct {
	ratePerMinute int
	burst         int
	processRPM    int
	processBurst  int

	mu        sync.Mutex
	bySubject map[string]*subjectBucket
	process   subjectBucket
	now       func() time.Time
}

// NewSubjectRateLimiter builds a per-subject rate limiter.
//
// ratePerMinute ≤ 0 disables (returns a limiter that rejects construction use —
// prefer nil wire). Callers should not construct when disabled; Allow on a
// zero-rate limiter fails closed as CodeQuota.
//
// Non-positive burst → DefaultSubjectRateBurst.
// Non-positive processMaxPerMinute → DefaultProcessRatePerMinute.
// Non-positive processBurst → DefaultProcessRateBurst.
// Values above absolute ceilings are clamped down.
//
// When burst > ratePerMinute and ratePerMinute > 0, burst is left as-is so short
// bursts are allowed (token bucket capacity independent of sustained rate).
func NewSubjectRateLimiter(ratePerMinute, burst, processMaxPerMinute, processBurst int) *SubjectRateLimiter {
	if ratePerMinute < 0 {
		ratePerMinute = 0
	}
	if ratePerMinute > AbsoluteMaxSubjectRatePerMinute {
		ratePerMinute = AbsoluteMaxSubjectRatePerMinute
	}
	if burst <= 0 {
		burst = DefaultSubjectRateBurst
	}
	if burst > AbsoluteMaxSubjectRateBurst {
		burst = AbsoluteMaxSubjectRateBurst
	}
	// Burst of 0 after clamp is unusable; keep at least 1 when rate is enabled.
	if ratePerMinute > 0 && burst < 1 {
		burst = 1
	}
	if processMaxPerMinute <= 0 {
		processMaxPerMinute = DefaultProcessRatePerMinute
	}
	if processMaxPerMinute > AbsoluteMaxProcessRatePerMinute {
		processMaxPerMinute = AbsoluteMaxProcessRatePerMinute
	}
	if processBurst <= 0 {
		processBurst = DefaultProcessRateBurst
	}
	if processBurst > AbsoluteMaxProcessRateBurst {
		processBurst = AbsoluteMaxProcessRateBurst
	}
	if processBurst < 1 {
		processBurst = 1
	}

	refillProc := float64(processMaxPerMinute) / 60.0
	return &SubjectRateLimiter{
		ratePerMinute: ratePerMinute,
		burst:         burst,
		processRPM:    processMaxPerMinute,
		processBurst:  processBurst,
		bySubject:     make(map[string]*subjectBucket),
		process: subjectBucket{
			tokens:     float64(processBurst),
			capacity:   float64(processBurst),
			refillPerS: refillProc,
		},
		now: time.Now,
	}
}

// RatePerMinute returns the effective per-subject sustained rate.
func (l *SubjectRateLimiter) RatePerMinute() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ratePerMinute
}

// Burst returns the effective per-subject burst capacity.
func (l *SubjectRateLimiter) Burst() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.burst
}

// ProcessRatePerMinute returns the effective process-wide sustained rate.
func (l *SubjectRateLimiter) ProcessRatePerMinute() int {
	if l == nil {
		return 0
	}
	return l.processRPM
}

// ProcessBurst returns the effective process-wide burst capacity.
func (l *SubjectRateLimiter) ProcessBurst() int {
	if l == nil {
		return 0
	}
	return l.processBurst
}

// LowerRate reduces per-subject sustained rate and/or burst when the requested
// values are positive and strictly smaller than the current live values.
//
// Policy/overlay may only lower serve-bootstrap rate — never raise (HOST-006).
// Semantics:
//   - perMin <= 0 → leave rate unchanged (empty / omitted)
//   - burst <= 0 → leave burst unchanged
//   - requested values are clamped to [MinSubjectRate*, AbsoluteMaxSubjectRate*]
//     then applied only when still strictly below current
//   - never raises above absolute ceilings or current live values
//   - does not change process-wide ceilings
//   - updates existing subject buckets' refill/capacity (tokens clamped to new capacity)
//
// Returns true when either dimension changed. Nil receiver is a no-op false.
// Raising rate above the live value still requires process restart with a higher
// env/bootstrap (overlay alone never elevates).
func (l *SubjectRateLimiter) LowerRate(perMin, burst int) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	changed := false
	if perMin > 0 {
		want := perMin
		if want > AbsoluteMaxSubjectRatePerMinute {
			want = AbsoluteMaxSubjectRatePerMinute
		}
		if want < MinSubjectRatePerMinute {
			want = MinSubjectRatePerMinute
		}
		if want < l.ratePerMinute {
			l.ratePerMinute = want
			refill := float64(want) / 60.0
			for _, b := range l.bySubject {
				if b == nil {
					continue
				}
				b.refillPerS = refill
			}
			changed = true
		}
	}
	if burst > 0 {
		want := burst
		if want > AbsoluteMaxSubjectRateBurst {
			want = AbsoluteMaxSubjectRateBurst
		}
		if want < MinSubjectRateBurst {
			want = MinSubjectRateBurst
		}
		if want < l.burst {
			l.burst = want
			cap := float64(want)
			for _, b := range l.bySubject {
				if b == nil {
					continue
				}
				b.capacity = cap
				if b.tokens > cap {
					b.tokens = cap
				}
			}
			changed = true
		}
	}
	return changed
}

// SetNow injects a clock for tests. Nil now is ignored.
func (l *SubjectRateLimiter) SetNow(now func() time.Time) {
	if l == nil || now == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Allow consumes one token for subjectKey. Fail closed:
//   - empty / invalid subjectKey → invalid_argument
//   - ratePerMinute == 0 (disabled residual constructed) → CodeQuota
//   - subject bucket empty → CodeQuota
//   - process bucket empty → CodeQuota
//
// Nil limiter is a no-op success (unlimited; tests / stdio / rate disabled wire).
func (l *SubjectRateLimiter) Allow(subjectKey string) error {
	if l == nil {
		return nil
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		return apperr.New(apperr.CodeInvalidArgument, "subject key is required for multi-tenant rate limit")
	}
	if err := ValidateSubjectKey(key); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "subject key is invalid for multi-tenant rate limit")
	}
	if l.ratePerMinute <= 0 {
		return apperr.New(apperr.CodeQuota, "subject tool rate limit disabled residual rejects all")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.bySubject == nil {
		l.bySubject = make(map[string]*subjectBucket)
	}

	// Process ceiling first so a single subject cannot exhaust process tokens
	// without checking process — then subject, then commit both.
	l.process.refill(now)
	if !l.process.take(1) {
		// Refill already advanced last; do not refund — deny without subject take.
		return apperr.New(apperr.CodeQuota, "process tool rate budget exceeded")
	}

	b := l.bySubject[key]
	if b == nil {
		b = &subjectBucket{
			tokens:     float64(l.burst),
			capacity:   float64(l.burst),
			refillPerS: float64(l.ratePerMinute) / 60.0,
			last:       now,
		}
		l.bySubject[key] = b
	} else {
		b.refill(now)
	}
	if !b.take(1) {
		// Refund process token so Alice's empty bucket does not burn process
		// budget that Bob still needs (fair-share isolation).
		l.process.tokens += 1
		if l.process.tokens > l.process.capacity {
			l.process.tokens = l.process.capacity
		}
		return apperr.New(apperr.CodeQuota, "subject tool rate budget exceeded")
	}
	return nil
}

// StatusMap is a non-secret summary for doctor / readiness (no subject keys).
func (l *SubjectRateLimiter) StatusMap() map[string]any {
	if l == nil {
		return map[string]any{"configured": false}
	}
	l.mu.Lock()
	subjects := len(l.bySubject)
	rpm := l.ratePerMinute
	burst := l.burst
	l.mu.Unlock()
	return map[string]any{
		"configured":                    true,
		"kind":                          "memory",
		"rate_per_minute":               rpm,
		"burst":                         burst,
		"process_rate_per_minute":       l.processRPM,
		"process_burst":                 l.processBurst,
		"subjects_tracked":              subjects,
		"absolute_max_rate_per_minute":  AbsoluteMaxSubjectRatePerMinute,
		"absolute_max_burst":            AbsoluteMaxSubjectRateBurst,
		"absolute_min_rate_per_minute":  MinSubjectRatePerMinute,
		"absolute_min_burst":            MinSubjectRateBurst,
		"absolute_process_rate_per_min": AbsoluteMaxProcessRatePerMinute,
		"shared_subject_rate_file":      false, // set path → FileSubjectRateLimiter
		"ha_multi_replica":              false, // HOST-008 multi-pod residual
	}
}
