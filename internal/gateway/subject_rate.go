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
//
// Serve wire (Done*): cmd sets tools.RegisterOptions.SubjectRateLimiter when
// --gateway is on and resolved ratePerMinute > 0 (0 = disabled residual).
// tools.addTool calls Allow when limiter and SubjectKey are set. tools does
// not import gateway (FND-004); the tools.SubjectRateLimiter interface is the
// wire surface.

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
	if getenv == nil {
		getenv = os.Getenv
	}
	rpm, _, err := ResolveSubjectRateCaps(getenv(EnvSubjectRatePerMinute), "")
	if err != nil {
		return false
	}
	return rpm > 0
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
// Thread-safe. Not shared across processes (HOST-008 residual).
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
	return l.ratePerMinute
}

// Burst returns the effective per-subject burst capacity.
func (l *SubjectRateLimiter) Burst() int {
	if l == nil {
		return 0
	}
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
	l.mu.Unlock()
	return map[string]any{
		"configured":                    true,
		"rate_per_minute":               l.ratePerMinute,
		"burst":                         l.burst,
		"process_rate_per_minute":       l.processRPM,
		"process_burst":                 l.processBurst,
		"subjects_tracked":              subjects,
		"absolute_max_rate_per_minute":  AbsoluteMaxSubjectRatePerMinute,
		"absolute_max_burst":            AbsoluteMaxSubjectRateBurst,
		"absolute_process_rate_per_min": AbsoluteMaxProcessRatePerMinute,
		"ha_multi_replica":              false, // HOST-008 residual
	}
}
