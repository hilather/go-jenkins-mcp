package gateway

import (
	"strconv"
	"strings"
	"sync"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// HOST-006: per-subject concurrent tool / preview caps under a process ceiling.
// Companion: subject_rate.go (token-bucket rate; SubjectRateLimiter).
//
// Single-process MVP only (HOST-008 multi-replica residual). Policy may only
// reduce these caps — never elevate past process absolute ceilings.
//
// Serve wire (Done*): cmd sets tools.RegisterOptions.SubjectLimiter to a
// *SubjectLimiter and SubjectKey from SubjectKey(CallerFromBoundSubject) when
// --gateway is on. tools.addTool Holds a slot around dispatch (after optional
// rate Allow). AuthGate is Check-only and cannot Release slots — do not model
// concurrent limiting as a pure AuthGate.

const (
	// DefaultMaxConcurrentPerSubject is the default concurrent tool slots per
	// subjectKey when not configured.
	DefaultMaxConcurrentPerSubject = 8
	// AbsoluteMaxConcurrentPerSubject is the hard per-subject ceiling
	// (fail closed; operators cannot raise above this in-process).
	AbsoluteMaxConcurrentPerSubject = 64
	// AbsoluteMaxProcessConcurrentSlots is the process-wide concurrent tool
	// ceiling for multi-tenant host (HOST-006). Independent of Jenkins client
	// AbsoluteMaxConcurrent but same order of magnitude.
	AbsoluteMaxProcessConcurrentSlots = 256
	// DefaultProcessConcurrentSlots is the default process-wide cap when
	// processMax is non-positive at construction.
	DefaultProcessConcurrentSlots = 64

	// EnvSubjectMaxConcurrent is the optional env for per-subject concurrent
	// tool slots (HOST-006 serve wire). Empty → DefaultMaxConcurrentPerSubject.
	EnvSubjectMaxConcurrent = "JENKINS_MCP_SUBJECT_MAX_CONCURRENT"
	// EnvSubjectProcessMaxConcurrent is the optional env for process-wide
	// concurrent tool slots. Empty → DefaultProcessConcurrentSlots.
	EnvSubjectProcessMaxConcurrent = "JENKINS_MCP_SUBJECT_PROCESS_MAX_CONCURRENT"
)

// ResolveSubjectLimiterCaps resolves optional env overrides for NewSubjectLimiter.
// Empty env strings keep package defaults. Invalid (non-integer / negative)
// values fail closed. Values above absolute ceilings are accepted here and
// clamped by NewSubjectLimiter (same as explicit constructor args).
func ResolveSubjectLimiterCaps(perSubjectEnv, processEnv string) (perSubject, process int, err error) {
	perSubject = DefaultMaxConcurrentPerSubject
	process = DefaultProcessConcurrentSlots
	if raw := strings.TrimSpace(perSubjectEnv); raw != "" {
		v, perr := strconv.Atoi(raw)
		if perr != nil || v < 0 {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvSubjectMaxConcurrent+" (non-negative integer; empty = default)")
		}
		perSubject = v
	}
	if raw := strings.TrimSpace(processEnv); raw != "" {
		v, perr := strconv.Atoi(raw)
		if perr != nil || v < 0 {
			return 0, 0, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvSubjectProcessMaxConcurrent+" (non-negative integer; empty = default)")
		}
		process = v
	}
	return perSubject, process, nil
}

// SubjectLimiter enforces per-subject concurrent slots under a process ceiling.
//
// Keys are subjectKey strings (prefer SubjectKey / SubjectKeyParts =
// tenant|subject|profile). Never put tokens in keys. Empty subjectKey fails
// closed on Acquire.
//
// Thread-safe. Not shared across processes (HOST-008 residual).
type SubjectLimiter struct {
	maxPerSubject int
	processMax    int

	mu        sync.Mutex
	total     int
	bySubject map[string]int
}

// NewSubjectLimiter builds a limiter. Non-positive maxPerSubject →
// DefaultMaxConcurrentPerSubject. Non-positive processMax →
// DefaultProcessConcurrentSlots. Values above absolute ceilings are clamped
// down (fail closed toward a finite bound; never silent elevation past abs).
//
// When maxPerSubject > processMax after normalize, maxPerSubject is reduced to
// processMax so a single subject cannot exceed the process envelope.
func NewSubjectLimiter(maxPerSubject, processMax int) *SubjectLimiter {
	if maxPerSubject <= 0 {
		maxPerSubject = DefaultMaxConcurrentPerSubject
	}
	if processMax <= 0 {
		processMax = DefaultProcessConcurrentSlots
	}
	if maxPerSubject > AbsoluteMaxConcurrentPerSubject {
		maxPerSubject = AbsoluteMaxConcurrentPerSubject
	}
	if processMax > AbsoluteMaxProcessConcurrentSlots {
		processMax = AbsoluteMaxProcessConcurrentSlots
	}
	if maxPerSubject > processMax {
		maxPerSubject = processMax
	}
	return &SubjectLimiter{
		maxPerSubject: maxPerSubject,
		processMax:    processMax,
		bySubject:     make(map[string]int),
	}
}

// MaxPerSubject returns the effective per-subject cap.
func (l *SubjectLimiter) MaxPerSubject() int {
	if l == nil {
		return 0
	}
	return l.maxPerSubject
}

// ProcessMax returns the effective process-wide cap.
func (l *SubjectLimiter) ProcessMax() int {
	if l == nil {
		return 0
	}
	return l.processMax
}

// Acquire takes one concurrent slot for subjectKey. Fail closed:
//   - empty subjectKey → invalid_argument
//   - subject at maxPerSubject → CodeQuota
//   - process at processMax → CodeQuota
//
// Callers must Release exactly once per successful Acquire (prefer Hold).
// Nil limiter is a no-op success (unlimited; tests / stdio without multi-tenant).
func (l *SubjectLimiter) Acquire(subjectKey string) error {
	if l == nil {
		return nil
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		return apperr.New(apperr.CodeInvalidArgument, "subject key is required for multi-tenant budget")
	}
	if err := ValidateSubjectKey(key); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "subject key is invalid for multi-tenant budget")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bySubject == nil {
		l.bySubject = make(map[string]int)
	}
	if l.total >= l.processMax {
		return apperr.New(apperr.CodeQuota, "process concurrent tool budget exceeded")
	}
	if l.bySubject[key] >= l.maxPerSubject {
		return apperr.New(apperr.CodeQuota, "subject concurrent tool budget exceeded")
	}
	l.bySubject[key]++
	l.total++
	return nil
}

// Release returns one slot for subjectKey. Safe no-op when undercounted or nil.
// Never panics. Does not free other subjects' slots.
func (l *SubjectLimiter) Release(subjectKey string) {
	if l == nil {
		return
	}
	key := strings.TrimSpace(subjectKey)
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.bySubject[key]
	if n <= 0 {
		return
	}
	if n == 1 {
		delete(l.bySubject, key)
	} else {
		l.bySubject[key] = n - 1
	}
	if l.total > 0 {
		l.total--
	}
}

// Hold acquires one slot and returns a release function suitable for defer.
// On acquire error, release is a no-op and err is non-nil.
//
//	release, err := limiter.Hold(gateway.SubjectKey(caller))
//	if err != nil { return err }
//	defer release()
func (l *SubjectLimiter) Hold(subjectKey string) (release func(), err error) {
	if err := l.Acquire(subjectKey); err != nil {
		return func() {}, err
	}
	var once sync.Once
	return func() {
		once.Do(func() { l.Release(subjectKey) })
	}, nil
}

// WithSubjectSlot acquires a slot, runs fn, and always releases (HOST-006).
// Acquire failures return before fn. fn nil is treated as success after acquire.
func (l *SubjectLimiter) WithSubjectSlot(subjectKey string, fn func() error) error {
	release, err := l.Hold(subjectKey)
	if err != nil {
		return err
	}
	defer release()
	if fn == nil {
		return nil
	}
	return fn()
}

// InUse returns held slots for subjectKey and process total (non-secret; doctor).
func (l *SubjectLimiter) InUse(subjectKey string) (subjectN, processN int) {
	if l == nil {
		return 0, 0
	}
	key := strings.TrimSpace(subjectKey)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.bySubject[key], l.total
}

// StatusMap is a non-secret summary for doctor / readiness (no subject keys with
// occupancy — only caps and process total).
func (l *SubjectLimiter) StatusMap() map[string]any {
	if l == nil {
		return map[string]any{"configured": false}
	}
	l.mu.Lock()
	total := l.total
	subjects := len(l.bySubject)
	l.mu.Unlock()
	return map[string]any{
		"configured":                 true,
		"max_per_subject":            l.maxPerSubject,
		"process_max":                l.processMax,
		"process_in_use":             total,
		"subjects_with_slots":        subjects,
		"absolute_max_per_subject":   AbsoluteMaxConcurrentPerSubject,
		"absolute_process_max_slots": AbsoluteMaxProcessConcurrentSlots,
		"ha_multi_replica":           false, // HOST-008 residual
	}
}
