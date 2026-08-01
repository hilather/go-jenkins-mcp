package gateway

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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
//
// Hygiene residual lite (long-running multi-user gateway):
//   - MaxSubjects (0 = unlimited default): on Acquire when map full for a new
//     subject, evict idle (0 in-use) subjects by oldest lastAccess. Prefer fail
//     closed when every tracked subject still holds slots — never steal live
//     holders (safer than wrong-subject elevation / accounting corruption).
// Process-local only — multi-pod shared concurrency residual.

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
	// EnvGatewaySubjectLimiterMaxSubjects is optional max tracked subjects for
	// SubjectLimiter map hygiene (HOST-006 residual lite). Empty → unlimited (0).
	// Non-negative int; invalid fails closed at resolve. Process-local only —
	// multi-pod residual remains.
	EnvGatewaySubjectLimiterMaxSubjects = "JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS"
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

// ResolveSubjectLimiterMaxSubjects parses optional max-subjects hygiene env raw.
// Empty → 0 (unlimited). Non-negative integer accepted; invalid/negative fails closed.
func ResolveSubjectLimiterMaxSubjects(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument,
			"invalid "+EnvGatewaySubjectLimiterMaxSubjects+" (non-negative integer; empty = unlimited)")
	}
	return v, nil
}

// SubjectLimiterMaxSubjectsFromEnviron resolves
// JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS (secret-free). Empty → 0 unlimited.
// Invalid → error (fail closed at serve / residual resolve). getenv nil → os.Getenv.
func SubjectLimiterMaxSubjectsFromEnviron(getenv func(string) string) (int, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	return ResolveSubjectLimiterMaxSubjects(getenv(EnvGatewaySubjectLimiterMaxSubjects))
}

// subjectSlot is one subject's concurrent slot accounting + LRU touch time.
type subjectSlot struct {
	inUse      int
	lastAccess time.Time
}

// SubjectLimiter enforces per-subject concurrent slots under a process ceiling.
//
// Keys are subjectKey strings (prefer SubjectKey / SubjectKeyParts =
// tenant|subject|profile). Never put tokens in keys. Empty subjectKey fails
// closed on Acquire.
//
// Thread-safe. Not shared across processes (HOST-008 residual).
//
// Hygiene residual lite (HOST-006): MaxSubjects (0 = unlimited) bounds the
// per-process subject map. When MaxSubjects > 0, fully released subjects may
// remain as idle (0 in-use) entries for LRU eviction; when unlimited, Release
// drops zeroed entries immediately (legacy tight map).
type SubjectLimiter struct {
	maxPerSubject int
	processMax    int
	maxSubjects   int // 0 = unlimited

	mu        sync.Mutex
	total     int
	bySubject map[string]*subjectSlot
	now       func() time.Time
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
		bySubject:     make(map[string]*subjectSlot),
		now:           time.Now,
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

// SetNow injects a clock for tests. Nil now is ignored.
func (l *SubjectLimiter) SetNow(now func() time.Time) {
	if l == nil || now == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// SetMaxSubjects bounds the per-process subject map (0 = unlimited).
// Negative treated as 0. Does not immediately evict; enforcement runs on
// Acquire when inserting a new subject. Process-local hygiene only
// (HOST-006 residual lite). When raised from unlimited to a finite cap,
// subsequent Releases may retain idle entries for LRU.
func (l *SubjectLimiter) SetMaxSubjects(n int) {
	if l == nil {
		return
	}
	if n < 0 {
		n = 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxSubjects = n
}

// MaxSubjects returns the configured subject-map cap (0 = unlimited).
func (l *SubjectLimiter) MaxSubjects() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxSubjects
}

// SubjectsTracked returns the number of subject map entries currently tracked
// (includes idle 0 in-use when MaxSubjects hygiene retains them). Non-secret.
func (l *SubjectLimiter) SubjectsTracked() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.bySubject)
}

func (l *SubjectLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Acquire takes one concurrent slot for subjectKey. Fail closed:
//   - empty subjectKey → invalid_argument
//   - subject at maxPerSubject → CodeQuota
//   - process at processMax → CodeQuota
//   - MaxSubjects > 0, new subject, map full, and no idle victims → CodeQuota
//
// When MaxSubjects > 0 and subjectKey is new while the map is full: evicts
// idle (0 in-use) subjects oldest-first by lastAccess. Never evicts subjects
// that still hold slots (prefer fail closed under load).
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
	now := l.clock()
	if l.bySubject == nil {
		l.bySubject = make(map[string]*subjectSlot)
	}
	if l.total >= l.processMax {
		return apperr.New(apperr.CodeQuota, "process concurrent tool budget exceeded")
	}

	slot := l.bySubject[key]
	if slot == nil {
		if l.maxSubjects > 0 && len(l.bySubject) >= l.maxSubjects {
			for len(l.bySubject) >= l.maxSubjects {
				if !l.evictOldestIdleSubjectLocked(key) {
					break
				}
			}
			if len(l.bySubject) >= l.maxSubjects {
				// All remaining subjects still hold slots — fail closed rather
				// than steal live holders (wrong-subject elevation risk).
				return apperr.New(apperr.CodeQuota, "subject limiter subject map budget exceeded")
			}
		}
		slot = &subjectSlot{}
		l.bySubject[key] = slot
	}
	if slot.inUse >= l.maxPerSubject {
		return apperr.New(apperr.CodeQuota, "subject concurrent tool budget exceeded")
	}
	slot.inUse++
	slot.lastAccess = now
	l.total++
	return nil
}

// evictOldestIdleSubjectLocked removes the idle (0 in-use) subject with the
// oldest lastAccess, never protectKey. Returns false if no idle victim exists.
// Caller holds l.mu.
func (l *SubjectLimiter) evictOldestIdleSubjectLocked(protectKey string) bool {
	if len(l.bySubject) == 0 {
		return false
	}
	var victim string
	var oldest time.Time
	first := true
	for k, s := range l.bySubject {
		if k == protectKey || s == nil {
			continue
		}
		if s.inUse > 0 {
			continue // never steal live holders
		}
		access := s.lastAccess
		// Zero lastAccess sorts before any real time (oldest idle free space).
		if first || access.Before(oldest) {
			victim = k
			oldest = access
			first = false
		}
	}
	if victim == "" {
		return false
	}
	delete(l.bySubject, victim)
	return true
}

// Release returns one slot for subjectKey. Safe no-op when undercounted or nil.
// Never panics. Does not free other subjects' slots.
//
// When MaxSubjects == 0 (unlimited), fully released subjects are dropped from
// the map. When MaxSubjects > 0, zeroed entries are retained as idle for LRU
// eviction on later Acquire of new subjects.
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
	slot := l.bySubject[key]
	if slot == nil || slot.inUse <= 0 {
		return
	}
	slot.inUse--
	if l.total > 0 {
		l.total--
	}
	if slot.inUse == 0 {
		if l.maxSubjects > 0 {
			// Retain idle for LRU hygiene; lastAccess already set on last Acquire.
			return
		}
		delete(l.bySubject, key)
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
	if s := l.bySubject[key]; s != nil {
		return s.inUse, l.total
	}
	return 0, l.total
}

// StatusMap is a non-secret summary for doctor / readiness (no subject keys with
// occupancy — only caps and process total).
// Includes subject_limiter_max_subjects only when configured (> 0).
func (l *SubjectLimiter) StatusMap() map[string]any {
	if l == nil {
		return map[string]any{"configured": false}
	}
	l.mu.Lock()
	total := l.total
	tracked := len(l.bySubject)
	active := 0
	for _, s := range l.bySubject {
		if s != nil && s.inUse > 0 {
			active++
		}
	}
	maxSubj := l.maxSubjects
	l.mu.Unlock()
	out := map[string]any{
		"configured":                 true,
		"max_per_subject":            l.maxPerSubject,
		"process_max":                l.processMax,
		"process_in_use":             total,
		"subjects_with_slots":        active,
		"subjects_tracked":           tracked,
		"absolute_max_per_subject":   AbsoluteMaxConcurrentPerSubject,
		"absolute_process_max_slots": AbsoluteMaxProcessConcurrentSlots,
		"ha_multi_replica":           false, // HOST-008 residual
	}
	if maxSubj > 0 {
		out["subject_limiter_max_subjects"] = maxSubj
	}
	return out
}
