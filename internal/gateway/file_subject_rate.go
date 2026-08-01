package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvGatewaySubjectRatePath is the optional file path for FileSubjectRateLimiter
// (HOST-008 residual lite / HOST-006 multi-process share). When set under
// gateway serve wiring, construct FileSubjectRateLimiter instead of the
// process-local SubjectRateLimiter.
//
// Empty / unset → process-local SubjectRateLimiter (default).
// When set: fail closed if path is invalid (empty after clean / root / ".").
//
// Honesty: same-host multi-process subject rate share only (flock + 0600).
// Not multi-pod shared rate / Redis / HA. Multi-replica shared rate residual.
// File contents are secret-free (subjectKey → bucket state only; never tokens).
const EnvGatewaySubjectRatePath = "JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH"

// FileSubjectRateLimiter is an optional file-backed subject rate coordinator
// (HOST-008 Done* lite). Per-subject token-bucket state under a single JSON
// file with mode 0600; process-wide ceiling remains process-local.
//
// Multi-process safety: process-local mutex + exclusive flock on path+".lock"
// (same primitive as FileAPITokenVault / FileTokenCache). Safe for same-host
// multi-process (e.g. CLI + serve, or multiple local processes) sharing one
// path on a local/shared filesystem. Not multi-pod HA without a shared FS;
// multi-pod shared rate remains residual.
//
// File contents are intentionally secret-free: only subjectKey → tokens/last
// refill timestamps (+ optional last_access for LRU hygiene). Never credentials,
// Bearer tokens, or Authorization material.
// Operators set path via JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH.
//
// Hygiene residual lite (HOST-008): optional MaxSubjects (0 = unlimited) via
// SetMaxSubjects / JENKINS_MCP_GATEWAY_SUBJECT_RATE_MAX_SUBJECTS. On Allow when
// the map is full for a new subject: purge idle full buckets, else evict oldest
// last_access (never the current subject mid-allow when other victims exist).
// File-local only — multi-pod shared rate residual.
//
// Implements the same Allow surface as SubjectRateLimiter (tools.SubjectRateLimiter)
// plus LowerRate / RatePerMinute / Burst for serve overlay wire.
type FileSubjectRateLimiter struct {
	path string

	ratePerMinute int
	burst         int
	processRPM    int
	processBurst  int
	maxSubjects   int // 0 = unlimited

	mu      sync.Mutex
	process subjectBucket
	now     func() time.Time
}

// fileSubjectRateDoc is the on-disk shape (versioned). Keys are subjectKey
// strings; values are bucket state only — never tokens/credentials.
type fileSubjectRateDoc struct {
	Version  int                             `json:"version"`
	Subjects map[string]fileSubjectRateEntry `json:"subjects"`
}

// fileSubjectRateEntry is one subject's durable token-bucket snapshot.
// Capacity and refill rate come from the live process config (not stored).
type fileSubjectRateEntry struct {
	Tokens     float64 `json:"tokens"`
	Last       string  `json:"last"`                  // RFC3339 UTC; empty → treat as now on first use
	LastAccess string  `json:"last_access,omitempty"` // RFC3339 UTC for LRU; empty → fall back to Last
}

// NewFileSubjectRateLimiter constructs a file-backed subject rate limiter at path.
// Parent directories are created on first write with 0700; the state file is 0600.
// Fail closed: empty / invalid path rejected (no silent memory fallthrough).
//
// Rate / burst / process ceilings use the same clamp rules as NewSubjectRateLimiter.
func NewFileSubjectRateLimiter(path string, ratePerMinute, burst, processMaxPerMinute, processBurst int) (*FileSubjectRateLimiter, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway subject rate path is required")
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "gateway subject rate path is invalid")
	}

	// Reuse memory limiter construction for clamp semantics, then copy config.
	base := NewSubjectRateLimiter(ratePerMinute, burst, processMaxPerMinute, processBurst)
	return &FileSubjectRateLimiter{
		path:          clean,
		ratePerMinute: base.ratePerMinute,
		burst:         base.burst,
		processRPM:    base.processRPM,
		processBurst:  base.processBurst,
		process: subjectBucket{
			tokens:     float64(base.processBurst),
			capacity:   float64(base.processBurst),
			refillPerS: float64(base.processRPM) / 60.0,
		},
		now: time.Now,
	}, nil
}

// Path returns the state file path (non-secret operator config).
func (l *FileSubjectRateLimiter) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// SubjectRatePathConfiguredFromEnviron reports whether
// JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH is non-empty (secret-free residual bool).
// Does not validate path usability (serve fails closed on construct when invalid).
// getenv nil → os.Getenv.
func SubjectRatePathConfiguredFromEnviron(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return strings.TrimSpace(getenv(EnvGatewaySubjectRatePath)) != ""
}

// RatePerMinute returns the effective per-subject sustained rate.
func (l *FileSubjectRateLimiter) RatePerMinute() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ratePerMinute
}

// Burst returns the effective per-subject burst capacity.
func (l *FileSubjectRateLimiter) Burst() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.burst
}

// ProcessRatePerMinute returns the effective process-wide sustained rate (process-local).
func (l *FileSubjectRateLimiter) ProcessRatePerMinute() int {
	if l == nil {
		return 0
	}
	return l.processRPM
}

// ProcessBurst returns the effective process-wide burst capacity (process-local).
func (l *FileSubjectRateLimiter) ProcessBurst() int {
	if l == nil {
		return 0
	}
	return l.processBurst
}

// LowerRate reduces per-subject sustained rate and/or burst when the requested
// values are positive and strictly smaller than the current live values.
// Same semantics as SubjectRateLimiter.LowerRate (HOST-006 lower only).
// Process ceilings are unchanged. Durable subject tokens are clamped to the
// new capacity on the next Allow (and best-effort rewrite under flock).
func (l *FileSubjectRateLimiter) LowerRate(perMin, burst int) bool {
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
			changed = true
		}
	}
	if !changed {
		return false
	}
	// Best-effort clamp durable subject tokens to the new capacity so multi-process
	// peers see the tighter budget promptly. Failures leave in-memory rate lowered
	// (Allow still clamps on load); do not surface IO here.
	_ = withVaultFileLock(l.path, func() error {
		doc, err := l.loadLocked()
		if err != nil {
			return err
		}
		cap := float64(l.burst)
		for k, e := range doc.Subjects {
			if e.Tokens > cap {
				e.Tokens = cap
				doc.Subjects[k] = e
			}
		}
		return l.saveLocked(doc)
	})
	return true
}

// SetNow injects a clock for tests. Nil now is ignored.
func (l *FileSubjectRateLimiter) SetNow(now func() time.Time) {
	if l == nil || now == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// SetMaxSubjects bounds the durable subject map (0 = unlimited).
// Negative treated as 0. Enforcement runs on Allow when inserting a new subject
// (file-local hygiene; multi-pod residual). Same knob as SubjectRateLimiter.
func (l *FileSubjectRateLimiter) SetMaxSubjects(n int) {
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
func (l *FileSubjectRateLimiter) MaxSubjects() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.maxSubjects
}

// SubjectsTracked returns durable subject count (non-secret; never keys).
// Best-effort under flock; IO failure → 0.
func (l *FileSubjectRateLimiter) SubjectsTracked() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	path := l.path
	l.mu.Unlock()
	subjects := 0
	_ = withVaultFileLock(path, func() error {
		doc, err := l.loadLocked()
		if err != nil {
			return err
		}
		subjects = len(doc.Subjects)
		return nil
	})
	return subjects
}

// Allow consumes one token for subjectKey against shared file state + process-local
// process ceiling. Fail closed:
//   - empty / invalid subjectKey → invalid_argument
//   - ratePerMinute == 0 → CodeQuota
//   - subject bucket empty → CodeQuota
//   - process bucket empty → CodeQuota
//   - IO / corrupt file → CodeQuota (fail closed; never over-allow)
//
// When MaxSubjects > 0 and subjectKey is new while the map is full: purges
// idle full buckets (if any), else evicts the oldest last_access subject
// (never the current key when other victims exist). If the map is still full
// after eviction (defense-in-depth), fails closed as CodeQuota and does not
// grow past MaxSubjects.
//
// Nil limiter is a no-op success (unlimited residual).
func (l *FileSubjectRateLimiter) Allow(subjectKey string) error {
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

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ratePerMinute <= 0 {
		return apperr.New(apperr.CodeQuota, "subject tool rate limit disabled residual rejects all")
	}
	now := l.now()
	if l.now == nil {
		now = time.Now()
	}

	// Process ceiling first (process-local; not shared across processes).
	l.process.refill(now)
	if !l.process.take(1) {
		return apperr.New(apperr.CodeQuota, "process tool rate budget exceeded")
	}

	var subjectDenied bool
	err := withVaultFileLock(l.path, func() error {
		doc, err := l.loadLocked()
		if err != nil {
			return err
		}
		if doc.Subjects == nil {
			doc.Subjects = make(map[string]fileSubjectRateEntry)
		}

		entry, found := doc.Subjects[key]
		if !found && l.maxSubjects > 0 && len(doc.Subjects) >= l.maxSubjects {
			l.purgeIdleFullFileLocked(doc, now, key)
			for len(doc.Subjects) >= l.maxSubjects {
				if !l.evictOldestFileSubjectLocked(doc, key) {
					break
				}
			}
			// Fail closed if map still full (defense-in-depth; normal new-key
			// admits always free a victim). Never grow past MaxSubjects.
			if len(doc.Subjects) >= l.maxSubjects {
				return apperr.New(apperr.CodeQuota, "subject rate subject map budget exceeded")
			}
		}
		b := l.bucketFromEntry(found, entry, now)
		b.refill(now)
		if !b.take(1) {
			subjectDenied = true
			return nil
		}
		doc.Version = 1
		doc.Subjects[key] = fileSubjectRateEntry{
			Tokens:     b.tokens,
			Last:       b.last.UTC().Format(time.RFC3339Nano),
			LastAccess: now.UTC().Format(time.RFC3339Nano),
		}
		return l.saveLocked(doc)
	})
	if err != nil {
		// Refund process token; fail closed (do not over-allow on IO error).
		l.process.tokens += 1
		if l.process.tokens > l.process.capacity {
			l.process.tokens = l.process.capacity
		}
		return apperr.New(apperr.CodeQuota, "subject tool rate budget unavailable")
	}
	if subjectDenied {
		l.process.tokens += 1
		if l.process.tokens > l.process.capacity {
			l.process.tokens = l.process.capacity
		}
		return apperr.New(apperr.CodeQuota, "subject tool rate budget exceeded")
	}
	return nil
}

// purgeIdleFullFileLocked drops durable subjects at full capacity after refill.
// Never purges protectKey. Mutates doc.Subjects in place. Caller holds process mu + flock.
func (l *FileSubjectRateLimiter) purgeIdleFullFileLocked(doc fileSubjectRateDoc, now time.Time, protectKey string) {
	for k, e := range doc.Subjects {
		if k == protectKey {
			continue
		}
		b := l.bucketFromEntry(true, e, now)
		b.refill(now)
		if b.tokens >= b.capacity && b.capacity > 0 {
			delete(doc.Subjects, k)
		}
	}
}

// evictOldestFileSubjectLocked removes the subject with the oldest last_access
// (fallback: Last refill timestamp; zero timestamps count as oldest).
// Never protectKey when other victims exist. Returns false if nothing evicted.
// Caller holds process mu + flock.
func (l *FileSubjectRateLimiter) evictOldestFileSubjectLocked(doc fileSubjectRateDoc, protectKey string) bool {
	if len(doc.Subjects) == 0 {
		return false
	}
	// Use a sentinel far in the past so zero / missing access sorts as oldest.
	const farPastUnix = 0
	var victim string
	oldestUnix := int64(1<<63 - 1) // max int64
	found := false
	for k, e := range doc.Subjects {
		if k == protectKey {
			continue
		}
		access := parseSubjectRateTime(e.LastAccess)
		if access.IsZero() {
			access = parseSubjectRateTime(e.Last)
		}
		var u int64 = farPastUnix
		if !access.IsZero() {
			u = access.UnixNano()
		}
		if !found || u < oldestUnix {
			victim = k
			oldestUnix = u
			found = true
		}
	}
	if !found || victim == "" {
		return false
	}
	delete(doc.Subjects, victim)
	return true
}

// parseSubjectRateTime parses RFC3339Nano / RFC3339; empty or bad → zero.
func parseSubjectRateTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

// StatusMap is a non-secret summary for doctor / residual-status (no subject keys,
// no path contents, no tokens). HOST-008 residual honesty: shared file lite only.
// Includes subject_rate_max_subjects only when configured (> 0).
func (l *FileSubjectRateLimiter) StatusMap() map[string]any {
	if l == nil {
		return map[string]any{"configured": false}
	}
	l.mu.Lock()
	rpm := l.ratePerMinute
	burst := l.burst
	pathConfigured := l.path != ""
	maxSubj := l.maxSubjects
	l.mu.Unlock()

	subjects := 0
	_ = withVaultFileLock(l.path, func() error {
		doc, err := l.loadLocked()
		if err != nil {
			return err
		}
		subjects = len(doc.Subjects)
		return nil
	})

	out := map[string]any{
		"configured":                    true,
		"kind":                          "file",
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
		"shared_subject_rate_file":      true, // HOST-008 Done* lite same-host
		"path_configured":               pathConfigured,
		"ha_multi_replica":              false, // multi-pod shared rate residual
	}
	if maxSubj > 0 {
		out["subject_rate_max_subjects"] = maxSubj
	}
	return out
}

// bucketFromEntry builds a live subjectBucket from durable state.
// found=false (new subject) → full burst at now.
func (l *FileSubjectRateLimiter) bucketFromEntry(found bool, e fileSubjectRateEntry, now time.Time) *subjectBucket {
	b := &subjectBucket{
		tokens:     float64(l.burst),
		capacity:   float64(l.burst),
		refillPerS: float64(l.ratePerMinute) / 60.0,
		last:       now,
	}
	if !found {
		return b
	}
	b.last = now
	if raw := strings.TrimSpace(e.Last); raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			b.last = t
		} else if t, err := time.Parse(time.RFC3339, raw); err == nil {
			b.last = t
		}
	}
	b.tokens = e.Tokens
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	if b.tokens < 0 {
		b.tokens = 0
	}
	return b
}

func (l *FileSubjectRateLimiter) loadLocked() (fileSubjectRateDoc, error) {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return fileSubjectRateDoc{Version: 1, Subjects: make(map[string]fileSubjectRateEntry)}, nil
		}
		return fileSubjectRateDoc{}, apperr.Wrap(apperr.CodeInternal, "gateway subject rate read failed", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return fileSubjectRateDoc{Version: 1, Subjects: make(map[string]fileSubjectRateEntry)}, nil
	}
	var doc fileSubjectRateDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fileSubjectRateDoc{}, apperr.Wrap(apperr.CodeCorruptCache, "gateway subject rate file is corrupt or unreadable", err)
	}
	if doc.Subjects == nil {
		doc.Subjects = make(map[string]fileSubjectRateEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	// Drop invalid subject keys fail-closed (never apply unknown key shapes).
	for k := range doc.Subjects {
		if err := ValidateSubjectKey(k); err != nil {
			delete(doc.Subjects, k)
		}
	}
	return doc, nil
}

func (l *FileSubjectRateLimiter) saveLocked(doc fileSubjectRateDoc) error {
	if doc.Subjects == nil {
		doc.Subjects = make(map[string]fileSubjectRateEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway subject rate directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway subject rate encode failed", err)
	}
	raw = append(raw, '\n')
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway subject rate write failed", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, l.path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "gateway subject rate rename failed", err)
	}
	_ = os.Chmod(l.path, 0o600)
	return nil
}
