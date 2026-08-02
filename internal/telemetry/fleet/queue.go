package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/config"
)

// Default queue bounds (MGR-002: drop oldest on overflow; never block MCP).
const (
	DefaultMaxEvents = 64
	DefaultMaxBytes  = 256 << 10 // 256 KiB of JSON payloads
	queueFileName    = "queue.jsonl"
	lastSnapFileName = "last_snapshot.json"
)

// Queue is a bounded, concurrent-safe local event queue with optional file mirror.
// Enqueue never blocks on network and drops oldest entries on overflow.
type Queue struct {
	mu       sync.Mutex
	events   []queued
	maxN     int
	maxBytes int64
	curBytes int64
	dropped  int64
	dir      string // empty ⇒ memory only
}

type queued struct {
	raw []byte
	ev  Event
}

// QueueConfig configures a Queue.
type QueueConfig struct {
	// Dir is the telemetry directory for queue.jsonl + last_snapshot.json.
	// Empty ⇒ in-memory only (still usable for tests / disabled export).
	Dir string
	// MaxEvents defaults to DefaultMaxEvents.
	MaxEvents int
	// MaxBytes defaults to DefaultMaxBytes (sum of JSON payload sizes).
	MaxBytes int64
}

// NewQueue builds a bounded queue. When Dir is set, creates it (0700) and
// loads any existing queue.jsonl (best-effort; corrupt lines skipped).
func NewQueue(cfg QueueConfig) (*Queue, error) {
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = DefaultMaxEvents
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	q := &Queue{
		maxN:     cfg.MaxEvents,
		maxBytes: cfg.MaxBytes,
		dir:      cfg.Dir,
	}
	if cfg.Dir != "" {
		if err := os.MkdirAll(cfg.Dir, dirPerm); err != nil {
			return nil, fmt.Errorf("fleet: queue dir: %w", err)
		}
		_ = os.Chmod(cfg.Dir, dirPerm)
		q.loadFromDisk()
	}
	return q, nil
}

// NewQueueFromPaths opens the default XDG-backed queue.
func NewQueueFromPaths(paths config.Paths) (*Queue, error) {
	return NewQueue(QueueConfig{Dir: TelemetryDir(paths)})
}

// Enqueue appends an event, dropping oldest until within bounds.
// Always non-blocking (no network). Returns false if the event could not be
// marshaled; true when accepted (including after drops).
func (q *Queue) Enqueue(e Event) bool {
	if q == nil {
		return false
	}
	e = SanitizeEvent(e)
	raw, err := MarshalEvent(e)
	if err != nil {
		return false
	}
	// Belt-and-suspenders privacy check.
	if err := ValidateExportJSON(raw); err != nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events = append(q.events, queued{raw: raw, ev: e})
	q.curBytes += int64(len(raw))
	for len(q.events) > q.maxN || q.curBytes > q.maxBytes {
		if len(q.events) == 0 {
			break
		}
		old := q.events[0]
		q.events = q.events[1:]
		q.curBytes -= int64(len(old.raw))
		if q.curBytes < 0 {
			q.curBytes = 0
		}
		q.dropped++
	}
	// Persist last snapshot + rewrite queue file (best-effort; never panics).
	if q.dir != "" {
		_ = q.persistLocked()
		_ = writeLastSnapshot(q.dir, e)
	}
	return true
}

// Depth returns the number of queued events.
func (q *Queue) Depth() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events)
}

// Dropped returns how many events were dropped due to bounds.
func (q *Queue) Dropped() int64 {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// Bytes returns approximate current queue payload size.
func (q *Queue) Bytes() int64 {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.curBytes
}

// PeekAll returns a copy of queued events (oldest first) without removing them.
func (q *Queue) PeekAll() []Event {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Event, len(q.events))
	for i, e := range q.events {
		out[i] = e.ev
	}
	return out
}

// Drain removes and returns up to n events (oldest first). n<=0 drains all.
func (q *Queue) Drain(n int) []Event {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if n <= 0 || n > len(q.events) {
		n = len(q.events)
	}
	out := make([]Event, n)
	for i := 0; i < n; i++ {
		out[i] = q.events[i].ev
		q.curBytes -= int64(len(q.events[i].raw))
	}
	if q.curBytes < 0 {
		q.curBytes = 0
	}
	q.events = append([]queued(nil), q.events[n:]...)
	if q.dir != "" {
		_ = q.persistLocked()
	}
	return out
}

// LastSnapshot loads the last written snapshot from disk (if any).
func LastSnapshot(dir string) (*Event, error) {
	if dir == "" {
		return nil, errString("fleet: no telemetry dir")
	}
	path := filepath.Join(dir, lastSnapFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// LastSnapshotFromPaths loads last_snapshot.json under XDG telemetry dir.
func LastSnapshotFromPaths(paths config.Paths) (*Event, error) {
	return LastSnapshot(TelemetryDir(paths))
}

func writeLastSnapshot(dir string, e Event) error {
	e = SanitizeEvent(e)
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, lastSnapFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), filePerm); err != nil {
		return err
	}
	_ = os.Chmod(tmp, filePerm)
	return os.Rename(tmp, path)
}

func (q *Queue) persistLocked() error {
	if q.dir == "" {
		return nil
	}
	path := filepath.Join(q.dir, queueFileName)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, filePerm)
	if err != nil {
		return err
	}
	for _, e := range q.events {
		if _, err := f.Write(append(e.raw, '\n')); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, filePerm)
	return os.Rename(tmp, path)
}

func (q *Queue) loadFromDisk() {
	path := filepath.Join(q.dir, queueFileName)
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	// Parse JSONL; skip bad lines.
	start := 0
	for start < len(b) {
		end := start
		for end < len(b) && b[end] != '\n' {
			end++
		}
		line := b[start:end]
		start = end + 1
		line = trimSpaceBytes(line)
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		if err := ValidateExportJSON(line); err != nil {
			continue
		}
		raw := append([]byte(nil), line...)
		q.events = append(q.events, queued{raw: raw, ev: e})
		q.curBytes += int64(len(raw))
	}
	// Enforce bounds after load.
	for len(q.events) > q.maxN || q.curBytes > q.maxBytes {
		if len(q.events) == 0 {
			break
		}
		old := q.events[0]
		q.events = q.events[1:]
		q.curBytes -= int64(len(old.raw))
		if q.curBytes < 0 {
			q.curBytes = 0
		}
		q.dropped++
	}
}

func trimSpaceBytes(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c == ' ' || c == '\t' || c == '\r' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return b
}

// Status is a secret-free operator view of fleet telemetry state.
type Status struct {
	Enabled             bool `json:"enabled"`
	ExportURLConfigured bool `json:"export_url_configured"`
	// ExportURLHost is the host portion only when set (never userinfo).
	ExportURLHost       string   `json:"export_url_host,omitempty"`
	QueueDepth          int      `json:"queue_depth"`
	QueueBytes          int64    `json:"queue_bytes"`
	Dropped             int64    `json:"dropped"`
	InstallationID      string   `json:"installation_id,omitempty"`
	CategoriesExported  []string `json:"categories_exported"`
	CategoriesForbidden []string `json:"categories_forbidden"`
	LastSnapshotAt      string   `json:"last_snapshot_at,omitempty"`
	Residual            string   `json:"residual,omitempty"`
	SchemaVersion       int      `json:"schema_version"`
}

// BuildStatus assembles CLI status from current policy + queue.
func BuildStatus(q *Queue, installID string, enabled, urlSet bool, urlHost string) Status {
	st := Status{
		Enabled:             enabled,
		ExportURLConfigured: urlSet,
		ExportURLHost:       urlHost,
		InstallationID:      installID,
		CategoriesExported:  append([]string(nil), ExportedCategories...),
		CategoriesForbidden: append([]string(nil), ForbiddenCategories...),
		SchemaVersion:       SchemaVersion,
		Residual:            residualNotes(enabled, urlSet),
	}
	if q != nil {
		st.QueueDepth = q.Depth()
		st.QueueBytes = q.Bytes()
		st.Dropped = q.Dropped()
		if snap, err := LastSnapshot(q.dir); err == nil && snap != nil {
			st.LastSnapshotAt = snap.Timestamp
		}
	}
	return st
}

// residualNotes is secret-free operator guidance (not free-text logs).
func residualNotes(enabled, urlSet bool) string {
	parts := []string{
		"enterprise fleet_telemetry_force_off overlay pin is wired (env cannot re-enable while force-off is true; serve applies on load/reload)",
		"central analytics / production enablement requires operator privacy review (not production-ready by default)",
		"HSM / true multi-sig t-of-n policy residual unchanged",
	}
	if enabled && !urlSet {
		parts = append(parts, "enabled without export URL: local queue only (no network export)")
	}
	return strings.Join(parts, "; ")
}

// Ensure lastSnapshot timestamp parsing stays timezone-safe for tests.
var _ = time.RFC3339
