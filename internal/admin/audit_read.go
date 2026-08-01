package admin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
)

// Audit read bounds (UI-002 / docs/admin/api-v1.md).
const (
	DefaultAuditLimit = 50
	MaxAuditLimit     = 200
	// maxRotatedProbe is an upper bound on numbered rotated siblings to
	// consider (audit.jsonl.1 … N). File sink keeps DefaultMaxRotated (3);
	// allow headroom for operator-retained copies without unbounded dir walks.
	maxRotatedProbe = 32
	// maxAuditLine caps a single JSONL audit line (fail closed on huge lines).
	maxAuditLine = 1 << 20 // 1 MiB
)

// Safe profile id: same charset as internal/profile (1–64, alnum start).
var profileIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// rotatedTimestampSuffix matches optional timestamped siblings next to the
// active file (not produced by the default File sink, but accepted if present):
// .<YYYYMMDD…>, .<RFC3339-ish with T/Z/-/:/_>, length-bounded.
// Numbered siblings use pure integer suffixes (audit.jsonl.1) via strconv.
var rotatedTimestampSuffix = regexp.MustCompile(
	`\.([0-9]{8,}[0-9TZz._:-]{0,40})$`,
)

// ValidateProfileID rejects empty, path traversal, absolute paths, and unsafe
// characters. Used for URL path params before any filesystem join.
func ValidateProfileID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	if filepath.IsAbs(id) {
		return apperr.New(apperr.CodeInvalidArgument, "profile id must not be an absolute path")
	}
	if strings.Contains(id, string(filepath.Separator)) ||
		strings.Contains(id, "/") ||
		strings.Contains(id, "\\") {
		return apperr.New(apperr.CodeInvalidArgument, "profile id must not contain path separators")
	}
	if id == "." || id == ".." || strings.Contains(id, "..") {
		return apperr.New(apperr.CodeInvalidArgument, "profile id must not contain path traversal")
	}
	if !profileIDPattern.MatchString(id) {
		return apperr.New(apperr.CodeInvalidArgument,
			"profile id must be 1-64 chars: alphanumeric, dot, underscore, hyphen; start alnum")
	}
	return nil
}

// AuditQuery filters a profile audit JSONL file (tail-oriented).
type AuditQuery struct {
	// Limit is the max number of matching events to return (newest-first).
	// Zero uses DefaultAuditLimit; values above MaxAuditLimit are capped.
	Limit int
	// Type filters by event type (exact match). Empty = all types.
	Type string
	// Before is an exclusive upper bound on event time (RFC3339 parse).
	Before *time.Time
}

// AuditPage is the secret-free audit list response.
type AuditPage struct {
	ProfileID string        `json:"profileId"`
	Events    []audit.Event `json:"events"`
	Truncated bool          `json:"truncated"`
}

// Normalize applies defaults and caps to q.
func (q AuditQuery) Normalize() AuditQuery {
	if q.Limit <= 0 {
		q.Limit = DefaultAuditLimit
	}
	if q.Limit > MaxAuditLimit {
		q.Limit = MaxAuditLimit
	}
	q.Type = strings.TrimSpace(q.Type)
	return q
}

// ProfileAuditPath returns the default active audit JSONL path for profileID
// under XDG data (…/profiles/<id>/audit/audit.jsonl). dataDirOverride, when
// non-empty and absolute, is used as the profile data root instead (profile.DataDir).
func ProfileAuditPath(paths config.Paths, profileID, dataDirOverride string) (string, error) {
	if err := ValidateProfileID(profileID); err != nil {
		return "", err
	}
	root := strings.TrimSpace(dataDirOverride)
	if root != "" {
		if !filepath.IsAbs(root) {
			return "", apperr.New(apperr.CodeInvalidArgument, "profile data dir must be absolute when set")
		}
		clean := filepath.Clean(root)
		return filepath.Join(clean, "audit", audit.DefaultFileName), nil
	}
	base := paths.ProfileDataDir(profileID)
	return filepath.Join(base, "audit", audit.DefaultFileName), nil
}

// ListAuditReadPaths returns JSONL paths to scan oldest-first for a given
// active audit path: optional timestamped siblings (mtime order), numbered
// rotated siblings (… .N … .1 — File sink scheme), then the active file.
//
// Missing paths are omitted when siblings exist. Same-host lite only —
// multi-pod aggregation residual. Exported for tests.
func ListAuditReadPaths(activePath string) []string {
	activePath = strings.TrimSpace(activePath)
	if activePath == "" {
		return nil
	}
	activePath = filepath.Clean(activePath)
	baseName := filepath.Base(activePath)
	dir := filepath.Dir(activePath)

	type numbered struct {
		n    int
		path string
	}
	var nums []numbered
	var stamped []string // non-numeric timestamp-like siblings

	// Prefer directory listing when available so operator-retained .N beyond
	// the default keep count and timestamped names are discovered.
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			name := ent.Name()
			if name == baseName {
				continue
			}
			if !strings.HasPrefix(name, baseName+".") {
				continue
			}
			full := filepath.Join(dir, name)
			suffix := strings.TrimPrefix(name, baseName+".")
			// Numbered: audit.jsonl.1 (File.rotateLocked scheme)
			if n, convErr := strconv.Atoi(suffix); convErr == nil && n >= 1 && n <= maxRotatedProbe {
				nums = append(nums, numbered{n: n, path: full})
				continue
			}
			// Timestamp-like: audit.jsonl.20260101T120000Z (optional naming)
			if rotatedTimestampSuffix.MatchString(name) {
				stamped = append(stamped, full)
			}
		}
	} else {
		// Dir unreadable: fall back to probing .1 … maxRotatedProbe only.
		for i := 1; i <= maxRotatedProbe; i++ {
			p := fmt.Sprintf("%s.%d", activePath, i)
			if fi, statErr := os.Stat(p); statErr == nil && !fi.IsDir() {
				nums = append(nums, numbered{n: i, path: p})
			}
		}
	}

	// Higher N = older (File.rotateLocked shifts active→.1, .1→.2, …).
	sort.Slice(nums, func(i, j int) bool { return nums[i].n > nums[j].n })

	// Timestamped: oldest mtime first (best-effort chronology).
	if len(stamped) > 1 {
		sort.Slice(stamped, func(i, j int) bool {
			fi, ei := os.Stat(stamped[i])
			fj, ej := os.Stat(stamped[j])
			if ei != nil || ej != nil {
				return stamped[i] < stamped[j]
			}
			if !fi.ModTime().Equal(fj.ModTime()) {
				return fi.ModTime().Before(fj.ModTime())
			}
			return stamped[i] < stamped[j]
		})
	}

	out := make([]string, 0, len(nums)+len(stamped)+1)
	// Timestamped first (typically older archives), then numbered rotates, then active.
	out = append(out, stamped...)
	for _, n := range nums {
		out = append(out, n.path)
	}
	// Include active last when it exists; if nothing else exists, still return
	// active so ReadAuditFile can empty-on-NotExist.
	if fi, err := os.Stat(activePath); err == nil && !fi.IsDir() {
		out = append(out, activePath)
	} else if len(out) == 0 {
		out = append(out, activePath)
	}
	return out
}

// ReadAuditFile reads events from a JSONL audit file path and same-host
// rotated siblings (audit.jsonl.1 … N; optional timestamped names).
// Missing active file → empty events when no siblings (not an error).
// Newest matching events first. Scans oldest→newest across the merge set so
// the ring retains the newest Limit matches. Memory is bounded to Limit events.
//
// Corrupt lines are skipped (fail closed per-line). Multi-pod / multi-replica
// aggregation remains residual — this is same-host rotated merge lite only.
func ReadAuditFile(path string, profileID string, q AuditQuery) (AuditPage, error) {
	q = q.Normalize()
	page := AuditPage{
		ProfileID: profileID,
		Events:    []audit.Event{},
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return page, nil
	}

	ring := make([]audit.Event, 0, q.Limit)
	overflow := false
	for _, p := range ListAuditReadPaths(path) {
		if err := appendAuditFileMatches(p, q, &ring, &overflow); err != nil {
			return page, err
		}
	}

	n := len(ring)
	if n == 0 {
		return page, nil
	}
	// Newest-first presentation.
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		ring[i], ring[j] = ring[j], ring[i]
	}
	page.Events = ring
	page.Truncated = overflow
	return page, nil
}

// appendAuditFileMatches streams one JSONL file into the match ring.
// Missing file is a no-op. Other open/read errors fail closed.
// Secrets are never introduced: only audit.Event JSON fields are decoded.
func appendAuditFileMatches(path string, q AuditQuery, ring *[]audit.Event, overflow *bool) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return apperr.Wrap(apperr.CodeInternal, "open audit file", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxAuditLine)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// Skip corrupt lines; do not fail the whole page.
			continue
		}
		// Reject non-event JSON objects (unknown keys are ignored by encoding/json,
		// which would otherwise yield a zero Event that Normalize fills with now).
		if strings.TrimSpace(e.Type) == "" {
			continue
		}
		e = e.Normalize()
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		if q.Before != nil && !q.Before.IsZero() {
			if !e.Time.Before(*q.Before) {
				continue
			}
		}
		if len(*ring) < q.Limit {
			*ring = append(*ring, e)
			continue
		}
		// Drop oldest match in the window; keep only newest Limit.
		copy(*ring, (*ring)[1:])
		(*ring)[q.Limit-1] = e
		*overflow = true
	}
	if err := sc.Err(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "read audit file", err)
	}
	return nil
}
