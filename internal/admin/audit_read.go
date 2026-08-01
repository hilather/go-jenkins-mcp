package admin

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
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
)

// Safe profile id: same charset as internal/profile (1–64, alnum start).
var profileIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

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

// ReadAuditFile reads events from a JSONL audit file path.
// Missing file → empty events (not an error). Newest matching events first.
// Scans the active file only (rotated siblings residual — not merged in v1).
// Memory is bounded: only the last Limit matching events are retained (ring).
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
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return page, nil
		}
		return page, apperr.Wrap(apperr.CodeInternal, "open audit file", err)
	}
	defer func() { _ = f.Close() }()

	// Ring of last Limit matches in file order (oldest of window at index 0).
	ring := make([]audit.Event, 0, q.Limit)
	overflow := false
	sc := bufio.NewScanner(f)
	// Cap line size well above typical audit.Event JSON (fail closed on huge lines).
	const maxLine = 1 << 20 // 1 MiB
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)
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
		e = e.Normalize()
		if q.Type != "" && e.Type != q.Type {
			continue
		}
		if q.Before != nil && !q.Before.IsZero() {
			if !e.Time.Before(*q.Before) {
				continue
			}
		}
		if len(ring) < q.Limit {
			ring = append(ring, e)
			continue
		}
		// Drop oldest match in the window; keep only newest Limit.
		copy(ring, ring[1:])
		ring[q.Limit-1] = e
		overflow = true
	}
	if err := sc.Err(); err != nil {
		return page, apperr.Wrap(apperr.CodeInternal, "read audit file", err)
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
