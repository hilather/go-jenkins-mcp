package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Default survey durable-cache bounds (tools may pass lower/higher within reason).
const (
	// DefaultSurveyCacheTTL is the default lifetime of a durable survey summary.
	DefaultSurveyCacheTTL = 5 * time.Minute
	// DefaultSurveyCacheMaxEntries caps on-disk survey summary rows per Meta DB.
	DefaultSurveyCacheMaxEntries = 256
	// SurveyCacheMaxTextField bounds optional redacted text fields in findings_json.
	SurveyCacheMaxTextField = 256
	// SurveyCacheMaxFindings caps findings serialized per build summary.
	SurveyCacheMaxFindings = 15
	// SurveyCacheMaxFindingsJSONBytes fail-closes oversized payloads.
	SurveyCacheMaxFindingsJSONBytes = 16 << 10 // 16 KiB
)

// SurveyCacheKey identifies one compact survey summary (profile+job+build+log budget).
// Different MaxLogBytes values must not share rows (small tail ≠ large scan).
type SurveyCacheKey struct {
	Profile     string
	Job         string
	Build       int64
	MaxLogBytes int
}

// SurveyCacheFinding is one compact, non-secret finding (hashes + short redacted text).
// Never store raw log tails here.
type SurveyCacheFinding struct {
	Signature       string  `json:"sig"`
	Pattern         string  `json:"pat,omitempty"`
	Message         string  `json:"msg,omitempty"`  // short redacted representative text
	Normalized      string  `json:"norm,omitempty"` // short redacted normalized preimage
	ExactSignature  string  `json:"esig,omitempty"`
	EvidenceExcerpt string  `json:"ev,omitempty"` // short redacted
	Confidence      float64 `json:"conf,omitempty"`
	Count           int     `json:"n,omitempty"`
}

// SurveyCacheEntry is a durable compact survey build summary (no log bodies).
type SurveyCacheEntry struct {
	Key        SurveyCacheKey
	Result     string
	Source     string
	LogBytes   int
	Incomplete bool
	Findings   []SurveyCacheFinding
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// ValidateKey checks key fields (fail closed before read/write).
func (k SurveyCacheKey) ValidateKey() error {
	if strings.TrimSpace(k.Profile) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "survey cache profile is required")
	}
	if strings.TrimSpace(k.Job) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "survey cache job is required")
	}
	if k.Build <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "survey cache build must be positive")
	}
	if k.MaxLogBytes <= 0 {
		return apperr.New(apperr.CodeInvalidArgument, "survey cache max_log_bytes must be positive")
	}
	return nil
}

// GetSurveySummary returns a non-expired compact summary, or (nil, nil) on miss.
// Corrupt / unparseable / oversized rows are deleted and treated as miss (fail closed).
// Context cancellation is respected.
func (m *Meta) GetSurveySummary(ctx context.Context, key SurveyCacheKey) (*SurveyCacheEntry, error) {
	if m == nil || m.db == nil {
		return nil, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := key.ValidateKey(); err != nil {
		return nil, err
	}
	profile := strings.TrimSpace(key.Profile)
	job := strings.TrimSpace(key.Job)

	var (
		result, source, findingsJSON, createdAt, expiresAt string
		logBytes, incomplete                               int
	)
	err := m.db.QueryRowContext(ctx, `
SELECT result, source, log_bytes, incomplete, findings_json, created_at, expires_at
FROM survey_summary_cache
WHERE profile = ? AND job = ? AND build = ? AND max_log_bytes = ?`,
		profile, job, key.Build, key.MaxLogBytes,
	).Scan(&result, &source, &logBytes, &incomplete, &findingsJSON, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "survey cache get failed", err)
	}

	exp, perr := time.Parse(time.RFC3339Nano, expiresAt)
	if perr != nil {
		// Corrupt expiry — purge and miss.
		_ = m.deleteSurveySummary(ctx, key)
		return nil, nil
	}
	if time.Now().After(exp) {
		_ = m.deleteSurveySummary(ctx, key)
		return nil, nil
	}

	findings, ok := decodeSurveyFindings(findingsJSON)
	if !ok {
		_ = m.deleteSurveySummary(ctx, key)
		return nil, nil
	}

	created, _ := time.Parse(time.RFC3339Nano, createdAt)
	entry := &SurveyCacheEntry{
		Key:        key,
		Result:     result,
		Source:     source,
		LogBytes:   logBytes,
		Incomplete: incomplete != 0,
		Findings:   findings,
		CreatedAt:  created,
		ExpiresAt:  exp,
	}
	return entry, nil
}

// PutSurveySummary upserts a compact summary with TTL and max-entry eviction.
// Callers must pass only redacted compact fields (no log bodies). Nil findings
// are stored as empty. Lossy on crash is acceptable for cache.
func (m *Meta) PutSurveySummary(ctx context.Context, entry *SurveyCacheEntry, ttl time.Duration, maxEntries int) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if entry == nil {
		return apperr.New(apperr.CodeInvalidArgument, "survey cache entry is nil")
	}
	if err := entry.Key.ValidateKey(); err != nil {
		return err
	}
	if ttl <= 0 {
		ttl = DefaultSurveyCacheTTL
	}
	if maxEntries <= 0 {
		maxEntries = DefaultSurveyCacheMaxEntries
	}

	findingsJSON, err := encodeSurveyFindings(entry.Findings)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	expires := now.Add(ttl)
	profile := strings.TrimSpace(entry.Key.Profile)
	job := strings.TrimSpace(entry.Key.Job)
	result := clampSurveyText(entry.Result, 64)
	source := clampSurveyText(entry.Source, 64)
	logBytes := entry.LogBytes
	if logBytes < 0 {
		logBytes = 0
	}
	incomplete := 0
	if entry.Incomplete {
		incomplete = 1
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	_, err = m.db.ExecContext(ctx, `
INSERT INTO survey_summary_cache(
	profile, job, build, max_log_bytes, result, source, log_bytes, incomplete,
	findings_json, created_at, expires_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(profile, job, build, max_log_bytes) DO UPDATE SET
	result = excluded.result,
	source = excluded.source,
	log_bytes = excluded.log_bytes,
	incomplete = excluded.incomplete,
	findings_json = excluded.findings_json,
	created_at = excluded.created_at,
	expires_at = excluded.expires_at`,
		profile, job, entry.Key.Build, entry.Key.MaxLogBytes,
		result, source, logBytes, incomplete,
		findingsJSON,
		now.Format(time.RFC3339Nano),
		expires.Format(time.RFC3339Nano),
	)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "survey cache put failed", err)
	}

	// Best-effort purge of expired rows (bounded growth).
	_, _ = m.db.ExecContext(ctx, `
DELETE FROM survey_summary_cache WHERE expires_at < ?`,
		now.Format(time.RFC3339Nano))

	// Cap max entries by oldest created_at (lossy eviction OK).
	var n int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM survey_summary_cache`).Scan(&n); err == nil && n > maxEntries {
		// Delete oldest until under cap.
		toDrop := n - maxEntries
		_, _ = m.db.ExecContext(ctx, `
DELETE FROM survey_summary_cache WHERE rowid IN (
	SELECT rowid FROM survey_summary_cache
	ORDER BY created_at ASC, profile ASC, job ASC, build ASC
	LIMIT ?
)`, toDrop)
	}

	entry.CreatedAt = now
	entry.ExpiresAt = expires
	return nil
}

// DeleteSurveySummary removes one key (tests / explicit invalidation).
func (m *Meta) DeleteSurveySummary(ctx context.Context, key SurveyCacheKey) error {
	if m == nil || m.db == nil {
		return apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	if err := key.ValidateKey(); err != nil {
		return err
	}
	return m.deleteSurveySummary(ctx, key)
}

func (m *Meta) deleteSurveySummary(ctx context.Context, key SurveyCacheKey) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err := m.db.ExecContext(ctx, `
DELETE FROM survey_summary_cache
WHERE profile = ? AND job = ? AND build = ? AND max_log_bytes = ?`,
		strings.TrimSpace(key.Profile), strings.TrimSpace(key.Job), key.Build, key.MaxLogBytes)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "survey cache delete failed", err)
	}
	return nil
}

// CountSurveySummaries returns the number of durable survey cache rows (tests/ops).
func (m *Meta) CountSurveySummaries(ctx context.Context) (int, error) {
	if m == nil || m.db == nil {
		return 0, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	var n int
	err := m.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM survey_summary_cache`).Scan(&n)
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeInternal, "survey cache count failed", err)
	}
	return n, nil
}

func encodeSurveyFindings(findings []SurveyCacheFinding) (string, error) {
	if len(findings) == 0 {
		return "[]", nil
	}
	if len(findings) > SurveyCacheMaxFindings {
		findings = findings[:SurveyCacheMaxFindings]
	}
	compact := make([]SurveyCacheFinding, 0, len(findings))
	for _, f := range findings {
		// Defensive clamp: hashes/patterns + short redacted text only.
		compact = append(compact, SurveyCacheFinding{
			Signature:       clampSurveyText(f.Signature, 64),
			Pattern:         clampSurveyText(f.Pattern, 64),
			Message:         clampSurveyText(f.Message, SurveyCacheMaxTextField),
			Normalized:      clampSurveyText(f.Normalized, SurveyCacheMaxTextField),
			ExactSignature:  clampSurveyText(f.ExactSignature, 64),
			EvidenceExcerpt: clampSurveyText(f.EvidenceExcerpt, SurveyCacheMaxTextField),
			Confidence:      f.Confidence,
			Count:           f.Count,
		})
	}
	b, err := json.Marshal(compact)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "survey findings encode failed", err)
	}
	if len(b) > SurveyCacheMaxFindingsJSONBytes {
		return "", apperr.New(apperr.CodeInvalidArgument, "survey findings_json exceeds size bound")
	}
	return string(b), nil
}

// decodeSurveyFindings returns findings and ok=false when corrupt / oversize.
func decodeSurveyFindings(raw string) ([]SurveyCacheFinding, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	if len(raw) > SurveyCacheMaxFindingsJSONBytes {
		return nil, false
	}
	// Must be a JSON array (fail closed on objects / scalars).
	if raw[0] != '[' {
		return nil, false
	}
	var findings []SurveyCacheFinding
	if err := json.Unmarshal([]byte(raw), &findings); err != nil {
		return nil, false
	}
	if len(findings) > SurveyCacheMaxFindings {
		findings = findings[:SurveyCacheMaxFindings]
	}
	// Clamp on read so corrupt long strings never surface.
	for i := range findings {
		findings[i].Signature = clampSurveyText(findings[i].Signature, 64)
		findings[i].Pattern = clampSurveyText(findings[i].Pattern, 64)
		findings[i].Message = clampSurveyText(findings[i].Message, SurveyCacheMaxTextField)
		findings[i].Normalized = clampSurveyText(findings[i].Normalized, SurveyCacheMaxTextField)
		findings[i].ExactSignature = clampSurveyText(findings[i].ExactSignature, 64)
		findings[i].EvidenceExcerpt = clampSurveyText(findings[i].EvidenceExcerpt, SurveyCacheMaxTextField)
	}
	return findings, true
}

func clampSurveyText(s string, max int) string {
	// Collapse newlines so multi-line log tails cannot persist as bodies.
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.Join(strings.Fields(s), " ")
	if max <= 0 || s == "" {
		return s
	}
	if len(s) <= max {
		return s
	}
	// Prefer rune-safe truncation.
	if utf8.ValidString(s) {
		r := []rune(s)
		if len(r) > max {
			return string(r[:max])
		}
		return s
	}
	if len(s) > max {
		return s[:max]
	}
	return s
}
