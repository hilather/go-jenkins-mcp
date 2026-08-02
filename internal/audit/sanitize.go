package audit

import (
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// Max field lengths keep audit files small and reduce free-form leak surface.
const (
	maxIDLen     = 128
	maxCodeLen   = 64
	maxToolLen   = 96
	maxActionLen = 64
	maxTypeLen   = 64
)

func sanitizeEvent(e Event) Event {
	e.Type = clip(redact.Secrets(e.Type), maxTypeLen)
	e.ProfileID = clip(redact.Secrets(e.ProfileID), maxIDLen)
	e.PrincipalID = clip(redact.Secrets(e.PrincipalID), maxIDLen)
	e.ExternalSubject = clip(redact.Secrets(e.ExternalSubject), maxIDLen)
	e.SubjectKeyHash = sanitizeSubjectKeyHash(e.SubjectKeyHash)
	e.Tool = clip(redact.Secrets(e.Tool), maxToolLen)
	e.Action = clip(redact.Secrets(e.Action), maxActionLen)
	e.Decision = clip(redact.Secrets(e.Decision), maxCodeLen)
	e.ReasonCode = clip(redact.Secrets(e.ReasonCode), maxCodeLen)
	e.RequestID = clip(redact.Secrets(e.RequestID), maxIDLen)
	e.TargetHash = clip(e.TargetHash, maxIDLen) // already opaque; still length-cap
	// Drop negative byte counters (invalid).
	if e.BytesIn != nil && *e.BytesIn < 0 {
		e.BytesIn = nil
	}
	if e.BytesOut != nil && *e.BytesOut < 0 {
		e.BytesOut = nil
	}
	if e.DurationMs < 0 {
		e.DurationMs = 0
	}
	return e
}

// sanitizeSubjectKeyHash keeps the field opaque: raw subject keys
// (tenant|subject|profile) or oversize free-form values are re-hashed with
// HashOpaque so vault/namespace material never lands in audit JSONL.
func sanitizeSubjectKeyHash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// SubjectKey format always contains '|' when multi-part; never store raw.
	if strings.Contains(s, "|") {
		return HashOpaque(s)
	}
	// Oversize or non-short labels → hash rather than clip raw identity strings.
	if utf8.RuneCountInString(s) > maxIDLen {
		return HashOpaque(s)
	}
	// Expected path: already HashOpaque (16 hex) or short opaque label.
	return clip(redact.Secrets(s), maxIDLen)
}

func clip(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || s == "" {
		return s
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	// Truncate on rune boundary.
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}
