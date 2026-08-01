package audit

import (
	"strings"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
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
