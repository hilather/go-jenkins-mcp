package otelx

import (
	"strings"
)

// Traceparent is a parsed W3C traceparent header value
// (https://www.w3.org/TR/trace-context/#traceparent-header).
//
//	{version}-{trace-id}-{parent-id}-{trace-flags}
//
// version is 2 hex digits; trace-id 32 hex; parent-id (span) 16 hex; flags 2 hex.
type Traceparent struct {
	Version    string
	TraceID    string
	SpanID     string // parent-id field in the header
	TraceFlags string
}

// ParseTraceparent parses a W3C traceparent header value.
// Returns ok=false for empty, malformed, all-zero ids, or unsupported version
// other than "00" (version 00 is the only version accepted in MVP).
// Input is trimmed; surrounding whitespace is ignored.
func ParseTraceparent(s string) (tp Traceparent, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxValueLen {
		return Traceparent{}, false
	}
	// Disallow control characters early.
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return Traceparent{}, false
		}
	}
	parts := strings.Split(s, "-")
	if len(parts) != 4 {
		return Traceparent{}, false
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]
	if len(version) != 2 || !isHex(version) {
		return Traceparent{}, false
	}
	// MVP: only version 00 (future versions residual).
	if !strings.EqualFold(version, "00") {
		return Traceparent{}, false
	}
	if !validTraceID(traceID) || !validSpanID(spanID) {
		return Traceparent{}, false
	}
	if len(flags) != 2 || !isHex(flags) {
		return Traceparent{}, false
	}
	return Traceparent{
		Version:    strings.ToLower(version),
		TraceID:    strings.ToLower(traceID),
		SpanID:     strings.ToLower(spanID),
		TraceFlags: strings.ToLower(flags),
	}, true
}

func validTraceID(s string) bool {
	if len(s) != 32 || !isHex(s) {
		return false
	}
	// All-zero forbidden by W3C.
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return true
		}
	}
	return false
}

func validSpanID(s string) bool {
	if len(s) != 16 || !isHex(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return true
		}
	}
	return false
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
