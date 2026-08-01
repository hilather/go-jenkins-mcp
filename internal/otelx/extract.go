package otelx

import (
	"strconv"
	"strings"
	"unicode"
)

// Bounds for correlation extraction (INT-002).
const (
	// DefaultMaxRefs is the default cap on TraceRef entries returned per build.
	DefaultMaxRefs = 8
	// HardMaxRefs is the absolute ceiling; callers cannot raise past this.
	HardMaxRefs = 16
	// maxValueLen rejects oversized parameter values before parse.
	maxValueLen = 256
	// maxServiceNameLen bounds service name labels.
	maxServiceNameLen = 128
)

// TraceRef is a bounded, non-secret correlation identifier for model/operator use.
// It is not a remote query result; EvidenceSource is always build metadata in MVP.
type TraceRef struct {
	// TraceID is a normalized lowercase hex trace id when known (32 hex for W3C;
	// Datadog may be shorter hex derived from decimal).
	TraceID string `json:"trace_id,omitempty"`
	// SpanID is a normalized lowercase hex span id when known (16 hex for W3C).
	SpanID string `json:"span_id,omitempty"`
	// ServiceName is a short service label when present.
	ServiceName string `json:"service_name,omitempty"`
	// TraceFlags is the W3C flags field when from traceparent.
	TraceFlags string `json:"trace_flags,omitempty"`
	// SourceKey is the original parameter key (as provided, not secret).
	SourceKey string `json:"source_key"`
	// Source is where the value was found (e.g. build_parameter).
	Source string `json:"source"`
	// Format classifies the identifier encoding.
	Format string `json:"format,omitempty"`
	// EvidenceSource labels the evidence origin (jenkins_build_metadata).
	EvidenceSource string `json:"evidence_source"`
	// Note carries residual / freshness guidance (never secrets).
	Note string `json:"note,omitempty"`
}

// ExtractOptions configures ExtractFromParams.
type ExtractOptions struct {
	// MaxRefs caps returned refs (0 ⇒ DefaultMaxRefs; hard-capped at HardMaxRefs).
	MaxRefs int
}

// ExtractResult is the bounded extraction outcome.
type ExtractResult struct {
	Refs      []TraceRef
	Truncated bool
	// Scanned is the number of candidate keys considered.
	Scanned int
	// MaxRefs is the effective cap applied.
	MaxRefs int
}

// ExtractFromParams extracts correlation identifiers from a Jenkins build
// parameter map (name → value). Nil/empty map yields empty result.
//
// Never reads values for sensitive-looking keys. Never returns unvalidated
// values. Does not perform network I/O.
func ExtractFromParams(params map[string]string, opts ExtractOptions) ExtractResult {
	max := opts.MaxRefs
	if max <= 0 {
		max = DefaultMaxRefs
	}
	if max > HardMaxRefs {
		max = HardMaxRefs
	}
	out := ExtractResult{MaxRefs: max}
	if len(params) == 0 {
		return out
	}

	// Index normalized key → original key + value (first wins for dups).
	byNorm := make(map[string]paramEntry, len(params))
	for k, v := range params {
		if k == "" {
			continue
		}
		if isSensitiveKey(k) {
			continue
		}
		nk := normalizeKey(k)
		if nk == "" {
			continue
		}
		if _, exists := byNorm[nk]; exists {
			continue
		}
		byNorm[nk] = paramEntry{origKey: k, value: v}
		out.Scanned++
	}

	var refs []TraceRef
	add := func(r TraceRef) {
		if len(refs) >= max {
			out.Truncated = true
			return
		}
		r.EvidenceSource = EvidenceSourceBuildMetadata
		if r.Source == "" {
			r.Source = SourceBuildParameter
		}
		if r.Note == "" {
			r.Note = "identifier from Jenkins build metadata only; no remote OTEL query"
		}
		// Dedupe exact (trace, span, service, format, source_key).
		for _, existing := range refs {
			if existing.TraceID == r.TraceID &&
				existing.SpanID == r.SpanID &&
				existing.ServiceName == r.ServiceName &&
				existing.Format == r.Format &&
				existing.SourceKey == r.SourceKey {
				return
			}
		}
		refs = append(refs, r)
	}

	// 1) W3C traceparent (highest fidelity single field).
	if e, ok := byNorm["traceparent"]; ok {
		if tp, ok := ParseTraceparent(e.value); ok {
			add(TraceRef{
				TraceID:    tp.TraceID,
				SpanID:     tp.SpanID,
				TraceFlags: tp.TraceFlags,
				SourceKey:  e.origKey,
				Format:     FormatW3CTraceparent,
			})
		}
	}

	// 2) Explicit OTEL/W3C hex ids — pair when both present under sibling keys.
	traceID, traceKey := firstHexTrace(byNorm, "trace_id", "traceid", "otel_trace_id")
	spanID, spanKey := firstHexSpan(byNorm, "span_id", "spanid", "otel_span_id")
	if traceID != "" && spanID != "" {
		// Prefer combined ref; source_key is the trace key.
		add(TraceRef{
			TraceID:   traceID,
			SpanID:    spanID,
			SourceKey: traceKey,
			Format:    FormatHexTraceID,
			Note:      "paired TRACE_ID+SPAN_ID from Jenkins build parameters; no remote OTEL query",
		})
	} else {
		if traceID != "" {
			add(TraceRef{
				TraceID:   traceID,
				SourceKey: traceKey,
				Format:    FormatHexTraceID,
			})
		}
		if spanID != "" {
			add(TraceRef{
				SpanID:    spanID,
				SourceKey: spanKey,
				Format:    FormatHexSpanID,
			})
		}
	}

	// 3) Datadog ids.
	if e, ok := byNorm["dd_trace_id"]; ok {
		if id, ok := parseDatadogID(e.value); ok {
			add(TraceRef{
				TraceID:   id,
				SourceKey: e.origKey,
				Format:    FormatDatadogTraceID,
			})
		}
	}
	if e, ok := byNorm["dd_span_id"]; ok {
		if id, ok := parseDatadogID(e.value); ok {
			add(TraceRef{
				SpanID:    id,
				SourceKey: e.origKey,
				Format:    FormatDatadogSpanID,
			})
		}
	}

	// 4) Service name.
	if name, key, ok := firstServiceName(byNorm); ok {
		add(TraceRef{
			ServiceName: name,
			SourceKey:   key,
			Format:      FormatServiceName,
		})
	}

	// 5) OTEL_RESOURCE_ATTRIBUTES → service.name=
	if e, ok := byNorm["otel_resource_attributes"]; ok {
		if name, ok := parseServiceNameFromResourceAttrs(e.value); ok {
			add(TraceRef{
				ServiceName: name,
				SourceKey:   e.origKey,
				Format:      FormatOTELResource,
			})
		}
	}

	out.Refs = refs
	return out
}

// paramEntry is one non-sensitive parameter after key normalization.
type paramEntry struct {
	origKey string
	value   string
}

func firstHexTrace(byNorm map[string]paramEntry, keys ...string) (id, origKey string) {
	for _, k := range keys {
		e, ok := byNorm[k]
		if !ok {
			continue
		}
		v := strings.TrimSpace(e.value)
		if len(v) > maxValueLen {
			continue
		}
		// Allow optional 0x prefix.
		v = strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
		if validTraceID(v) {
			return strings.ToLower(v), e.origKey
		}
	}
	return "", ""
}

func firstHexSpan(byNorm map[string]paramEntry, keys ...string) (id, origKey string) {
	for _, k := range keys {
		e, ok := byNorm[k]
		if !ok {
			continue
		}
		v := strings.TrimSpace(e.value)
		if len(v) > maxValueLen {
			continue
		}
		v = strings.TrimPrefix(strings.TrimPrefix(v, "0x"), "0X")
		if validSpanID(v) {
			return strings.ToLower(v), e.origKey
		}
	}
	return "", ""
}

func firstServiceName(byNorm map[string]paramEntry) (name, origKey string, ok bool) {
	for _, k := range []string{"service_name", "otel_service_name", "otel_service"} {
		e, found := byNorm[k]
		if !found {
			continue
		}
		n, valid := sanitizeServiceName(e.value)
		if valid {
			return n, e.origKey, true
		}
	}
	return "", "", false
}

func sanitizeServiceName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxServiceNameLen {
		return "", false
	}
	// Printable ASCII / basic unicode letters/digits/.-_ only; no control chars.
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '.', '-', '_', '/', ':', '@':
			continue
		default:
			// Allow limited punctuation common in service names; reject spaces/quotes.
			if r == ' ' {
				return "", false
			}
			// Reject anything that looks like a secret blob (e.g. base64 with +/= only long).
			if !unicode.IsPrint(r) {
				return "", false
			}
		}
	}
	// Reject values that look like hex secrets / tokens (very long hex).
	if len(s) >= 32 && isHex(s) {
		return "", false
	}
	return s, true
}

// parseServiceNameFromResourceAttrs parses OTEL resource attribute lists:
// "service.name=my-svc,service.version=1.0".
func parseServiceNameFromResourceAttrs(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxValueLen {
		return "", false
	}
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		if !strings.EqualFold(key, "service.name") {
			continue
		}
		return sanitizeServiceName(kv[1])
	}
	return "", false
}

// parseDatadogID accepts decimal uint64 or hex (optionally 0x-prefixed).
// Returns lowercase hex without 0x prefix.
func parseDatadogID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxValueLen {
		return "", false
	}
	// Decimal path (Datadog classic).
	if isAllDigits(s) {
		// Bound length to avoid huge-int DoS (uint64 max ~20 digits).
		if len(s) > 20 {
			return "", false
		}
		u, err := strconv.ParseUint(s, 10, 64)
		if err != nil || u == 0 {
			return "", false
		}
		return strings.ToLower(strconv.FormatUint(u, 16)), true
	}
	hex := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if !isHex(hex) || len(hex) == 0 || len(hex) > 32 {
		return "", false
	}
	// Reject all-zero.
	allZero := true
	for i := 0; i < len(hex); i++ {
		if hex[i] != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return "", false
	}
	return strings.ToLower(hex), true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func normalizeKey(k string) string {
	k = strings.TrimSpace(k)
	k = strings.ToLower(k)
	k = strings.ReplaceAll(k, "-", "_")
	// Datadog sometimes uses dd.trace_id
	k = strings.ReplaceAll(k, ".", "_")
	return k
}

// isSensitiveKey rejects parameter names that must never be read for correlation.
// Independent of internal/redact to keep otelx a leaf package.
func isSensitiveKey(name string) bool {
	if name == "" {
		return false
	}
	n := normalizeKey(name)
	switch n {
	case "password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "access_key", "client_secret", "authorization",
		"cookie", "credentials", "credential", "auth", "auth_token",
		"access_token", "refresh_token", "api_token", "jsessionid":
		return true
	}
	for _, frag := range []string{
		"password", "passwd", "secret", "token", "api_key", "apikey",
		"private_key", "access_key", "client_secret", "credential",
		"authorization", "jsessionid",
	} {
		if strings.Contains(n, frag) {
			return true
		}
	}
	return false
}
