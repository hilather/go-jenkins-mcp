package otelx_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/otelx"
)

func TestExtractFromParams_Traceparent(t *testing.T) {
	t.Parallel()
	params := map[string]string{
		"TRACEPARENT": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"BRANCH":      "main",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	if res.Truncated {
		t.Fatal("unexpected truncated")
	}
	if len(res.Refs) != 1 {
		t.Fatalf("refs=%d %+v", len(res.Refs), res.Refs)
	}
	r := res.Refs[0]
	if r.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || r.SpanID != "00f067aa0ba902b7" {
		t.Fatalf("ref=%+v", r)
	}
	if r.Format != otelx.FormatW3CTraceparent {
		t.Fatalf("format=%s", r.Format)
	}
	if r.EvidenceSource != otelx.EvidenceSourceBuildMetadata {
		t.Fatalf("evidence=%s", r.EvidenceSource)
	}
	if r.SourceKey != "TRACEPARENT" {
		t.Fatalf("source_key=%s", r.SourceKey)
	}
}

func TestExtractFromParams_PairedHexIDs(t *testing.T) {
	t.Parallel()
	params := map[string]string{
		"OTEL_TRACE_ID": "4bf92f3577b34da6a3ce929d0e0e4736",
		"OTEL_SPAN_ID":  "00f067aa0ba902b7",
		"SERVICE_NAME":  "payments-api",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	if len(res.Refs) < 2 {
		t.Fatalf("want paired + service, got %+v", res.Refs)
	}
	var sawPair, sawSvc bool
	for _, r := range res.Refs {
		if r.TraceID != "" && r.SpanID != "" {
			sawPair = true
		}
		if r.ServiceName == "payments-api" {
			sawSvc = true
		}
	}
	if !sawPair || !sawSvc {
		t.Fatalf("pair=%v svc=%v refs=%+v", sawPair, sawSvc, res.Refs)
	}
}

func TestExtractFromParams_Datadog(t *testing.T) {
	t.Parallel()
	params := map[string]string{
		"dd.trace_id": "1234567890123456789",
		"DD_SPAN_ID":  "9876543210",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	if len(res.Refs) < 2 {
		t.Fatalf("refs=%+v", res.Refs)
	}
	var sawTrace, sawSpan bool
	for _, r := range res.Refs {
		if r.Format == otelx.FormatDatadogTraceID && r.TraceID != "" {
			sawTrace = true
		}
		if r.Format == otelx.FormatDatadogSpanID && r.SpanID != "" {
			sawSpan = true
		}
	}
	if !sawTrace || !sawSpan {
		t.Fatalf("trace=%v span=%v refs=%+v", sawTrace, sawSpan, res.Refs)
	}
}

func TestExtractFromParams_ResourceAttributes(t *testing.T) {
	t.Parallel()
	params := map[string]string{
		"OTEL_RESOURCE_ATTRIBUTES": "service.name=checkout,service.version=1.2.3",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	if len(res.Refs) != 1 || res.Refs[0].ServiceName != "checkout" {
		t.Fatalf("refs=%+v", res.Refs)
	}
	if res.Refs[0].Format != otelx.FormatOTELResource {
		t.Fatalf("format=%s", res.Refs[0].Format)
	}
}

func TestExtractFromParams_SkipsSensitiveKeys(t *testing.T) {
	t.Parallel()
	// Even if a secret looks like a trace id hex, sensitive key must never be read.
	params := map[string]string{
		"API_TOKEN":    "4bf92f3577b34da6a3ce929d0e0e4736",
		"TRACE_ID":     "4bf92f3577b34da6a3ce929d0e0e4736",
		"secret_trace": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"PASSWORD":     "00f067aa0ba902b7",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	// Only TRACE_ID should contribute (hex trace only, no span).
	if len(res.Refs) != 1 {
		t.Fatalf("want 1 ref, got %+v", res.Refs)
	}
	if res.Refs[0].TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("ref=%+v", res.Refs[0])
	}
	// Ensure no secret values appear as span/service.
	for _, r := range res.Refs {
		if strings.Contains(strings.ToLower(r.SourceKey), "token") ||
			strings.Contains(strings.ToLower(r.SourceKey), "secret") ||
			strings.Contains(strings.ToLower(r.SourceKey), "password") {
			t.Fatalf("sensitive source key leaked: %+v", r)
		}
	}
}

func TestExtractFromParams_RejectsInvalidValues(t *testing.T) {
	t.Parallel()
	params := map[string]string{
		"TRACE_ID":     "not-hex",
		"SPAN_ID":      "tooshort",
		"TRACEPARENT":  "garbage",
		"SERVICE_NAME": strings.Repeat("a", 200),
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	if len(res.Refs) != 0 {
		t.Fatalf("want empty, got %+v", res.Refs)
	}
}

func TestExtractFromParams_MaxRefsCap(t *testing.T) {
	t.Parallel()
	// Force multiple independent refs via many service + datadog + hex fields.
	params := map[string]string{
		"TRACEPARENT":   "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"dd.trace_id":   "42",
		"dd.span_id":    "43",
		"SERVICE_NAME":  "svc-a",
		"OTEL_TRACE_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // different from TRACEPARENT
		"OTEL_SPAN_ID":  "bbbbbbbbbbbbbbbb",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{MaxRefs: 2})
	if res.MaxRefs != 2 {
		t.Fatalf("max=%d", res.MaxRefs)
	}
	if len(res.Refs) != 2 {
		t.Fatalf("refs=%d %+v", len(res.Refs), res.Refs)
	}
	if !res.Truncated {
		t.Fatal("expected truncated")
	}
}

func TestExtractFromParams_HardMaxRefs(t *testing.T) {
	t.Parallel()
	res := otelx.ExtractFromParams(map[string]string{
		"TRACEPARENT": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}, otelx.ExtractOptions{MaxRefs: 1000})
	if res.MaxRefs != otelx.HardMaxRefs {
		t.Fatalf("max=%d want %d", res.MaxRefs, otelx.HardMaxRefs)
	}
}

func TestExtractFromParams_EmptyAndNil(t *testing.T) {
	t.Parallel()
	if r := otelx.ExtractFromParams(nil, otelx.ExtractOptions{}); len(r.Refs) != 0 {
		t.Fatalf("%+v", r)
	}
	if r := otelx.ExtractFromParams(map[string]string{}, otelx.ExtractOptions{}); len(r.Refs) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestExtractFromParams_NoSecretsInNotes(t *testing.T) {
	t.Parallel()
	secret := "super-secret-token-value-XYZ"
	params := map[string]string{
		"TRACEPARENT": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"API_TOKEN":   secret,
		"BRANCH":      "main",
	}
	res := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	blob := ""
	for _, r := range res.Refs {
		blob += r.TraceID + r.SpanID + r.ServiceName + r.SourceKey + r.Note + r.Format
	}
	if strings.Contains(blob, secret) {
		t.Fatal("secret leaked into ref fields")
	}
}
