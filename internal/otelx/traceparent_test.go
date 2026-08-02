package otelx_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/otelx"
)

func TestParseTraceparent_Valid(t *testing.T) {
	t.Parallel()
	const raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tp, ok := otelx.ParseTraceparent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if tp.Version != "00" {
		t.Fatalf("version=%q", tp.Version)
	}
	if tp.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace=%q", tp.TraceID)
	}
	if tp.SpanID != "00f067aa0ba902b7" {
		t.Fatalf("span=%q", tp.SpanID)
	}
	if tp.TraceFlags != "01" {
		t.Fatalf("flags=%q", tp.TraceFlags)
	}
}

func TestParseTraceparent_WhitespaceAndCase(t *testing.T) {
	t.Parallel()
	raw := "  00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01  "
	tp, ok := otelx.ParseTraceparent(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if tp.TraceID != strings.ToLower("4BF92F3577B34DA6A3CE929D0E0E4736") {
		t.Fatalf("trace=%q", tp.TraceID)
	}
}

func TestParseTraceparent_Rejects(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"not-a-traceparent",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero span
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // unsupported version
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",    // missing flags
		"00-short-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\x00",
		strings.Repeat("a", 300),
	}
	for _, c := range cases {
		if _, ok := otelx.ParseTraceparent(c); ok {
			t.Errorf("expected reject for %q", c)
		}
	}
}
