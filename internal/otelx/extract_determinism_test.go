package otelx_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/otelx"
)

// Regression: ExtractFromParams resolved duplicate normalized keys
// ("TRACE_ID" vs "trace-id" normalize identically) by map iteration order —
// which value won varied run to run, so the same build produced different
// extracted trace ids across calls. The winner is now deterministic (the
// smallest original key in sorted order).
func TestExtractFromParams_DuplicateNormalizedKeyDeterministic(t *testing.T) {
	t.Parallel()
	// Valid 32-hex W3C trace ids; three keys normalize to the same trace-id slot.
	params := map[string]string{
		"TRACE_ID":  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"trace-id":  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"Trace_Id":  "cccccccccccccccccccccccccccccccc",
		"unrelated": "x",
	}
	first := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
	for i := 0; i < 100; i++ {
		got := otelx.ExtractFromParams(params, otelx.ExtractOptions{})
		if len(got.Refs) != len(first.Refs) {
			t.Fatalf("ref count differs: %d vs %d", len(got.Refs), len(first.Refs))
		}
		for j := range got.Refs {
			if got.Refs[j] != first.Refs[j] {
				t.Fatalf("iteration %d differs:\nfirst=%v\ngot=%v", i, first.Refs, got.Refs)
			}
		}
	}
	// Deterministic winner: "TRACE_ID" is the smallest original key.
	if len(first.Refs) > 0 {
		found := false
		for _, r := range first.Refs {
			if r.TraceID == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
				found = true
			}
			if r.TraceID == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || r.TraceID == "cccccccccccccccccccccccccccccccc" {
				t.Fatalf("non-deterministic dup winner present: %+v", r)
			}
		}
		if !found {
			t.Fatalf("expected smallest-key winner aaaa…: %+v", first.Refs)
		}
	}
}
