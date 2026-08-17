package correlate_test

import (
	"reflect"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/correlate"
)

// Regression: ExtractFromParams iterated the params map — output order (and,
// over MaxItems, WHICH items survived truncation) depended on Go map iteration
// order. Two identical calls on the same build could return differently
// ordered work items, breaking reproducible evidence. Extraction now iterates
// in sorted key order.
func TestExtractFromParams_DeterministicOrder(t *testing.T) {
	t.Parallel()
	params := map[string]string{
		"zeta":  "fixes PROJ-100",
		"alpha": "refs PROJ-200",
		"mid":   "PROJ-300",
		"beta":  "see PROJ-400 and PROJ-500",
	}
	first := correlate.ExtractFromParams(params, correlate.ExtractOptions{})
	for i := 0; i < 50; i++ {
		got := correlate.ExtractFromParams(params, correlate.ExtractOptions{})
		if !reflect.DeepEqual(got.Items, first.Items) {
			t.Fatalf("iteration %d differs:\nfirst=%v\ngot=%v", i, first.Items, got.Items)
		}
	}
	// And the order follows sorted parameter keys (alpha, beta, mid, zeta).
	if len(first.Items) < 4 {
		t.Fatalf("items: %+v", first.Items)
	}
}

// Over-cap truncation keeps a deterministic subset (the earliest sorted keys).
func TestExtractFromParams_DeterministicTruncation(t *testing.T) {
	t.Parallel()
	params := map[string]string{}
	for _, k := range []string{"k40", "k05", "k20", "k33", "k11", "k02"} {
		params[k] = "fixes PROJ-" + k[1:]
	}
	first := correlate.ExtractFromParams(params, correlate.ExtractOptions{MaxItems: 2})
	for i := 0; i < 50; i++ {
		got := correlate.ExtractFromParams(params, correlate.ExtractOptions{MaxItems: 2})
		if !reflect.DeepEqual(got.Items, first.Items) {
			t.Fatalf("truncated set differs on iteration %d:\nfirst=%v\ngot=%v", i, first.Items, got.Items)
		}
	}
}
