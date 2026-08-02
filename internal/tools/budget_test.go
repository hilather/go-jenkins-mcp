package tools_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestEnforceBudgetEmpty(t *testing.T) {
	t.Parallel()
	b := tools.DefaultBudgets()

	// Regression: empty/nil must not panic and must pass.
	out, info, err := tools.EnforceBudget(nil, b)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if out != nil || info != nil {
		t.Fatalf("nil out=%v info=%v", out, info)
	}

	out, info, err = tools.EnforceBudget("", b)
	if err != nil || out != "" || info != nil {
		t.Fatalf("empty string: out=%v info=%v err=%v", out, info, err)
	}

	out, info, err = tools.EnforceBudget(map[string]any{}, b)
	if err != nil {
		t.Fatalf("empty map: %v", err)
	}
	if info != nil {
		t.Fatalf("empty map should be under budget, info=%v", info)
	}
	_ = out
}

func TestEnforceBudgetUnderHardMax(t *testing.T) {
	t.Parallel()
	b := tools.Budgets{TargetBytes: 64, HardMaxBytes: 1024}
	payload := map[string]any{"ok": true, "n": 42}
	out, info, err := tools.EnforceBudget(payload, b)
	if err != nil {
		t.Fatal(err)
	}
	if info != nil && info.Truncated {
		t.Fatalf("should not truncate under hard max: %+v", info)
	}
	got, ok := out.(map[string]any)
	if !ok || got["ok"] != true {
		t.Fatalf("payload mutated or wrong type: %#v", out)
	}
}

func TestEnforceBudgetOverHardMaxTruncates(t *testing.T) {
	t.Parallel()
	// Hard max large enough for truncation summary metadata, small enough that
	// a 10 KiB payload exceeds it (production default is 1 MiB).
	b := tools.Budgets{TargetBytes: 64, HardMaxBytes: 512}
	big := map[string]any{
		"logs": strings.Repeat("A", 10_000),
	}
	out, info, err := tools.EnforceBudget(big, b)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if info == nil || !info.Truncated {
		t.Fatalf("want truncated info, got %+v", info)
	}
	if info.OriginalBytes <= b.HardMaxBytes {
		t.Fatalf("original_bytes=%d should exceed hard max %d", info.OriginalBytes, b.HardMaxBytes)
	}
	if info.ReturnedBytes <= 0 || info.ReturnedBytes > b.HardMaxBytes {
		t.Fatalf("returned_bytes=%d hard=%d", info.ReturnedBytes, b.HardMaxBytes)
	}
	if !info.ContentOmitted {
		t.Fatal("content should be omitted on hard cap")
	}

	// Serialized summary must fit hard max and not contain the huge payload.
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > b.HardMaxBytes {
		t.Fatalf("summary len %d exceeds hard max %d", len(raw), b.HardMaxBytes)
	}
	if strings.Contains(string(raw), strings.Repeat("A", 100)) {
		t.Fatal("truncated summary must not embed oversized content")
	}

	tr, ok := out.(tools.TruncatedResult)
	if !ok {
		// JSON round-trip style map is also acceptable if type changes; accept either.
		m, mok := out.(map[string]any)
		if !mok {
			t.Fatalf("unexpected out type %T", out)
		}
		if _, has := m["truncation"]; !has {
			t.Fatalf("summary missing truncation: %#v", m)
		}
		_ = tr
	} else if !tr.Truncation.Truncated {
		t.Fatal("TruncatedResult.Truncation.Truncated=false")
	}
}

func TestEnforceBudgetOrError(t *testing.T) {
	t.Parallel()
	b := tools.Budgets{TargetBytes: 64, HardMaxBytes: 256}
	big := map[string]string{"x": strings.Repeat("Z", 5_000)}
	_, info, err := tools.EnforceBudgetOrError(big, b, true)
	if err == nil {
		t.Fatal("preferError should yield error on hard cap")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code=%q want quota", apperr.CodeOf(err))
	}
	if info == nil || !info.Truncated {
		t.Fatalf("info=%+v", info)
	}
	// Message must not include payload.
	if strings.Contains(err.Error(), "ZZZZ") {
		t.Fatalf("error leaked payload: %q", err.Error())
	}
}

func TestEnforceBudgetOverTargetUnderHard(t *testing.T) {
	t.Parallel()
	b := tools.Budgets{TargetBytes: 32, HardMaxBytes: 10_000}
	payload := map[string]string{"body": strings.Repeat("b", 200)}
	out, info, err := tools.EnforceBudget(payload, b)
	if err != nil {
		t.Fatal(err)
	}
	if info == nil || !info.OverTarget || info.Truncated {
		t.Fatalf("want over-target non-truncated meta: %+v", info)
	}
	// Original payload preserved under hard max.
	if _, ok := out.(map[string]string); !ok {
		t.Fatalf("type=%T", out)
	}
}

func TestDefaultBudgetsConstants(t *testing.T) {
	t.Parallel()
	b := tools.DefaultBudgets()
	if b.TargetBytes != 64*1024 || b.HardMaxBytes != 1024*1024 {
		t.Fatalf("defaults=%+v (ADR 0010)", b)
	}
	n := tools.Budgets{}.Normalize()
	if n.TargetBytes != tools.DefaultTargetBytes || n.HardMaxBytes != tools.DefaultHardMaxBytes {
		t.Fatalf("normalize zero: %+v", n)
	}
}

func TestClampListLen(t *testing.T) {
	t.Parallel()
	items := []int{1, 2, 3, 4, 5}
	out, rem := tools.ClampListLen(items, 3)
	if len(out) != 3 || rem != 2 {
		t.Fatalf("out=%v rem=%d", out, rem)
	}
	out, rem = tools.ClampListLen(items, 0) // default max is large
	if len(out) != 5 || rem != 0 {
		t.Fatalf("default cap: out=%v rem=%d", out, rem)
	}
}

// Wave 53 Track C / MCP-001 residual honesty: SoftTargetClampApplied is the
// pure predicate for operator-visible target_bytes_clamped serve logging.
func TestSoftTargetClampApplied(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		resolvedTarget int
		hardMax        int
		want           bool
	}{
		{name: "above hard", resolvedTarget: 2_000_000, hardMax: 1_048_576, want: true},
		{name: "equal hard", resolvedTarget: 1_048_576, hardMax: 1_048_576, want: false},
		{name: "below hard", resolvedTarget: 64_000, hardMax: 1_048_576, want: false},
		{name: "zero hard", resolvedTarget: 2_000_000, hardMax: 0, want: false},
		{name: "negative hard", resolvedTarget: 2_000_000, hardMax: -1, want: false},
		{name: "zero target", resolvedTarget: 0, hardMax: 1_048_576, want: false},
		{name: "zero both", resolvedTarget: 0, hardMax: 0, want: false},
		{name: "target one over", resolvedTarget: 1_048_577, hardMax: 1_048_576, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tools.SoftTargetClampApplied(tc.resolvedTarget, tc.hardMax)
			if got != tc.want {
				t.Fatalf("SoftTargetClampApplied(%d, %d)=%v want %v",
					tc.resolvedTarget, tc.hardMax, got, tc.want)
			}
		})
	}
	// Align with Normalize: when target > hard, Normalize clamps and the
	// pre-Normalize SoftTargetClampApplied must report true.
	resolved := tools.DefaultHardMaxBytes + 1
	hard := tools.DefaultHardMaxBytes
	if !tools.SoftTargetClampApplied(resolved, hard) {
		t.Fatal("pre-Normalize excess must report clamp applied")
	}
	b := tools.Budgets{TargetBytes: resolved, HardMaxBytes: hard}.Normalize()
	if b.TargetBytes != hard {
		t.Fatalf("Normalize clamp: TargetBytes=%d want hard=%d", b.TargetBytes, hard)
	}
	// Post-clamp equality is not a further clamp.
	if tools.SoftTargetClampApplied(b.TargetBytes, b.HardMaxBytes) {
		t.Fatal("post-Normalize equal target/hard must not report clamp")
	}
}
