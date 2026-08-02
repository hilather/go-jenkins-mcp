package tools_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestLiveHardMaxLowerToOnlyLowers(t *testing.T) {
	t.Parallel()
	h := tools.NewLiveHardMax(1024)
	if h.Get() != 1024 {
		t.Fatalf("get=%d", h.Get())
	}
	if h.Ceiling() != 1024 {
		t.Fatalf("ceiling=%d want 1024", h.Ceiling())
	}
	if h.LowerTo(2048) {
		t.Fatal("must not raise")
	}
	if h.Get() != 1024 {
		t.Fatalf("after raise attempt get=%d", h.Get())
	}
	if !h.LowerTo(256) {
		t.Fatal("want lower success")
	}
	if h.Get() != 256 {
		t.Fatalf("get=%d", h.Get())
	}
	if h.LowerTo(256) {
		t.Fatal("equal must not report change")
	}
	if h.LowerTo(0) || h.LowerTo(-1) {
		t.Fatal("non-positive must be ignored")
	}
	if h.Get() != 256 {
		t.Fatalf("get=%d", h.Get())
	}
	// Ceiling stays at construction value after lower.
	if h.Ceiling() != 1024 {
		t.Fatalf("ceiling must stay 1024, got %d", h.Ceiling())
	}
}

// TestLiveHardMaxSetWithinCeilingRaiseAndLower covers Wave 31: raise after prior
// lower within serve-bootstrap ceiling; clamp above ceiling; non-positive no-op.
func TestLiveHardMaxSetWithinCeilingRaiseAndLower(t *testing.T) {
	t.Parallel()
	const ceiling = 4096
	h := tools.NewLiveHardMax(ceiling)
	if h.Ceiling() != ceiling || h.Get() != ceiling {
		t.Fatalf("init get=%d ceiling=%d", h.Get(), h.Ceiling())
	}

	// Lower via SetWithinCeiling.
	if !h.SetWithinCeiling(512) {
		t.Fatal("want lower change")
	}
	if h.Get() != 512 {
		t.Fatalf("get=%d", h.Get())
	}

	// Raise back within ceiling (Wave 31 — mid-serve raise after prior lower).
	if !h.SetWithinCeiling(2048) {
		t.Fatal("want raise within ceiling")
	}
	if h.Get() != 2048 {
		t.Fatalf("get=%d want 2048", h.Get())
	}
	if h.Ceiling() != ceiling {
		t.Fatalf("ceiling mutated=%d", h.Ceiling())
	}

	// Equal → no change.
	if h.SetWithinCeiling(2048) {
		t.Fatal("equal must not report change")
	}

	// Request above ceiling → clamp to ceiling, change true.
	if !h.SetWithinCeiling(ceiling * 2) {
		t.Fatal("want raise clamped to ceiling")
	}
	if h.Get() != ceiling {
		t.Fatalf("get=%d want ceiling %d", h.Get(), ceiling)
	}
	// Already at ceiling; request higher again → no change.
	if h.SetWithinCeiling(ceiling * 4) {
		t.Fatal("already at ceiling; no change")
	}
	if h.Get() != ceiling {
		t.Fatalf("get=%d", h.Get())
	}

	// Non-positive: keep last (do not restore / clear).
	if h.SetWithinCeiling(0) || h.SetWithinCeiling(-1) {
		t.Fatal("non-positive must be ignored")
	}
	if h.Get() != ceiling {
		t.Fatalf("get=%d after non-positive", h.Get())
	}

	// Lower then SetWithinCeiling(0) keeps lowered value (overlay omit semantics).
	if !h.LowerTo(256) {
		t.Fatal("LowerTo")
	}
	if h.SetWithinCeiling(0) {
		t.Fatal("omit must not change")
	}
	if h.Get() != 256 {
		t.Fatalf("keep last after omit get=%d", h.Get())
	}
}

func TestLiveHardMaxCannotExceedCeiling(t *testing.T) {
	t.Parallel()
	h := tools.NewLiveHardMax(1000)
	_ = h.LowerTo(100)
	// SetWithinCeiling clamps; never stores above ceiling.
	_ = h.SetWithinCeiling(1_000_000)
	if h.Get() > h.Ceiling() {
		t.Fatalf("get %d > ceiling %d", h.Get(), h.Ceiling())
	}
	if h.Get() != 1000 {
		t.Fatalf("get=%d want 1000", h.Get())
	}
	// LowerTo still cannot raise even if n is below ceiling.
	if !h.LowerTo(500) {
		t.Fatal("want LowerTo success")
	}
	if h.Get() != 500 {
		t.Fatalf("get=%d", h.Get())
	}
	if h.LowerTo(999) {
		t.Fatal("LowerTo must not raise")
	}
	if h.Get() != 500 {
		t.Fatalf("get=%d after failed raise", h.Get())
	}
}

func TestLiveHardMaxNilSafe(t *testing.T) {
	t.Parallel()
	var h *tools.LiveHardMax
	if h.Get() != 0 {
		t.Fatal("nil Get")
	}
	if h.Ceiling() != 0 {
		t.Fatal("nil Ceiling")
	}
	if h.LowerTo(10) {
		t.Fatal("nil LowerTo")
	}
	if h.SetWithinCeiling(10) {
		t.Fatal("nil SetWithinCeiling")
	}
}

func TestLiveHardMaxDefaultOnNonPositive(t *testing.T) {
	t.Parallel()
	h := tools.NewLiveHardMax(0)
	if h.Get() != tools.DefaultHardMaxBytes || h.Ceiling() != tools.DefaultHardMaxBytes {
		t.Fatalf("get=%d ceiling=%d want default %d", h.Get(), h.Ceiling(), tools.DefaultHardMaxBytes)
	}
	h2 := tools.NewLiveHardMax(-5)
	if h2.Ceiling() != tools.DefaultHardMaxBytes {
		t.Fatalf("ceiling=%d", h2.Ceiling())
	}
}

// TestLiveHardMaxMidServeAffectsNextToolResult proves Wave 25: lowering the
// shared hard max after Register changes EnforceBudget on the next tool call.
// Regression: previously budgets HardMaxBytes were fixed at Register.
func TestLiveHardMaxMidServeAffectsNextToolResult(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Soft target tiny; hard max large enough for a mid-size payload initially.
	const initialHard = 10_000
	const loweredHard = 512
	live := tools.NewLiveHardMax(initialHard)
	budgets := tools.Budgets{TargetBytes: 64, HardMaxBytes: initialHard}

	server := mcp.NewServer(&mcp.Implementation{Name: "live-hard-max", Version: "test"}, nil)
	// Payload ~2 KiB of repeated text — fits under 10k, exceeds 512 hard max.
	type budgetArgs struct{}
	type budgetOut struct {
		Blob string `json:"blob"`
	}
	payload := budgetOut{Blob: strings.Repeat("X", 2000)}

	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Budgets:     budgets,
		LiveHardMax: live,
	}, &mcp.Tool{
		Name:        "test_budget_payload",
		Description: "returns a fixed mid-size structured result",
	}, func(context.Context, *mcp.CallToolRequest, budgetArgs) (*mcp.CallToolResult, budgetOut, error) {
		return &mcp.CallToolResult{}, payload, nil
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// First call: under initial hard max → full payload.
	res1, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_budget_payload", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call1: %v", err)
	}
	m1 := toolStructuredJSON(t, res1)
	raw1, _ := json.Marshal(m1)
	if _, hasTrunc := m1["truncation"]; hasTrunc {
		t.Fatalf("first call should not truncate under hard max %d: %s", initialHard, raw1)
	}
	blob, _ := m1["blob"].(string)
	if !strings.Contains(blob, strings.Repeat("X", 50)) {
		t.Fatalf("first call missing payload body: %s", raw1)
	}

	// Mid-serve lower (policy reload path).
	if !live.LowerTo(loweredHard) {
		t.Fatal("LowerTo should change hard max")
	}

	// Second call: same tool, now truncated.
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_budget_payload", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call2: %v", err)
	}
	m2 := toolStructuredJSON(t, res2)
	raw2, _ := json.Marshal(m2)
	trunc, hasTrunc := m2["truncation"].(map[string]any)
	if !hasTrunc {
		t.Fatalf("second call must return TruncatedResult after LowerTo(%d): %s", loweredHard, raw2)
	}
	if trunc["truncated"] != true && trunc["content_omitted"] != true {
		t.Fatalf("truncation meta incomplete: %v", trunc)
	}
	if strings.Contains(string(raw2), strings.Repeat("X", 100)) {
		t.Fatalf("truncated summary must not embed oversized content: %s", raw2)
	}
	if len(raw2) > loweredHard {
		t.Fatalf("returned JSON len %d exceeds lowered hard max %d", len(raw2), loweredHard)
	}

	// Wave 31: raise within serve-bootstrap ceiling mid-serve → full payload again.
	if !live.SetWithinCeiling(initialHard) {
		t.Fatal("SetWithinCeiling raise within ceiling should change hard max")
	}
	if live.Get() != initialHard {
		t.Fatalf("after raise get=%d want %d", live.Get(), initialHard)
	}
	res3, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "test_budget_payload", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call3: %v", err)
	}
	m3 := toolStructuredJSON(t, res3)
	raw3, _ := json.Marshal(m3)
	if _, hasTrunc := m3["truncation"]; hasTrunc {
		t.Fatalf("third call should not truncate after raise to %d: %s", initialHard, raw3)
	}
	blob3, _ := m3["blob"].(string)
	if !strings.Contains(blob3, strings.Repeat("X", 50)) {
		t.Fatalf("third call missing payload body after raise: %s", raw3)
	}

	// Cannot exceed ceiling: request above bootstrap still clamps.
	if !live.LowerTo(loweredHard) {
		t.Fatal("re-lower")
	}
	if !live.SetWithinCeiling(initialHard * 10) {
		t.Fatal("raise clamped to ceiling should report change from lowered value")
	}
	if live.Get() != initialHard {
		t.Fatalf("clamped get=%d want ceiling %d", live.Get(), initialHard)
	}
	if live.Get() > live.Ceiling() {
		t.Fatalf("get %d > ceiling %d", live.Get(), live.Ceiling())
	}
}
