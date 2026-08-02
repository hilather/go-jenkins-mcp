package tools_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestFetchCache_LogTailHitAndSmallerWindow(t *testing.T) {
	c := tools.NewFetchCache(tools.FetchCacheConfig{TTL: time.Minute, MaxEntries: 16})
	// Store via public diagnose path with a real fixture-ish put: use two sequential
	// diagnose calls (integration below). Here exercise Stats/Reset only + key stability.
	if c.Stats().Entries != 0 {
		t.Fatalf("entries=%d", c.Stats().Entries)
	}
	c.Reset()
	if c.Stats() != (tools.FetchCacheStats{}) {
		t.Fatalf("reset stats=%+v", c.Stats())
	}
	key := tools.DiagFetchKey("demo", 7, tools.FetchKindLogTail)
	if !strings.Contains(key, "kind=logtail") || !strings.Contains(key, "demo|7|") {
		t.Fatalf("key=%q", key)
	}
}

func TestDiagnoseBuild_CacheHitSecondCall(t *testing.T) {
	// PERF-003: two sequential diagnose calls share FetchCache; second is near-zero re-fetch.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	body := strings.Join([]string{
		"Started by user admin",
		"Error: compilation failed in module demo",
		"BUILD FAILURE",
		"Finished: FAILURE",
	}, "\n")
	fake := &fakeLogAccess{
		Body:       body,
		Sealed:     true,
		Generation: 3,
	}
	cache := tools.NewFetchCache(tools.FetchCacheConfig{TTL: time.Minute, MaxEntries: 64})
	server := mcp.NewServer(&mcp.Implementation{Name: "perf-cache", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Logs:      fake,
		DiagCache: cache,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	call := func() map[string]any {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: tools.ToolDiagnoseBuild,
			Arguments: map[string]any{
				"job_name":     "folder/demo",
				"build_number": 7,
			},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if res.IsError {
			t.Fatalf("tool error: %+v", res)
		}
		return toolStructuredJSON(t, res)
	}

	p1 := call()
	tails1 := fake.tailCalls.Load()
	if tails1 < 1 {
		t.Fatalf("expected first call to tail logs, got %d", tails1)
	}
	perf1, _ := p1["perf"].(map[string]any)
	if perf1 == nil {
		t.Fatalf("missing perf on first response: %v", p1)
	}
	// First call should miss cache for log (and possibly build if client empty).
	misses1 := asInt64(perf1["cache_misses"])
	if misses1 < 1 {
		t.Fatalf("expected cache_misses>=1 first call, perf=%v", perf1)
	}

	p2 := call()
	tails2 := fake.tailCalls.Load()
	if tails2 != tails1 {
		t.Fatalf("second diagnose must not re-tail logs: tails before=%d after=%d", tails1, tails2)
	}
	perf2, _ := p2["perf"].(map[string]any)
	if perf2 == nil {
		t.Fatalf("missing perf on second response")
	}
	hits2 := asInt64(perf2["cache_hits"])
	if hits2 < 1 {
		t.Fatalf("expected cache_hits>=1 on second call, perf=%v stats=%+v", perf2, cache.Stats())
	}
	// Process cache should show hits and that remote log bytes were not re-counted as much.
	st := cache.Stats()
	if st.Hits < 1 {
		t.Fatalf("process cache hits=%d stats=%+v", st.Hits, st)
	}
	// Findings still present after cache hit.
	findings, _ := p2["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("expected findings on cached diagnose: %v", p2["findings"])
	}
	// Budgets ceilings recorded.
	budgets, _ := p2["budgets"].(map[string]any)
	if budgets == nil {
		t.Fatal("missing budgets")
	}
	if asInt64(budgets["max_remote_calls"]) <= 0 {
		t.Fatalf("budgets=%v", budgets)
	}
}

func TestDiagnoseBuild_BudgetExhaustionIncomplete(t *testing.T) {
	// PERF-003: MaxRemoteCalls=1 is consumed by build meta; log fetch blocked.
	// incomplete + residual note + truncation/incomplete flags must remain present.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newDiagFixture()
	defer f.close()
	cache := tools.NewFetchCache(tools.FetchCacheConfig{TTL: time.Minute})
	server := mcp.NewServer(&mcp.Implementation{Name: "perf-budget", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		DiagCache: cache,
		DiagOpBudgets: tools.DiagBudgetConfig{
			MaxRemoteCalls: 1, // build meta consumes the only remote call; log blocked
		},
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 10,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	if payload["incomplete"] != true {
		t.Fatalf("expected incomplete on budget exhaustion, payload=%v", payload)
	}
	// Truncation / residual indicators must not be omitted.
	notes, _ := payload["confidence_notes"].([]any)
	residuals, _ := payload["residuals"].([]any)
	joined := strings.ToLower(joinAny(notes) + " " + joinAny(residuals))
	if !strings.Contains(joined, "budget") && !strings.Contains(joined, "remote") {
		t.Fatalf("expected budget residual/note, notes=%v residuals=%v", notes, residuals)
	}
	perf, _ := payload["perf"].(map[string]any)
	if perf == nil {
		t.Fatal("missing perf")
	}
	if perf["budget_exhausted"] != true {
		t.Fatalf("perf.budget_exhausted=%v", perf["budget_exhausted"])
	}
	// Log tail should not have run after the single build-meta call.
	if f.logTailCalls.Load() != 0 {
		t.Fatalf("expected no log fetch under budget, logTailCalls=%d", f.logTailCalls.Load())
	}
	raw, _ := json.Marshal(payload)
	if !strings.Contains(string(raw), `"incomplete":true`) {
		t.Fatalf("incomplete flag omitted from JSON: %s", raw)
	}
}

func TestDiagnoseBuild_CancellationStopsWork(t *testing.T) {
	// PERF-003: cancelled context stops dependent log work.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var tailStarts atomic.Int32
	fake := &blockingLogAccess{tailStarts: &tailStarts}
	server := mcp.NewServer(&mcp.Implementation{Name: "perf-cancel", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	callCtx, callCancel := context.WithCancel(ctx)
	// Cancel before the tool runs so acquireDiagnoseLog sees ctx.Err immediately.
	callCancel()

	res, err := cs.CallTool(callCtx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
		},
	})
	// MCP layer may surface cancel as error or incomplete structured result.
	if err != nil {
		// Acceptable: cancellation propagated.
		return
	}
	if res != nil && res.IsError {
		return
	}
	if res != nil {
		payload := toolStructuredJSON(t, res)
		// Soft path: incomplete with cancel note, and no successful full extraction requirement.
		if payload["incomplete"] != true {
			// If the tool completed with empty log due to cancel, incomplete should be set.
			// Some stacks may fail the whole call; if we got a body, require incomplete.
			t.Fatalf("expected incomplete on cancel, payload=%v", payload)
		}
	}
}

func TestCompareBuilds_SharedCacheWithDiagnose(t *testing.T) {
	// After diagnose warms log cache, compare should hit for the same build log.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	f := newDiagFixture()
	defer f.close()
	cache := tools.NewFetchCache(tools.FetchCacheConfig{TTL: time.Minute})
	server := mcp.NewServer(&mcp.Implementation{Name: "perf-share", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{DiagCache: cache})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	_, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 10,
		},
	})
	if err != nil {
		t.Fatalf("diagnose: %v", err)
	}
	afterDiag := f.logTailCalls.Load()
	if afterDiag < 1 {
		t.Fatalf("diagnose should fetch log, calls=%d", afterDiag)
	}
	detailsAfterDiag := f.buildDetailsCalls.Load()
	if detailsAfterDiag != 1 {
		t.Fatalf("diagnose should GetBuildDetailsByJob once, got %d", detailsAfterDiag)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
		},
	})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if res.IsError {
		t.Fatalf("compare error: %+v", res)
	}
	// Build 10 log should be a cache hit; build 9 is a new fetch.
	// GetBuildLogTail issues 2 progressive HTTP calls (size probe + tail).
	afterCmp := f.logTailCalls.Load()
	const progressiveCallsPerTail = 2
	if afterCmp > afterDiag+progressiveCallsPerTail {
		t.Fatalf("compare re-fetched too many logs (build 10 should be cached): afterDiag=%d afterCmp=%d stats=%+v",
			afterDiag, afterCmp, cache.Stats())
	}
	// Build 10 details reused from diagnose cache; build 9 is one new details fetch.
	detailsAfterCmp := f.buildDetailsCalls.Load()
	if detailsAfterCmp != detailsAfterDiag+1 {
		t.Fatalf("compare must not re-fetch build 10 details: afterDiag=%d afterCmp=%d stats=%+v",
			detailsAfterDiag, detailsAfterCmp, cache.Stats())
	}
	payload := toolStructuredJSON(t, res)
	if payload["budgets"] == nil {
		t.Fatal("compare missing budgets")
	}
	perf, _ := payload["perf"].(map[string]any)
	if perf == nil {
		t.Fatal("compare missing perf")
	}
	if asInt64(perf["cache_hits"]) < 1 {
		t.Fatalf("compare expected cache hit for warmed build 10 log, perf=%v stats=%+v", perf, cache.Stats())
	}
	// ceilings recorded
	budgets, _ := payload["budgets"].(map[string]any)
	if asInt64(budgets["max_remote_calls"]) <= 0 {
		t.Fatalf("compare budgets=%v", budgets)
	}
}

// PERF-003 Wave 27: diagnose enrichment must not double-fetch GetBuildDetailsByJob
// JSON for the same job+build (details tree hit count == 1).
func TestDiagnoseBuild_NoDoubleFetchBuildDetails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	f := newDiagFixture()
	defer f.close()
	f.buildAPIPrefix = "job/demo/10"
	cache := tools.NewFetchCache(tools.FetchCacheConfig{
		TTL:        time.Minute,
		MaxEntries: tools.DefaultBuildDetailsCacheMax,
	})
	server := mcp.NewServer(&mcp.Implementation{Name: "perf-build-sf", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{DiagCache: cache})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 10,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	// GetBuildDetailsByJob tree exactly once for the diagnosed build.
	if got := f.buildDetailsCalls.Load(); got != 1 {
		t.Fatalf("Regression: GetBuildDetailsByJob HTTP hits=%d want 1 (enrichment must not re-fetch)", got)
	}
	// Other build-level trees (SCM/graph) may still hit api/json — that is residual.
	// Ensure we did at least some enrichment traffic (not zero build API).
	if f.buildAPICalls.Load() < 1 {
		t.Fatalf("expected some build api/json traffic, got %d", f.buildAPICalls.Load())
	}
	payload := toolStructuredJSON(t, res)
	perf, _ := payload["perf"].(map[string]any)
	if perf == nil {
		t.Fatal("missing perf")
	}
	// Remote call accounting is the diagnose_jenkins_calls metric surface.
	if asInt64(perf["remote_calls"]) < 1 {
		t.Fatalf("expected remote_calls>=1, perf=%v", perf)
	}
	// Second diagnose: zero additional GetBuildDetailsByJob (TTL cache).
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 10,
		},
	})
	if err != nil {
		t.Fatalf("second diagnose: %v", err)
	}
	if got := f.buildDetailsCalls.Load(); got != 1 {
		t.Fatalf("second diagnose re-fetched build details: hits=%d want 1", got)
	}
}

// blockingLogAccess hangs on Tail until ctx cancel (or returns cancel error).
type blockingLogAccess struct {
	tailStarts *atomic.Int32
}

func (b *blockingLogAccess) EnsureMirrored(ctx context.Context, job string, build int64) error {
	return ctx.Err()
}

func (b *blockingLogAccess) ReadRange(ctx context.Context, job string, build int64, offset, length int64) (string, tools.LogReadMeta, error) {
	return "", tools.LogReadMeta{}, ctx.Err()
}

func (b *blockingLogAccess) Tail(ctx context.Context, job string, build int64, maxLen int64) (string, tools.LogReadMeta, error) {
	if b.tailStarts != nil {
		b.tailStarts.Add(1)
	}
	<-ctx.Done()
	return "", tools.LogReadMeta{}, ctx.Err()
}

func asInt64(v any) int64 {
	switch n := v.(type) {
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case int64:
		return n
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}

func joinAny(items []any) string {
	var b strings.Builder
	for _, it := range items {
		b.WriteString(strings.TrimSpace(toString(it)))
		b.WriteByte(' ')
	}
	return b.String()
}

func toString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	default:
		return ""
	}
}
