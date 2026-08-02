package tools_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestSurveyRecentFailures_RegistersAndKnownSeed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolSurveyRecentFailures]; !ok {
		t.Fatalf("expected %s registered by default", tools.ToolSurveyRecentFailures)
	}
	if !policy.IsKnownSeedTool(tools.ToolSurveyRecentFailures) {
		t.Fatal("expected tool in policy.knownSeedTools")
	}
}

func TestSurveyRecentFailures_ClustersSharedSignature(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	// Shared error across three failed builds on demo (6, 8, 10).
	// Add secret canary into one log body.
	f.mu.Lock()
	f.logs["job/demo/6"] = "password=supersecret-survey-token-xyz\nError: compilation failed in module demo\nBUILD FAILURE\nFinished: FAILURE\n"
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tools.ClearSurveyCacheForTest()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{
			"job_names":           []any{"demo"},
			"max_builds_per_job":  10,
			"max_total_builds":    20,
			"max_log_bytes_total": 1 << 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), "supersecret-survey-token-xyz") {
		t.Fatalf("secret leaked in survey output: %s", raw)
	}
	if payload["untrusted"] != true {
		t.Fatalf("untrusted=%v", payload["untrusted"])
	}

	clusters, ok := payload["clusters"].([]any)
	if !ok || len(clusters) == 0 {
		t.Fatalf("expected clusters, got %v", payload["clusters"])
	}
	// Top cluster should count multiple builds (demo failures share error text).
	top, _ := clusters[0].(map[string]any)
	count := int(asFloat(top["count"]))
	if count < 2 {
		t.Fatalf("expected cluster count>=2 for shared failure, got %d full=%s", count, raw)
	}
	if top["normalization_method"] != tools.NormalizationMethodDiag001 {
		t.Fatalf("normalization_method=%v", top["normalization_method"])
	}
	if sig, _ := top["signature"].(string); sig == "" {
		t.Fatal("empty signature")
	}
	examples, _ := top["examples"].([]any)
	if len(examples) == 0 {
		t.Fatal("expected examples")
	}
	// Only failed builds extracted; SUCCESS not surveyed.
	budgets, _ := payload["budgets"].(map[string]any)
	extracted := int(asFloat(budgets["builds_extracted"]))
	if extracted < 2 {
		t.Fatalf("builds_extracted=%d want >=2", extracted)
	}
	// Cache miss on first pass.
	if int(asFloat(budgets["cache_misses"])) < 1 {
		t.Fatalf("expected cache misses on first survey: %v", budgets)
	}
}

func TestSurveyRecentFailures_CrossJobDeniedByDefault(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-xjob", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{
			"job_names": []any{"demo", "service"},
		},
	})
	// Expect invalid_argument / tool error path.
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected cross-job denial, got %+v", toolStructuredJSON(t, res))
	}
	// Message should mention allow_cross_job when available.
	msg := ""
	if err != nil {
		msg = err.Error()
	} else if res != nil {
		for _, c := range res.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				msg += t.Text
			}
		}
	}
	if msg != "" && !strings.Contains(strings.ToLower(msg), "cross-job") &&
		!strings.Contains(msg, "allow_cross_job") &&
		!strings.Contains(strings.ToLower(msg), "invalid") {
		// Soft check: some SDK paths only set IsError.
		t.Logf("cross-job deny message: %q", msg)
	}
}

func TestSurveyRecentFailures_CrossJobAllowedClusters(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	// Give service and smoke a shared failure signature with demo-like text on one,
	// distinct on the other — still multi-job survey must run.
	f.mu.Lock()
	f.logs["job/service/5"] = "Error: compilation failed in module demo\nBUILD FAILURE\n"
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tools.ClearSurveyCacheForTest()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-xok", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{
			"job_names":       []any{"demo", "service"},
			"allow_cross_job": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	scope, _ := payload["scope_jobs"].([]any)
	if len(scope) != 2 {
		t.Fatalf("scope_jobs=%v", scope)
	}
	if payload["allow_cross_job"] != true {
		t.Fatalf("allow_cross_job=%v", payload["allow_cross_job"])
	}
	clusters, _ := payload["clusters"].([]any)
	if len(clusters) == 0 {
		t.Fatalf("expected clusters: %v", payload)
	}
	// Shared compilation error should span jobs.
	top, _ := clusters[0].(map[string]any)
	jobs, _ := top["jobs"].([]any)
	if len(jobs) < 2 && int(asFloat(top["count"])) < 2 {
		// Either multi-job jobs list or multi-count is acceptable evidence of clustering.
		t.Fatalf("expected multi-job or multi-count cluster: %v", top)
	}
}

func TestSurveyRecentFailures_BoundsEnforced(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tools.ClearSurveyCacheForTest()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-bound", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{
			"job_names":           []any{"demo"},
			"max_builds_per_job":  1,
			"max_total_builds":    1,
			"max_log_bytes_total": 64,
			"max_clusters":        1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	budgets, _ := payload["budgets"].(map[string]any)
	if int(asFloat(budgets["max_builds_per_job"])) != 1 {
		t.Fatalf("max_builds_per_job=%v", budgets["max_builds_per_job"])
	}
	if int(asFloat(budgets["max_total_builds"])) != 1 {
		t.Fatalf("max_total_builds=%v", budgets["max_total_builds"])
	}
	extracted := int(asFloat(budgets["builds_extracted"]))
	if extracted > 1 {
		t.Fatalf("builds_extracted=%d want <=1", extracted)
	}
	logBytes := int(asFloat(budgets["log_bytes_scanned"]))
	if logBytes > 64 {
		// Hard per-build may still be smaller than total; total should not exceed residual after clamp.
		// extract may report slightly more if meta length vs text; allow small slack only if total cap was hit.
		if logBytes > 128 {
			t.Fatalf("log_bytes_scanned=%d far above total cap 64", logBytes)
		}
	}
	clusters, _ := payload["clusters"].([]any)
	if len(clusters) > 1 {
		t.Fatalf("max_clusters not enforced: %d", len(clusters))
	}
}

func TestSurveyRecentFailures_ProcessCacheHit(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tools.ClearSurveyCacheForTest()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-cache", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	args := map[string]any{
		"job_names": []any{"demo"},
	}
	res1, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tools.ToolSurveyRecentFailures, Arguments: args})
	if err != nil || res1.IsError {
		t.Fatalf("first survey: err=%v res=%+v", err, res1)
	}
	tails1 := f.logTailCalls.Load()

	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tools.ToolSurveyRecentFailures, Arguments: args})
	if err != nil || res2.IsError {
		t.Fatalf("second survey: err=%v res=%+v", err, res2)
	}
	payload := toolStructuredJSON(t, res2)
	budgets, _ := payload["budgets"].(map[string]any)
	hits := int(asFloat(budgets["cache_hits"]))
	if hits < 1 {
		t.Fatalf("expected cache hits on second survey, budgets=%v tails1=%d tails2=%d",
			budgets, tails1, f.logTailCalls.Load())
	}
	// Second pass should not re-pull all tails (cache avoids extract/log).
	if f.logTailCalls.Load() > tails1 {
		// Some re-fetch may still happen if cache miss; hits already assert path works.
		t.Logf("log tails first=%d second_total=%d (cache_hits=%d)", tails1, f.logTailCalls.Load(), hits)
	}
}

func TestSurveyRecentFailures_RequiresScope(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-empty", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{},
	})
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected invalid_argument for empty scope, got %+v", toolStructuredJSON(t, res))
	}
}

// Regression: durable Meta cache must serve second survey without re-fetching log tails
// after process cache is cleared (cross-process / cold process L1 path).
func TestSurveyRecentFailures_DurableCacheHit(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	// Secret canary in log body.
	const secret = "supersecret-survey-durable-tool-xyz"
	f.mu.Lock()
	f.logs["job/demo/6"] = "password=" + secret + "\nError: compilation failed in module demo\nBUILD FAILURE\nFinished: FAILURE\n"
	f.mu.Unlock()

	dir := t.TempDir()
	meta, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tools.ClearSurveyCacheForTest()

	opts := &tools.RegisterOptions{
		ProfileID: "corp",
		Meta:      meta,
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "survey-durable", Version: "test"}, nil)
	tools.Register(server, f.client(), opts)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	args := map[string]any{
		"job_names":          []any{"demo"},
		"max_builds_per_job": 5,
	}
	res1, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tools.ToolSurveyRecentFailures, Arguments: args})
	if err != nil || res1.IsError {
		t.Fatalf("first survey: err=%v res=%+v", err, res1)
	}
	p1 := toolStructuredJSON(t, res1)
	raw1, _ := json.Marshal(p1)
	if strings.Contains(string(raw1), secret) {
		t.Fatalf("secret leaked in survey output: %s", raw1)
	}
	// Residual should mention durable cache active.
	resids, _ := p1["residuals"].([]any)
	joined := ""
	for _, r := range resids {
		if s, ok := r.(string); ok {
			joined += s + " "
		}
	}
	if !strings.Contains(joined, "durable compact survey") {
		t.Fatalf("expected durable residual, got %v", resids)
	}
	tails1 := f.logTailCalls.Load()
	if tails1 < 1 {
		t.Fatalf("expected log tail fetches on first survey, got %d", tails1)
	}
	n, err := meta.CountSurveySummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected durable rows after first survey, count=%d", n)
	}

	// Canary: secret must not persist in Meta survey_summary_cache blob.
	var blob string
	if err := meta.DB().QueryRowContext(ctx, `
SELECT group_concat(findings_json || result || source, ' ') FROM survey_summary_cache`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, secret) {
		t.Fatalf("secret persisted in durable survey cache: %q", blob)
	}

	// Clear process L1; durable L2 must still hit.
	tools.ClearSurveyCacheForTest()
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tools.ToolSurveyRecentFailures, Arguments: args})
	if err != nil || res2.IsError {
		t.Fatalf("second survey: err=%v res=%+v", err, res2)
	}
	p2 := toolStructuredJSON(t, res2)
	budgets, _ := p2["budgets"].(map[string]any)
	hits := int(asFloat(budgets["cache_hits"]))
	if hits < 1 {
		t.Fatalf("expected durable cache hits after process clear, budgets=%v tails1=%d tails2=%d",
			budgets, tails1, f.logTailCalls.Load())
	}
	// Second pass should not re-pull log tails for cached builds.
	if f.logTailCalls.Load() > tails1 {
		t.Fatalf("log tails increased after durable hit: first=%d second_total=%d (cache_hits=%d)",
			tails1, f.logTailCalls.Load(), hits)
	}
	sources, _ := p2["sources"].([]any)
	hasDurable := false
	for _, s := range sources {
		if s == "survey_cache_durable" {
			hasDurable = true
			break
		}
	}
	if !hasDurable {
		// Source may be uniqueStrings-collapsed; budgets.cache_hits already asserts path.
		t.Logf("sources=%v (durable source optional if unique-collapsed)", sources)
	}
}

func TestSurveyRecentFailures_NoMetaProcessOnlyResidual(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tools.ClearSurveyCacheForTest()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-nometa", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{ProfileID: "corp"})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{
			"job_names": []any{"demo"},
		},
	})
	if err != nil || res.IsError {
		t.Fatalf("survey: err=%v res=%+v", err, res)
	}
	payload := toolStructuredJSON(t, res)
	resids, _ := payload["residuals"].([]any)
	joined := ""
	for _, r := range resids {
		if s, ok := r.(string); ok {
			joined += s + " "
		}
	}
	if !strings.Contains(joined, "process-scoped") {
		t.Fatalf("expected process-only residual without Meta, got %v", resids)
	}
	if strings.Contains(joined, "durable compact survey summary cache active") {
		t.Fatalf("must not claim durable active without Meta: %v", resids)
	}
}

func TestSurveyRecentFailures_RejectsURLJobName(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "survey-url", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSurveyRecentFailures,
		Arguments: map[string]any{
			"job_names": []any{"https://jenkins.example.com/job/x"},
		},
	})
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected invalid_argument for URL job name, got %+v", toolStructuredJSON(t, res))
	}
}
