package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiagnoseBuild_RegistersByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolDiagnoseBuild]; !ok {
		t.Fatalf("expected %s registered by default", tools.ToolDiagnoseBuild)
	}
}

func TestDiagnoseBuild_LocalMirrorExtraction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body := strings.Join([]string{
		"Started by user admin",
		"[INFO] Building...",
		"password=supersecret-token-xyz",
		"Error: compilation failed in module demo",
		"BUILD FAILURE",
		"Finished: FAILURE",
	}, "\n")
	fake := &fakeLogAccess{
		Body:       body,
		Sealed:     true,
		Generation: 3,
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-test", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

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
	if fake.tailCalls.Load() < 1 && fake.readCalls.Load() < 1 {
		t.Fatal("expected local log access")
	}

	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), "supersecret-token-xyz") {
		t.Fatalf("secret leaked in diagnose output: %s", raw)
	}
	if strings.Contains(string(raw), body) && len(body) > 200 {
		t.Fatal("full log dump must not appear")
	}
	// Must not echo entire log body as a single field.
	if logs, ok := payload["logs"]; ok && logs != nil {
		t.Fatalf("must not include full logs field: %v", logs)
	}

	if payload["untrusted"] != true {
		t.Fatalf("untrusted=%v", payload["untrusted"])
	}
	if payload["job"] != "folder/demo" {
		t.Fatalf("job=%v", payload["job"])
	}
	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("findings missing: %v", payload["findings"])
	}
	// Top findings should include build_failure or error_prefix.
	summary, _ := payload["summary"].(string)
	if summary == "" {
		t.Fatal("empty summary")
	}
	if !strings.Contains(summary, "folder/demo") {
		t.Fatalf("summary=%q", summary)
	}
	notes, _ := payload["confidence_notes"].([]any)
	if len(notes) == 0 {
		t.Fatal("expected confidence notes")
	}
	sources, _ := payload["sources"].([]any)
	var sawMirror bool
	for _, s := range sources {
		if s == "local_mirror" {
			sawMirror = true
		}
	}
	if !sawMirror {
		t.Fatalf("sources=%v", sources)
	}

	// Budget path: must fit under hard max easily.
	enforced, info, berr := tools.EnforceBudget(payload, tools.DefaultBudgets())
	if berr != nil {
		t.Fatal(berr)
	}
	_ = enforced
	if info != nil && info.Truncated {
		t.Fatalf("unexpected truncation for small diagnose: %+v", info)
	}
}

func TestDiagnoseBuild_RejectsURLJobName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-url", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Logs: &fakeLogAccess{Body: "Error: x", Sealed: true, Generation: 1},
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "https://jenkins.example.com/job/x",
			"build_number": 1,
		},
	})
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected invalid_argument for URL job name, got %+v", toolStructuredJSON(t, res))
	}
}

func TestDiagnoseBuild_OptionalTestsAttached(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeLogAccess{
		Body:       "Tests FAILED\nError: suite boom\n",
		Sealed:     true,
		Generation: 1,
	}
	tests := &fakeTestSource{failures: []tools.TestFailure{
		{Name: "TestFoo", Class: "pkg.Foo", Message: "expected true", Status: "FAILED"},
	}}
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-tests", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Logs:        fake,
		Diagnostics: tools.DiagnoseHelpers{Tests: tests},
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	tf, ok := payload["test_failures"].([]any)
	if !ok || len(tf) != 1 {
		t.Fatalf("test_failures=%v", payload["test_failures"])
	}
	sources, _ := payload["sources"].([]any)
	var sawTests bool
	for _, s := range sources {
		if s == "tests" {
			sawTests = true
		}
	}
	if !sawTests {
		t.Fatalf("sources=%v", sources)
	}
}

func TestDiagnoseBuild_AmbiguousMultipleFindings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body := "Error: alpha\npanic: beta\nBUILD FAILURE\n"
	fake := &fakeLogAccess{Body: body, Sealed: true, Generation: 1}
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-ambig", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 2,
			"max_findings": 5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	findings, _ := payload["findings"].([]any)
	if len(findings) < 2 {
		t.Fatalf("want multiple candidates, got %v", findings)
	}
	notes, _ := payload["confidence_notes"].([]any)
	var sawAmbiguous bool
	for _, n := range notes {
		if s, ok := n.(string); ok && strings.Contains(s, "multiple candidates") {
			sawAmbiguous = true
		}
	}
	if !sawAmbiguous {
		t.Fatalf("expected ambiguous note: %v", notes)
	}
}

func TestDiagnoseBuild_SanitizeCanary(t *testing.T) {
	// Regression: secrets must never appear in diagnose MCP output.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	canary := "hunter2-diagnose-canary-9f3a"
	body := "Error: deploy failed password=" + canary + "\nBUILD FAILURE\n"
	fake := &fakeLogAccess{Body: body, Sealed: true, Generation: 1}
	server := mcp.NewServer(&mcp.Implementation{Name: "diagnose-canary", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 9,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(toolStructuredJSON(t, res))
	if strings.Contains(string(raw), canary) {
		t.Fatalf("canary leaked: %s", raw)
	}
	if !strings.Contains(string(raw), "build_failure") && !strings.Contains(string(raw), "error_prefix") {
		t.Fatalf("lost diagnostic signal after redact: %s", raw)
	}
}

// fakeTestSource implements tools.TestFailureSource for tests.
type fakeTestSource struct {
	failures []tools.TestFailure
	err      error
}

func (f *fakeTestSource) ListFailedTests(ctx context.Context, job string, build int64) ([]tools.TestFailure, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.failures, nil
}

// --- DIAG-002 enrichment (SCM + TEST + PIPE + GRAPH) ---

func TestDiagnoseBuild_EnrichmentSCMTestsPipeline(t *testing.T) {
	// Fixture with changeSet + failed tests + pipeline stages → diagnose includes all three.
	f := newDiagFixture()
	defer f.close()

	// Attach multi-SCM changes + secret-bearing commit message on demo#10.
	f.mu.Lock()
	f.builds["job/demo/10"]["changeSet"] = map[string]any{
		"kind": "git",
		"items": []any{
			map[string]any{
				"commitId":      "abc111",
				"msg":           "fix compile: password=scm-secret-canary-zz99",
				"author":        map[string]any{"fullName": "Dev One"},
				"affectedPaths": []any{"src/a.go"},
			},
			map[string]any{
				"commitId": "abc222",
				"msg":      "second change",
				"author":   map[string]any{"fullName": "Dev Two"},
			},
		},
	}
	f.builds["job/demo/10"]["changeSets"] = []any{
		map[string]any{
			"kind": "git",
			"items": []any{
				map[string]any{"commitId": "abc111", "msg": "fix compile: password=scm-secret-canary-zz99", "author": map[string]any{"fullName": "Dev One"}},
			},
		},
		map[string]any{
			"kind": "git",
			"items": []any{
				map[string]any{"commitId": "def333", "msg": "lib bump", "author": map[string]any{"fullName": "Lib Bot"}},
			},
		},
	}
	f.builds["job/demo/10"]["culprits"] = []any{
		map[string]any{"fullName": "Dev One"},
	}
	f.builds["job/demo/10"]["actions"] = append(
		asAnySlice(f.builds["job/demo/10"]["actions"]),
		map[string]any{
			"_class":     "hudson.plugins.git.util.BuildData",
			"remoteUrls": []any{"https://ci-bot:token-should-strip@github.com/acme/app.git"},
			"lastBuiltRevision": map[string]any{
				"SHA1":   "abc111",
				"branch": []any{map[string]any{"name": "main", "SHA1": "abc111"}},
			},
		},
		map[string]any{
			"_class":            "hudson.plugins.git.util.BuildData",
			"remoteUrls":        []any{"https://github.com/acme/lib.git"},
			"lastBuiltRevision": map[string]any{"SHA1": "def333"},
		},
	)
	// Failed stage already set by fixture; ensure explicit FAILED stage name.
	f.wfapi["job/demo/10"] = mustJSON(map[string]any{
		"name": "#10", "status": "FAILED", "durationMillis": 3000,
		"stages": []map[string]any{
			{"id": "1", "name": "Checkout", "status": "SUCCESS", "durationMillis": 100},
			{"id": "2", "name": "Compile", "status": "FAILED", "durationMillis": 900},
			{"id": "3", "name": "Test", "status": "NOT_EXECUTED", "durationMillis": 0},
		},
	})
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "diag-enrich", Version: "test"}, nil)
	// No Logs helper ⇒ client_tail; enrichment uses live client.
	tools.Register(server, f.client(), nil)
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
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), "scm-secret-canary-zz99") {
		t.Fatalf("SCM commit secret leaked: %s", raw)
	}
	if strings.Contains(string(raw), "token-should-strip") {
		t.Fatalf("SCM credential leaked: %s", raw)
	}

	// SCM summary
	scm, ok := payload["scm"].(map[string]any)
	if !ok {
		t.Fatalf("scm missing: %s", raw)
	}
	if intFromAny(scm["commit_count"]) < 1 {
		t.Fatalf("commit_count=%v", scm["commit_count"])
	}
	if scm["multi_scm"] != true {
		t.Fatalf("want multi_scm: %v", scm["multi_scm"])
	}
	commits, _ := scm["commits"].([]any)
	if len(commits) == 0 {
		t.Fatalf("commits empty: %v", scm)
	}
	culprits, _ := scm["culprits"].([]any)
	if len(culprits) == 0 {
		t.Fatalf("culprits empty: %v", scm)
	}
	c0, _ := culprits[0].(map[string]any)
	if note, _ := c0["note"].(string); !strings.Contains(note, "correlation") {
		t.Fatalf("culprit note missing correlation label: %v", c0)
	}

	// Test failures auto-wire
	tf, ok := payload["test_failures"].([]any)
	if !ok || len(tf) == 0 {
		t.Fatalf("test_failures=%v", payload["test_failures"])
	}

	// Failed stage
	fs, ok := payload["failed_stage"].(map[string]any)
	if !ok {
		t.Fatalf("failed_stage missing: %s", raw)
	}
	if fs["name"] != "Compile" || fs["status"] != "FAILED" {
		t.Fatalf("failed_stage=%v", fs)
	}

	// Sources include enrichment paths
	sources, _ := payload["sources"].([]any)
	need := map[string]bool{"scm": false, "tests": false, "pipeline": false, "build_api": false}
	for _, s := range sources {
		if _, ok := need[fmt.Sprint(s)]; ok {
			need[fmt.Sprint(s)] = true
		}
	}
	for k, v := range need {
		if !v {
			t.Fatalf("missing source %q in %v", k, sources)
		}
	}

	// Successful auto-wire must not leave the old "SCM auto-wire residual" string.
	for _, r := range asStringSlice(payload["residuals"]) {
		if strings.Contains(r, "DIAG-002 auto-wire residual") {
			t.Fatalf("stale SCM auto-wire residual still present: %v", payload["residuals"])
		}
		if strings.Contains(r, "PIPE stages/failed stage not wired") {
			t.Fatalf("stale PIPE residual still present: %v", payload["residuals"])
		}
	}

	summary, _ := payload["summary"].(string)
	if !strings.Contains(summary, "Compile") && !strings.Contains(summary, "failed_stage") {
		// failed_stage is in summary as failed_stage=Compile
		if !strings.Contains(summary, "failed test") && !strings.Contains(summary, "SCM commit") {
			t.Fatalf("summary missing enrichment hints: %q", summary)
		}
	}
}

func TestDiagnoseBuild_SCMSecretRedacted(t *testing.T) {
	// Regression: secrets in commit messages must never appear in diagnose MCP output.
	f := newDiagFixture()
	defer f.close()
	canary := "hunter2-scm-diag-canary-4c1d"
	f.mu.Lock()
	f.builds["job/demo/6"]["changeSet"] = map[string]any{
		"kind": "git",
		"items": []any{
			map[string]any{
				"commitId": "deadbeef",
				"msg":      "deploy password=" + canary,
				"author":   map[string]any{"fullName": "CI"},
			},
		},
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "diag-scm-secret", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 6,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(toolStructuredJSON(t, res))
	if strings.Contains(string(raw), canary) {
		t.Fatalf("canary leaked in diagnose: %s", raw)
	}
	payload := toolStructuredJSON(t, res)
	scm, ok := payload["scm"].(map[string]any)
	if !ok {
		t.Fatalf("scm missing: %s", raw)
	}
	commits, _ := scm["commits"].([]any)
	if len(commits) == 0 {
		t.Fatalf("expected commits with redacted message: %v", scm)
	}
}

func TestDiagnoseBuild_NoCapabilityResiduals(t *testing.T) {
	// Empty plugins + 404 descriptors ⇒ capability_missing residuals, no panic, no invented data.
	f := newDiagFixture()
	defer f.close()
	f.mu.Lock()
	f.pluginsJSON = `{"plugins":[]}`
	f.denyDescriptors = true
	delete(f.wfapi, "job/demo/10")
	delete(f.testReports, "job/demo/10")
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "diag-nocap", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
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
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("must not error/panic when capabilities missing: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	// Must not invent test failures or failed stage.
	if tf, ok := payload["test_failures"].([]any); ok && len(tf) > 0 {
		t.Fatalf("invented test_failures without JUnit: %v", tf)
	}
	if payload["failed_stage"] != nil {
		t.Fatalf("invented failed_stage without Pipeline REST: %v", payload["failed_stage"])
	}
	residuals := asStringSlice(payload["residuals"])
	var sawTEST, sawPIPE bool
	for _, r := range residuals {
		if strings.Contains(r, "TEST") && strings.Contains(strings.ToLower(r), "capability") {
			sawTEST = true
		}
		if strings.Contains(r, "PIPE") && strings.Contains(strings.ToLower(r), "capability") {
			sawPIPE = true
		}
	}
	if !sawTEST {
		t.Fatalf("expected TEST capability residual: %v", residuals)
	}
	if !sawPIPE {
		t.Fatalf("expected PIPE capability residual: %v", residuals)
	}
}

func TestDiagnoseBuild_UpstreamOneHop(t *testing.T) {
	// service#5 has upstream deploy#3 in fixture actions.
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "diag-up", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "service",
			"build_number": 5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	rb, ok := payload["related_builds"].(map[string]any)
	if !ok {
		t.Fatalf("related_builds missing: %v", payload)
	}
	ups, _ := rb["upstream"].([]any)
	if len(ups) == 0 {
		t.Fatalf("expected upstream hint: %v", rb)
	}
	u0, _ := ups[0].(map[string]any)
	if u0["job_name"] != "deploy" || intFromAny(u0["build_number"]) != 3 {
		t.Fatalf("upstream=%v", u0)
	}
	note, _ := rb["note"].(string)
	if !strings.Contains(note, "jenkins_get_build_graph") {
		t.Fatalf("note=%q", note)
	}
}

func TestDiagnoseBuild_MissingChangeDataNoInvent(t *testing.T) {
	// Build without changeSet → residual, never invent commits.
	f := newDiagFixture()
	defer f.close()
	// demo#5 is SUCCESS with no SCM fields.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "diag-noscm", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolDiagnoseBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	if scm, ok := payload["scm"].(map[string]any); ok {
		if intFromAny(scm["commit_count"]) != 0 {
			t.Fatalf("invented commits: %v", scm)
		}
		commits, _ := scm["commits"].([]any)
		if len(commits) > 0 {
			t.Fatalf("invented commit list: %v", commits)
		}
	}
	var sawSCMResidual bool
	for _, r := range asStringSlice(payload["residuals"]) {
		if strings.Contains(r, "SCM") {
			sawSCMResidual = true
		}
	}
	if !sawSCMResidual {
		t.Fatalf("expected SCM missing-data residual: %v", payload["residuals"])
	}
}

func asAnySlice(v any) []any {
	if v == nil {
		return nil
	}
	if s, ok := v.([]any); ok {
		return s
	}
	// JSON-decoded from map may already be []any from setBuild.
	return []any{}
}

func asStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
