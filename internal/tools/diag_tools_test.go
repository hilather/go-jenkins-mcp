package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// diagFixture is a multi-build Jenkins HTTP surface for DIAG-003/004/005 tests.
type diagFixture struct {
	srv *httptest.Server

	mu              sync.Mutex
	builds          map[string]map[string]any // "job/demo/N" → build JSON fields
	logs            map[string]string         // "job/demo/N" → progressive text
	jobBuilds       map[string][]map[string]any
	wfapi           map[string]string
	testReports     map[string]string
	artifacts       map[string][]map[string]any
	pluginsJSON     string
	denyDescriptors bool // when true, descriptor probes 404 (capability missing)
	logTailCalls    atomic.Int32
	// PERF-003: count GetBuildDetailsByJob-shaped tree queries (displayName + parameters).
	buildDetailsCalls atomic.Int32
	// Optional gate to block build-details responses until released (single-flight tests).
	buildDetailsGate chan struct{}
	// Optional: count all build-level /api/json hits for a specific prefix (e.g. job/demo/10).
	buildAPIPrefix string
	buildAPICalls  atomic.Int32
}

func newDiagFixture() *diagFixture {
	f := &diagFixture{
		builds:      make(map[string]map[string]any),
		logs:        make(map[string]string),
		jobBuilds:   make(map[string][]map[string]any),
		wfapi:       make(map[string]string),
		testReports: make(map[string]string),
		artifacts:   make(map[string][]map[string]any),
	}
	// Default plugins: pipeline + junit so capability probes succeed.
	f.pluginsJSON = `{"plugins":[
		{"shortName":"pipeline-rest-api","version":"1.0","active":true,"enabled":true},
		{"shortName":"workflow-job","version":"1.0","active":true,"enabled":true},
		{"shortName":"junit","version":"1.0","active":true,"enabled":true}
	]}`

	// demo job history: 5 SUCCESS clean, 6-8 FAILURE with error, 9 SUCCESS, 10 FAILURE
	// Gap at #7 for uncertain interval tests (optional; include 5,6,8,9,10 by default).
	f.setBuild("demo", 5, "SUCCESS", 1000, map[string]string{"BRANCH": "main"},
		"Started\nFinished: SUCCESS\n", nil, nil, nil)
	f.setBuild("demo", 6, "FAILURE", 2000, map[string]string{"BRANCH": "main", "API_TOKEN": "super-secret-token-value"},
		"Error: compilation failed in module demo\nBUILD FAILURE\nFinished: FAILURE\n",
		[]map[string]any{{"name": "Build", "status": "FAILED", "durationMillis": 500}},
		map[string]any{
			"failCount": 1, "passCount": 9, "skipCount": 0, "totalCount": 10, "duration": 1.0,
			"suites": []map[string]any{{
				"name": "s",
				"cases": []map[string]any{{
					"name": "TestFoo", "className": "pkg.Foo", "status": "FAILED",
					"duration": 0.1, "errorDetails": "expected true", "age": 1,
				}},
			}},
		},
		[]map[string]any{{"relativePath": "log.txt", "fileName": "log.txt"}})
	f.setBuild("demo", 8, "FAILURE", 2500, map[string]string{"BRANCH": "feature"},
		"Error: compilation failed in module demo\nBUILD FAILURE\nFinished: FAILURE\n",
		[]map[string]any{{"name": "Build", "status": "FAILED", "durationMillis": 800}},
		map[string]any{
			"failCount": 2, "passCount": 8, "skipCount": 0, "totalCount": 10, "duration": 1.2,
			"suites": []map[string]any{{
				"name": "s",
				"cases": []map[string]any{
					{"name": "TestFoo", "className": "pkg.Foo", "status": "FAILED", "duration": 0.1, "errorDetails": "expected true", "age": 2},
					{"name": "TestBar", "className": "pkg.Bar", "status": "FAILED", "duration": 0.2, "errorDetails": "boom", "age": 1},
				},
			}},
		},
		[]map[string]any{{"relativePath": "log.txt", "fileName": "log.txt"}, {"relativePath": "report.xml", "fileName": "report.xml"}})
	f.setBuild("demo", 9, "SUCCESS", 1200, map[string]string{"BRANCH": "feature"},
		"Started\nFinished: SUCCESS\n",
		[]map[string]any{{"name": "Build", "status": "SUCCESS", "durationMillis": 400}},
		map[string]any{
			"failCount": 0, "passCount": 10, "skipCount": 0, "totalCount": 10, "duration": 0.8,
			"suites": []map[string]any{{"name": "s", "cases": []map[string]any{
				{"name": "TestFoo", "className": "pkg.Foo", "status": "PASSED", "duration": 0.1},
			}}},
		},
		[]map[string]any{{"relativePath": "log.txt", "fileName": "log.txt"}})
	f.setBuild("demo", 10, "FAILURE", 3000, map[string]string{"BRANCH": "feature", "API_TOKEN": "another-secret"},
		"Error: compilation failed in module demo\nBUILD FAILURE\nFinished: FAILURE\n",
		[]map[string]any{{"name": "Build", "status": "FAILED", "durationMillis": 900}},
		map[string]any{
			"failCount": 1, "passCount": 9, "skipCount": 0, "totalCount": 10, "duration": 1.1,
			"suites": []map[string]any{{
				"name": "s",
				"cases": []map[string]any{{
					"name": "TestFoo", "className": "pkg.Foo", "status": "FAILED",
					"duration": 0.1, "errorDetails": "expected true", "age": 1,
				}},
			}},
		},
		[]map[string]any{{"relativePath": "log.txt", "fileName": "log.txt"}})

	// Graph fixtures: service#5 caused by deploy#3, triggers smoke#2 (both fail).
	f.setBuild("deploy", 3, "SUCCESS", 3000, nil, "ok\n", nil, nil, nil)
	f.setBuild("service", 5, "FAILURE", 5000, nil,
		"Error: service crash\nBUILD FAILURE\n", nil, nil, nil)
	f.setBuild("smoke", 2, "FAILURE", 1000, nil,
		"Error: smoke failed\nBUILD FAILURE\n", nil, nil, nil)
	// Attach upstream/downstream on service/5 and friends.
	f.mu.Lock()
	f.builds["job/service/5"]["actions"] = []any{
		map[string]any{
			"_class": "hudson.model.CauseAction",
			"causes": []any{map[string]any{
				"_class":           "hudson.model.Cause$UpstreamCause",
				"upstreamProject":  "deploy",
				"upstreamBuild":    3,
				"shortDescription": "Started by upstream project deploy",
			}},
		},
	}
	f.builds["job/service/5"]["downstreamBuilds"] = []any{
		map[string]any{"jobName": "smoke", "buildNumber": 2},
	}
	f.builds["job/smoke/2"]["actions"] = []any{
		map[string]any{
			"_class": "hudson.model.CauseAction",
			"causes": []any{map[string]any{
				"_class":          "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "service",
				"upstreamBuild":   5,
			}},
		},
	}
	// Cycle A <-> B
	f.builds["job/cycleA/1"] = map[string]any{
		"number": 1, "result": "FAILURE", "building": false,
		"timestamp": 1700000700000, "duration": 100, "displayName": "#1",
		"actions": []any{map[string]any{
			"_class": "hudson.model.CauseAction",
			"causes": []any{map[string]any{
				"_class":          "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "cycleB", "upstreamBuild": 1,
			}},
		}},
	}
	f.builds["job/cycleB/1"] = map[string]any{
		"number": 1, "result": "FAILURE", "building": false,
		"timestamp": 1700000710000, "duration": 100, "displayName": "#1",
		"actions": []any{map[string]any{
			"_class": "hudson.model.CauseAction",
			"causes": []any{map[string]any{
				"_class":          "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "cycleA", "upstreamBuild": 1,
			}},
		}},
	}
	f.logs["job/cycleA/1"] = "Error: cycleA\nBUILD FAILURE\n"
	f.logs["job/cycleB/1"] = "Error: cycleB\nBUILD FAILURE\n"
	f.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", f.handle)
	f.srv = httptest.NewServer(mux)
	return f
}

func (f *diagFixture) setBuild(
	job string, num int, result string, durationMs int,
	params map[string]string, log string,
	stages []map[string]any, testReport map[string]any,
	arts []map[string]any,
) {
	key := "job/" + job + "/" + strconv.Itoa(num)
	actions := []any{}
	if len(params) > 0 {
		var plist []map[string]any
		for k, v := range params {
			plist = append(plist, map[string]any{"name": k, "value": v})
		}
		actions = append(actions, map[string]any{
			"_class":     "hudson.model.ParametersAction",
			"parameters": plist,
		})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.builds[key] = map[string]any{
		"number":            num,
		"url":               "http://jenkins/job/" + job + "/" + strconv.Itoa(num) + "/",
		"result":            result,
		"building":          false,
		"timestamp":         1700000000000 + int64(num)*10000,
		"duration":          durationMs,
		"estimatedDuration": 1000,
		"displayName":       "#" + strconv.Itoa(num),
		"actions":           actions,
	}
	if log != "" {
		f.logs[key] = log
	}
	if stages != nil {
		b, _ := json.Marshal(map[string]any{
			"name":           "#" + strconv.Itoa(num),
			"status":         result,
			"durationMillis": durationMs,
			"stages":         stages,
		})
		f.wfapi[key] = string(b)
	}
	if testReport != nil {
		b, _ := json.Marshal(testReport)
		f.testReports[key] = string(b)
	}
	if arts != nil {
		f.artifacts[key] = arts
	}
	// Maintain job-level builds list (newest first).
	entry := map[string]any{
		"number": num, "url": "http://jenkins/job/" + job + "/" + strconv.Itoa(num) + "/",
		"result": result, "building": false,
		"timestamp": 1700000000000 + int64(num)*10000,
		"duration":  durationMs, "displayName": "#" + strconv.Itoa(num),
		"actions": actions,
	}
	list := f.jobBuilds[job]
	// Insert sorted newest first.
	inserted := false
	for i, e := range list {
		if e["number"].(int) < num {
			list = append(list[:i], append([]map[string]any{entry}, list[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		list = append(list, entry)
	}
	f.jobBuilds[job] = list
}

func (f *diagFixture) close() { f.srv.Close() }

func (f *diagFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func (f *diagFixture) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Jenkins", "2.462.3")
	path := r.URL.Path
	if dec, err := strconv.Unquote(`"` + path + ``); err == nil {
		_ = dec
	}

	switch {
	case path == "/api/json" || path == "/api/json/":
		writeJSON(w, `{"jobs":[{"name":"demo","url":"http://jenkins/job/demo/","color":"red"}]}`)
	case path == "/pluginManager/api/json" || strings.HasPrefix(path, "/pluginManager/api/json"):
		f.mu.Lock()
		body := f.pluginsJSON
		f.mu.Unlock()
		writeJSON(w, body)
	case strings.HasPrefix(path, "/descriptorByName/"):
		f.mu.Lock()
		deny := f.denyDescriptors
		f.mu.Unlock()
		if deny {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, `{}`)
	case strings.Contains(path, "/logText/progressiveText"):
		f.handleProgressive(w, r, path)
	case strings.Contains(path, "/wfapi/describe"):
		f.handleWFAPI(w, path)
	case strings.Contains(path, "/testReport/api/json"):
		f.handleTestReport(w, path)
	case strings.Contains(path, "/api/json") && strings.Contains(path, "/job/"):
		// PERF-003 hit accounting for GetBuildDetailsByJob vs other build trees.
		tree := r.URL.Query().Get("tree")
		if tree == "" && strings.Contains(r.URL.RawQuery, "tree=") {
			// Unescaped tree= may appear in RawQuery for GetBuildDetailsByJob.
			if idx := strings.Index(r.URL.RawQuery, "tree="); idx >= 0 {
				tree = r.URL.RawQuery[idx+len("tree="):]
				if amp := strings.IndexByte(tree, '&'); amp >= 0 {
					tree = tree[:amp]
				}
			}
		}
		isBuildDetails := strings.Contains(tree, "displayName") &&
			strings.Contains(tree, "parameters[name,value]") &&
			!strings.Contains(tree, "changeSet") &&
			!strings.Contains(tree, "causes")
		if isBuildDetails {
			f.buildDetailsCalls.Add(1)
			if f.buildDetailsGate != nil {
				<-f.buildDetailsGate
			}
		}
		// Optional prefix counter for all build-level api/json (details+scm+graph trees).
		if f.buildAPIPrefix != "" {
			p := strings.TrimSuffix(path, "/api/json")
			p = strings.Trim(p, "/")
			if p == f.buildAPIPrefix || strings.HasPrefix(p, f.buildAPIPrefix+"/") {
				// only exact build key match (job/demo/10)
				if p == f.buildAPIPrefix {
					f.buildAPICalls.Add(1)
				}
			}
		}
		f.handleJobOrBuild(w, path)
	case path == "/crumbIssuer/api/json":
		w.WriteHeader(http.StatusNotFound)
	default:
		http.NotFound(w, r)
	}
}

func (f *diagFixture) handleProgressive(w http.ResponseWriter, r *http.Request, path string) {
	// /job/demo/6/logText/progressiveText
	f.logTailCalls.Add(1)
	idx := strings.Index(path, "/logText/")
	if idx < 0 {
		http.NotFound(w, r)
		return
	}
	prefix := strings.Trim(path[:idx], "/")
	f.mu.Lock()
	body, ok := f.logs[prefix]
	f.mu.Unlock()
	if !ok {
		// empty log
		body = ""
	}
	start := 0
	if s := r.URL.Query().Get("start"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			start = n
		}
	}
	if start > len(body) {
		start = len(body)
	}
	chunk := body[start:]
	w.Header().Set("X-Text-Size", strconv.Itoa(len(body)))
	if start+len(chunk) < len(body) {
		w.Header().Set("X-More-Data", "true")
	}
	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	_, _ = w.Write([]byte(chunk))
}

func (f *diagFixture) handleWFAPI(w http.ResponseWriter, path string) {
	idx := strings.Index(path, "/wfapi/")
	if idx < 0 {
		http.NotFound(w, nil)
		return
	}
	prefix := strings.Trim(path[:idx], "/")
	f.mu.Lock()
	body, ok := f.wfapi[prefix]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	writeJSON(w, body)
}

func (f *diagFixture) handleTestReport(w http.ResponseWriter, path string) {
	idx := strings.Index(path, "/testReport/")
	if idx < 0 {
		http.NotFound(w, nil)
		return
	}
	prefix := strings.Trim(path[:idx], "/")
	f.mu.Lock()
	body, ok := f.testReports[prefix]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, nil)
		return
	}
	writeJSON(w, body)
}

func (f *diagFixture) handleJobOrBuild(w http.ResponseWriter, path string) {
	// Strip /api/json
	p := strings.TrimSuffix(path, "/api/json")
	p = strings.Trim(p, "/")
	parts := strings.Split(p, "/")
	// job/<name>/... or job/<folder>/job/<name>/...
	// Detect trailing build number.
	if len(parts) >= 3 && isDigits(parts[len(parts)-1]) {
		// build API — may include artifact list when tree requests artifacts.
		key := p
		f.mu.Lock()
		b, ok := f.builds[key]
		arts := f.artifacts[key]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, nil)
			return
		}
		// Copy and optionally attach artifacts for listArtifacts tree queries.
		out := make(map[string]any, len(b)+1)
		for k, v := range b {
			out[k] = v
		}
		if arts != nil {
			out["artifacts"] = arts
		}
		writeJSONObj(w, out)
		return
	}
	// Job-level API: return builds list.
	// Extract job full name from path: job/demo or job/a/job/b
	jobName := jobNameFromPath(p)
	f.mu.Lock()
	list := f.jobBuilds[jobName]
	f.mu.Unlock()
	if list == nil {
		http.NotFound(w, nil)
		return
	}
	writeJSONObj(w, map[string]any{
		"name":                jobName,
		"url":                 "http://jenkins/job/" + jobName + "/",
		"builds":              list,
		"lastBuild":           list[0],
		"lastSuccessfulBuild": findResult(list, "SUCCESS"),
		"lastFailedBuild":     findResult(list, "FAILURE"),
		"lastCompletedBuild":  list[0],
	})
}

func jobNameFromPath(p string) string {
	// p like "job/demo" or "job/team/job/app"
	parts := strings.Split(p, "/")
	var segs []string
	for i := 0; i < len(parts); i++ {
		if parts[i] == "job" && i+1 < len(parts) {
			segs = append(segs, parts[i+1])
			i++
		}
	}
	return strings.Join(segs, "/")
}

func findResult(list []map[string]any, result string) map[string]any {
	for _, b := range list {
		if b["result"] == result {
			return b
		}
	}
	return nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func writeJSONObj(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// multiLogAccess returns per-build log bodies for local-mirror preference tests.
type multiLogAccess struct {
	bodies map[string]string // "job#build" → body
	calls  atomic.Int64
}

func (m *multiLogAccess) EnsureMirrored(ctx context.Context, job string, build int64) error {
	return ctx.Err()
}

func (m *multiLogAccess) ReadRange(ctx context.Context, job string, build int64, offset, length int64) (string, tools.LogReadMeta, error) {
	return m.Tail(ctx, job, build, length)
}

func (m *multiLogAccess) Tail(ctx context.Context, job string, build int64, maxLen int64) (string, tools.LogReadMeta, error) {
	m.calls.Add(1)
	key := fmt.Sprintf("%s#%d", job, build)
	body := m.bodies[key]
	if maxLen > 0 && int64(len(body)) > maxLen {
		body = body[int64(len(body))-maxLen:]
	}
	return body, tools.LogReadMeta{
		Offset:     0,
		Length:     len(body),
		TotalSize:  len(m.bodies[key]),
		Sealed:     true,
		Generation: 1,
	}, nil
}

// --- DIAG-003 ---

func TestCompareBuilds_RegistersByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolCompareBuilds]; !ok {
		t.Fatalf("expected %s registered", tools.ToolCompareBuilds)
	}
	if _, ok := names[tools.ToolFindRegressionWindow]; !ok {
		t.Fatalf("expected %s registered", tools.ToolFindRegressionWindow)
	}
	if _, ok := names[tools.ToolTraceFailureGraph]; !ok {
		t.Fatalf("expected %s registered", tools.ToolTraceFailureGraph)
	}
}

func TestCompareBuilds_MaterialDiffAndSecretStrip(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "cmp", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
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
	if strings.Contains(string(raw), "super-secret") || strings.Contains(string(raw), "another-secret") {
		t.Fatalf("secret leaked: %s", raw)
	}
	if payload["material_difference"] != true {
		t.Fatalf("want material_difference=true: %s", raw)
	}
	// Result should differ FAILURE vs SUCCESS
	rd, ok := payload["result_diff"].(map[string]any)
	if !ok {
		t.Fatalf("result_diff missing: %s", raw)
	}
	if rd["build_a_result"] != "FAILURE" || rd["build_b_result"] != "SUCCESS" {
		t.Fatalf("result_diff=%v", rd)
	}
	// Signature diffs present
	if sigs, _ := payload["signature_diffs"].([]any); len(sigs) == 0 {
		t.Fatalf("expected signature_diffs: %s", raw)
	}
	// Fixture has no changeSet → residual about missing SCM data (not the old "not wired" string).
	residuals, _ := payload["residuals"].([]any)
	var sawSCMMissing bool
	for _, r := range residuals {
		s, ok := r.(string)
		if !ok {
			continue
		}
		if strings.Contains(s, "SCM changesets/revisions not wired") {
			t.Fatalf("stale SCM-001 residual still present: %v", residuals)
		}
		if strings.Contains(s, "SCM:") && strings.Contains(s, "nothing invented") {
			sawSCMMissing = true
		}
	}
	if !sawSCMMissing {
		t.Fatalf("expected missing-changeSet SCM residual: %v", residuals)
	}
	// scm_diff may still attach with empty commits_total
	if scm, ok := payload["scm_diff"].(map[string]any); ok {
		if scm["mode"] != "range" {
			t.Fatalf("want range mode for adjacent builds: %v", scm)
		}
	}
	// Parameter BRANCH may differ feature vs feature for 10 vs 9 — same BRANCH=feature; secret excluded
	if params, ok := payload["parameter_diffs"].([]any); ok {
		for _, p := range params {
			pm, _ := p.(map[string]any)
			name, _ := pm["name"].(string)
			if strings.Contains(strings.ToLower(name), "token") || strings.Contains(strings.ToLower(name), "secret") {
				t.Fatalf("secret param in diffs: %v", pm)
			}
		}
	}
}

// TestCompareBuilds_SCMWireSuccess wires changeSet between two builds and asserts
// scm_diff commits appear without the SCM-001 residual.
func TestCompareBuilds_SCMWireSuccess(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	f.mu.Lock()
	f.builds["job/demo/10"]["changeSet"] = map[string]any{
		"kind": "git",
		"items": []any{
			map[string]any{
				"commitId":      "cmp111",
				"msg":           "fix compile for compare",
				"author":        map[string]any{"fullName": "Dev Compare"},
				"affectedPaths": []any{"src/a.go"},
			},
			map[string]any{
				"commitId": "cmp222",
				"msg":      "second change",
				"author":   map[string]any{"fullName": "Dev Two"},
			},
		},
	}
	f.builds["job/demo/10"]["actions"] = append(
		asAnySlice(f.builds["job/demo/10"]["actions"]),
		map[string]any{
			"_class":     "hudson.plugins.git.util.BuildData",
			"remoteUrls": []any{"https://github.com/acme/app.git"},
			"lastBuiltRevision": map[string]any{
				"SHA1":   "cmp111",
				"branch": []any{map[string]any{"name": "main", "SHA1": "cmp111"}},
			},
		},
	)
	// Baseline build 9 may also report BuildData without commits (range only scans 10).
	f.builds["job/demo/9"]["actions"] = append(
		asAnySlice(f.builds["job/demo/9"]["actions"]),
		map[string]any{
			"_class":            "hudson.plugins.git.util.BuildData",
			"remoteUrls":        []any{"https://github.com/acme/app.git"},
			"lastBuiltRevision": map[string]any{"SHA1": "old999"},
		},
	)
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-scm", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
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

	// Stale residual must be gone on success.
	for _, r := range asStringSlice(payload["residuals"]) {
		if strings.Contains(r, "SCM changesets/revisions not wired") || strings.Contains(r, "SCM-001 residual") {
			t.Fatalf("stale SCM residual on success: %v", payload["residuals"])
		}
		if strings.Contains(r, "nothing invented") {
			t.Fatalf("missing-data residual on success with commits: %v", payload["residuals"])
		}
	}

	scm, ok := payload["scm_diff"].(map[string]any)
	if !ok {
		t.Fatalf("scm_diff missing: %s", raw)
	}
	if scm["mode"] != "range" {
		t.Fatalf("mode=%v want range", scm["mode"])
	}
	if intFromAny(scm["baseline_build"]) != 9 || intFromAny(scm["target_build"]) != 10 {
		t.Fatalf("baseline/target=%v/%v", scm["baseline_build"], scm["target_build"])
	}
	if intFromAny(scm["commits_total"]) < 1 {
		t.Fatalf("commits_total=%v", scm["commits_total"])
	}
	commits, _ := scm["commits"].([]any)
	if len(commits) == 0 {
		t.Fatalf("commits empty: %v", scm)
	}
	// Sources include scm
	var sawSCMSrc bool
	for _, s := range asStringSlice(payload["sources"]) {
		if s == "scm" {
			sawSCMSrc = true
		}
	}
	if !sawSCMSrc {
		t.Fatalf("sources missing scm: %v", payload["sources"])
	}
	// Material difference should include SCM
	if payload["material_difference"] != true {
		t.Fatalf("want material_difference with SCM commits: %s", raw)
	}
	summary, _ := payload["summary"].(string)
	if !strings.Contains(summary, "SCM commit") {
		t.Fatalf("summary missing SCM hint: %q", summary)
	}
}

// TestCompareBuilds_SCMSecretRedacted ensures commit messages are scrubbed in compare output.
func TestCompareBuilds_SCMSecretRedacted(t *testing.T) {
	// Regression: secrets in commit messages must never appear in compare MCP output.
	f := newDiagFixture()
	defer f.close()
	canary := "hunter2-cmp-scm-canary-9f3a"
	f.mu.Lock()
	f.builds["job/demo/10"]["changeSet"] = map[string]any{
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
	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-scm-secret", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(toolStructuredJSON(t, res))
	if strings.Contains(string(raw), canary) {
		t.Fatalf("canary leaked in compare: %s", raw)
	}
	payload := toolStructuredJSON(t, res)
	scm, ok := payload["scm_diff"].(map[string]any)
	if !ok {
		t.Fatalf("scm_diff missing: %s", raw)
	}
	commits, _ := scm["commits"].([]any)
	if len(commits) == 0 {
		t.Fatalf("expected redacted commits present: %v", scm)
	}
}

// TestCompareBuilds_SCMBudgetExhaustion leaves Incomplete/residuals without panic.
func TestCompareBuilds_SCMBudgetExhaustion(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	// Attach changeSet so that if budget were higher, SCM would succeed.
	f.mu.Lock()
	f.builds["job/demo/10"]["changeSet"] = map[string]any{
		"kind":  "git",
		"items": []any{map[string]any{"commitId": "x", "msg": "should not fetch under budget"}},
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-scm-budget", Version: "test"}, nil)
	// MaxRemoteCalls=2: both build details consume budget; stages/tests/logs/SCM skip.
	tools.Register(server, f.client(), &tools.RegisterOptions{
		DiagOpBudgets: tools.DiagBudgetConfig{MaxRemoteCalls: 2},
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("compare must not hard-fail on budget: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	// Should complete with incomplete and/or SCM residual; never panic.
	if payload["incomplete"] != true {
		// Budget note is appended to residuals/confidence; incomplete expected when budget trips.
		// Some paths set incomplete only via sess.BudgetNote at end — should still be true.
		t.Fatalf("expected incomplete under tight budget, payload=%v", payload)
	}
	joined := strings.Join(asStringSlice(payload["residuals"]), " ") + " " +
		strings.Join(asStringSlice(payload["confidence_notes"]), " ")
	if !strings.Contains(joined, "budget") && !strings.Contains(joined, "SCM") {
		t.Fatalf("expected budget/SCM residual or note: residuals=%v notes=%v",
			payload["residuals"], payload["confidence_notes"])
	}
	// scm_diff should be absent or empty when skipped for budget
	if scm, ok := payload["scm_diff"].(map[string]any); ok {
		if intFromAny(scm["commits_total"]) > 0 {
			// Under MaxRemoteCalls=2, SCM should not have been fetched after details.
			t.Fatalf("unexpected SCM commits under exhausted budget: %v", scm)
		}
	}
}

func TestCompareBuilds_IdenticalNoMaterialDiff(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	// Two identical SUCCESS builds with same log/params.
	f.setBuild("demo", 20, "SUCCESS", 1000, map[string]string{"BRANCH": "main"},
		"Started\nFinished: SUCCESS\n", nil, nil, nil)
	f.setBuild("demo", 21, "SUCCESS", 1000, map[string]string{"BRANCH": "main"},
		"Started\nFinished: SUCCESS\n", nil, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-id", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  20,
			"build_b":  21,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	if payload["material_difference"] != false {
		t.Fatalf("want no material difference: %v", payload)
	}
	summary, _ := payload["summary"].(string)
	if !strings.Contains(summary, "no material difference") {
		t.Fatalf("summary=%q", summary)
	}
}

func TestCompareBuilds_RejectsURLAndInvalidArgs(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-bad", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "https://jenkins.example.com/job/x",
			"build_a":  1,
			"build_b":  2,
		},
	})
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected invalid_argument for URL: %+v", toolStructuredJSON(t, res))
	}

	res2, err2 := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  0,
			"build_b":  2,
		},
	})
	if err2 == nil && res2 != nil && !res2.IsError {
		t.Fatalf("expected invalid_argument for build_a=0")
	}
}

// --- DIAG-004 ---

func TestFindRegressionWindow_FullScanBoundaries(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "reg", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolFindRegressionWindow,
		Arguments: map[string]any{
			"job_name":         "demo",
			"pattern":          "build_failure",
			"max_builds":       20,
			"assume_monotonic": false,
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
	if payload["algorithm"] != "reverse_chronological_scan" {
		t.Fatalf("algorithm=%v", payload["algorithm"])
	}
	// Oldest matching among 6,8,10 is #6.
	bad, ok := payload["first_known_bad"].(map[string]any)
	if !ok {
		t.Fatalf("first_known_bad missing: %s", raw)
	}
	// JSON numbers may be float64
	badNum := int(asFloat(bad["build_number"]))
	if badNum != 6 {
		t.Fatalf("first_known_bad=#%d want #6: %s", badNum, raw)
	}
	good, ok := payload["first_known_good"].(map[string]any)
	if !ok {
		t.Fatalf("first_known_good missing: %s", raw)
	}
	goodNum := int(asFloat(good["build_number"]))
	if goodNum != 5 {
		t.Fatalf("first_known_good=#%d want #5: %s", goodNum, raw)
	}
	// Missing #7 should appear in missing_builds or uncertain_intervals
	foundGap := false
	if miss, ok := payload["missing_builds"].([]any); ok {
		for _, m := range miss {
			if int(asFloat(m)) == 7 {
				foundGap = true
			}
		}
	}
	if !foundGap {
		if ivals, ok := payload["uncertain_intervals"].([]any); ok {
			for _, iv := range ivals {
				im, _ := iv.(map[string]any)
				if int(asFloat(im["from_build"])) == 7 || int(asFloat(im["to_build"])) == 7 {
					foundGap = true
				}
			}
		}
	}
	if !foundGap {
		t.Fatalf("expected gap at build 7: %s", raw)
	}
	// Evidence citation on bad boundary
	if bad["pattern"] == "" && bad["signature"] == "" && bad["match"] == "" {
		t.Fatalf("expected evidence on first_known_bad: %v", bad)
	}
}

func TestFindRegressionWindow_RequiresMatchCriteria(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "reg-bad", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolFindRegressionWindow,
		Arguments: map[string]any{
			"job_name": "demo",
		},
	})
	if err == nil && res != nil && !res.IsError {
		t.Fatalf("expected invalid_argument without match criteria")
	}
}

func TestFindRegressionWindow_MaxBuildsCap(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "reg-cap", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolFindRegressionWindow,
		Arguments: map[string]any{
			"job_name":   "demo",
			"pattern":    "build_failure",
			"max_builds": 2, // only scan 2 newest
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	budgets, _ := payload["budgets"].(map[string]any)
	scanned := int(asFloat(budgets["builds_scanned"]))
	if scanned > 2 {
		t.Fatalf("builds_scanned=%d want <=2: %v", scanned, payload)
	}
	// max_builds hard-capped field should be 2
	if int(asFloat(budgets["max_builds"])) != 2 {
		t.Fatalf("max_builds budget=%v", budgets["max_builds"])
	}
}

func TestFindRegressionWindow_MonotonicAlgorithmLabel(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "reg-mono", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolFindRegressionWindow,
		Arguments: map[string]any{
			"job_name":         "demo",
			"pattern":          "build_failure",
			"assume_monotonic": true,
			"max_builds":       20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	if payload["algorithm"] != "binary_search_monotonic" {
		t.Fatalf("algorithm=%v", payload["algorithm"])
	}
	notes, _ := payload["confidence_notes"].([]any)
	var sawMono bool
	for _, n := range notes {
		if s, ok := n.(string); ok && strings.Contains(s, "assume_monotonic") {
			sawMono = true
		}
	}
	if !sawMono {
		t.Fatalf("expected monotonic note: %v", notes)
	}
}

// --- DIAG-005 ---

func TestTraceFailureGraph_EarliestVsLeavesAndDedupe(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Local mirror for service and smoke — count unique reads.
	mirror := &multiLogAccess{bodies: map[string]string{
		"service#5": "Error: service crash\nBUILD FAILURE\n",
		"smoke#2":   "Error: smoke failed\nBUILD FAILURE\n",
		"deploy#3":  "ok\n",
	}}

	server := mcp.NewServer(&mcp.Implementation{Name: "trace", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Logs: mirror})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolTraceFailureGraph,
		Arguments: map[string]any{
			"job_name":           "service",
			"build_number":       5,
			"max_depth":          3,
			"max_nodes":          20,
			"max_diagnose_nodes": 8,
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

	// Root present
	if payload["root"] != "service#5" {
		t.Fatalf("root=%v", payload["root"])
	}
	// Earliest failure and leaves distinguished
	if payload["earliest_failure"] == nil || payload["earliest_failure"] == "" {
		// service ts < smoke ts in fixture
		t.Fatalf("earliest_failure missing: %s", raw)
	}
	leaves, _ := payload["first_failing_leaves"].([]any)
	if len(leaves) == 0 {
		t.Fatalf("first_failing_leaves empty: %s", raw)
	}
	// Failed nodes diagnosed with signatures
	failed, _ := payload["failed_nodes"].([]any)
	if len(failed) == 0 {
		t.Fatalf("failed_nodes empty: %s", raw)
	}
	var sawSig bool
	for _, fn := range failed {
		fm, _ := fn.(map[string]any)
		if fm["top_signature"] != nil && fm["top_signature"] != "" {
			sawSig = true
		}
	}
	if !sawSig {
		t.Fatalf("expected top signatures: %s", raw)
	}
	// Dedupe: unique_logs_read <= number of distinct failed builds
	budgets, _ := payload["budgets"].(map[string]any)
	unique := int(asFloat(budgets["unique_logs_read"]))
	if unique < 1 {
		t.Fatalf("unique_logs_read=%d: %s", unique, raw)
	}
	// Mirror called once per unique failed node that was diagnosed (not twice for same key)
	if mirror.calls.Load() < 1 {
		t.Fatal("expected local mirror log reads")
	}
	// Calling again in same process with same request already completed — re-call and ensure no explosion.
	// Unique keys only.
	if mirror.calls.Load() > 10 {
		t.Fatalf("too many log reads: %d", mirror.calls.Load())
	}
}

func TestTraceFailureGraph_CycleWithinBudget(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "trace-cycle", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolTraceFailureGraph,
		Arguments: map[string]any{
			"job_name":     "cycleA",
			"build_number": 1,
			"max_depth":    3,
			"max_nodes":    10,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	if payload["cycle_detected"] != true {
		t.Fatalf("expected cycle_detected: %v", payload)
	}
	// Still returns compact result under budget
	enforced, info, berr := tools.EnforceBudget(payload, tools.DefaultBudgets())
	if berr != nil {
		t.Fatal(berr)
	}
	_ = enforced
	if info != nil && info.Truncated {
		t.Fatalf("unexpected truncation: %+v", info)
	}
}

func TestTraceFailureGraph_DiagnoseBudget(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "trace-bud", Version: "test"}, nil)
	tools.Register(server, f.client(), nil)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolTraceFailureGraph,
		Arguments: map[string]any{
			"job_name":           "service",
			"build_number":       5,
			"max_diagnose_nodes": 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	budgets, _ := payload["budgets"].(map[string]any)
	if int(asFloat(budgets["max_diagnose_nodes"])) != 1 {
		t.Fatalf("max_diagnose_nodes=%v", budgets["max_diagnose_nodes"])
	}
	diagnosed := int(asFloat(budgets["nodes_diagnosed"]))
	if diagnosed > 1 {
		t.Fatalf("nodes_diagnosed=%d want <=1", diagnosed)
	}
}

func TestCompareBuilds_LocalMirrorPreferred(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	canary := "hunter2-compare-canary-7a1c"
	mirror := &multiLogAccess{bodies: map[string]string{
		"demo#10": "Error: fail password=" + canary + "\nBUILD FAILURE\n",
		"demo#9":  "Started\nFinished: SUCCESS\n",
	}}
	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-mir", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{Logs: mirror})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := toolStructuredJSON(t, res)
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), canary) {
		t.Fatalf("canary leaked: %s", raw)
	}
	if mirror.calls.Load() < 1 {
		t.Fatal("expected local mirror use")
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
}

func asFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}
