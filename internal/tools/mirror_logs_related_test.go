package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

func TestNormalizeRelatedDiscoveryArgs(t *testing.T) {
	t.Parallel()

	// Off by default — related fields ignored.
	max, dir, err := normalizeRelatedDiscoveryArgs(MirrorLogsToolArgs{
		RelatedMax: 99, RelatedDirection: "nope",
	})
	if err != nil || max != 0 || dir != "" {
		t.Fatalf("include_related=false: max=%d dir=%q err=%v", max, dir, err)
	}

	// Defaults.
	max, dir, err = normalizeRelatedDiscoveryArgs(MirrorLogsToolArgs{IncludeRelated: true})
	if err != nil || max != DefaultRelatedMax || dir != jenkins.GraphDirectionBoth {
		t.Fatalf("defaults: max=%d dir=%q err=%v", max, dir, err)
	}

	// Fail closed on oversized related_max.
	_, _, err = normalizeRelatedDiscoveryArgs(MirrorLogsToolArgs{
		IncludeRelated: true, RelatedMax: HardRelatedMax + 1,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("expected invalid_argument for related_max>%d, got %v", HardRelatedMax, err)
	}

	// Boundary: HardRelatedMax allowed.
	max, _, err = normalizeRelatedDiscoveryArgs(MirrorLogsToolArgs{
		IncludeRelated: true, RelatedMax: HardRelatedMax,
	})
	if err != nil || max != HardRelatedMax {
		t.Fatalf("hard max allowed: max=%d err=%v", max, err)
	}

	// Bad direction.
	_, _, err = normalizeRelatedDiscoveryArgs(MirrorLogsToolArgs{
		IncludeRelated: true, RelatedDirection: "sideways",
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("expected invalid direction: %v", err)
	}

	max, dir, err = normalizeRelatedDiscoveryArgs(MirrorLogsToolArgs{
		IncludeRelated: true, RelatedMax: 2, RelatedDirection: "upstream",
	})
	if err != nil || max != 2 || dir != jenkins.GraphDirectionUpstream {
		t.Fatalf("upstream: max=%d dir=%q err=%v", max, dir, err)
	}
}

func TestRelatedMirrorRequestsFromGraph_DedupeAndCap(t *testing.T) {
	t.Parallel()
	seen := map[string]struct{}{
		"service|5": {},
	}
	nodes := []jenkins.BuildGraphNode{
		{JobName: "service", BuildNumber: 5, Role: "root"},
		{JobName: "deploy", BuildNumber: 3, Role: "upstream"},
		{JobName: "smoke", BuildNumber: 2, Role: "downstream"},
		{JobName: "deploy", BuildNumber: 3, Role: "upstream"},                     // dup
		{JobName: "https://evil.example/job", BuildNumber: 1, Role: "downstream"}, // invent/URL reject
		{JobName: "", BuildNumber: 9, Role: "downstream"},
		{JobName: "extra", BuildNumber: 1, Role: "downstream"},
	}
	got := relatedMirrorRequestsFromGraph(nodes, seen, 2)
	if len(got) != 2 {
		t.Fatalf("cap 2: got %+v", got)
	}
	// Sorted: deploy before extra/smoke → deploy + extra? deploy, extra, smoke → deploy, extra (cap 2)
	// Wait: sort is job name: deploy, extra, smoke → deploy + extra
	if got[0].Job != "deploy" || got[0].Relation != RelationUpstream {
		t.Fatalf("first: %+v", got[0])
	}
	if got[1].Job != "extra" || got[1].Relation != RelationDownstream {
		t.Fatalf("second: %+v", got[1])
	}
	// Primary already in seen never re-added.
	for _, r := range got {
		if r.Job == "service" {
			t.Fatal("must not re-add primary")
		}
	}
}

func TestRelationFromGraphRole(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"upstream":   RelationUpstream,
		"Downstream": RelationDownstream,
		"root":       RelationPrimary,
		"":           RelationRelated,
		"other":      RelationRelated,
	}
	for in, want := range cases {
		if got := relationFromGraphRole(in); got != want {
			t.Fatalf("role %q: got %q want %q", in, got, want)
		}
	}
}

// graphHTTPFixture serves GetBuildGraph JSON similar to jenkins setGraphFixture.
type graphHTTPFixture struct {
	srv       *httptest.Server
	mu        sync.Mutex
	buildJSON map[string]string
	failAll   bool
	hits      int // API requests (for policy-before-graph regressions)
}

func newGraphHTTPFixture() *graphHTTPFixture {
	f := &graphHTTPFixture{buildJSON: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		if f.failAll {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		// job/service/5/api/json
		if !strings.Contains(path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		// key without /api/json
		key := strings.TrimSuffix(path, "/api/json")
		key = strings.TrimSuffix(key, "/")
		if body, ok := f.buildJSON[key]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		// default empty success root
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"number":1,"result":"SUCCESS","building":false,"actions":[]}`))
	}))
	return f
}

func (f *graphHTTPFixture) close() { f.srv.Close() }

func (f *graphHTTPFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func (f *graphHTTPFixture) setServiceGraph() {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Same shape as internal/jenkins setGraphFixture (service ← deploy, → smoke).
	f.buildJSON["job/service/5"] = `{
		"number": 5,
		"result": "FAILURE",
		"building": false,
		"timestamp": 1700000500000,
		"duration": 5000,
		"actions": [{
			"_class": "hudson.model.CauseAction",
			"causes": [{
				"_class": "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "deploy",
				"upstreamBuild": 3,
				"shortDescription": "upstream"
			}]
		}],
		"downstreamBuilds": [{"jobName": "smoke", "buildNumber": 2}]
	}`
	f.buildJSON["job/deploy/3"] = `{
		"number": 3,
		"result": "SUCCESS",
		"building": false,
		"timestamp": 1700000400000,
		"duration": 3000,
		"actions": [],
		"downstreamBuilds": [{"jobName": "service", "buildNumber": 5}]
	}`
	f.buildJSON["job/smoke/2"] = `{
		"number": 2,
		"result": "FAILURE",
		"building": false,
		"timestamp": 1700000600000,
		"duration": 1000,
		"actions": [{
			"_class": "hudson.model.CauseAction",
			"causes": [{
				"_class": "hudson.model.Cause$UpstreamCause",
				"upstreamProject": "service",
				"upstreamBuild": 5,
				"shortDescription": "upstream"
			}]
		}]
	}`
}

// relatedFakeMulti is a MultiLogAcquirer that records AcquireMulti requests.
type relatedFakeMulti struct {
	mu       sync.Mutex
	LastReqs []MultiLogRequest
	Calls    int
}

func (f *relatedFakeMulti) MultiLogAvailable() bool { return true }

func (f *relatedFakeMulti) AcquireMulti(ctx context.Context, reqs []MultiLogRequest) (MultiLogCollection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return MultiLogCollection{}, err
	}
	f.Calls++
	f.LastReqs = append([]MultiLogRequest(nil), reqs...)
	out := MultiLogCollection{
		CollectionID: "coll-related-1",
		Profile:      "corp",
		Logs:         make([]MultiLogEntry, 0, len(reqs)),
	}
	for _, r := range reqs {
		out.Logs = append(out.Logs, MultiLogEntry{
			Job: r.Job, Build: r.Build, Relation: r.Relation,
			Status: MirrorStatusSealed, Generation: 1, DurableBytes: 8, BytesFetched: 8,
		})
	}
	return out, nil
}

func (f *relatedFakeMulti) ResidualMembers(ctx context.Context, collectionID string) ([]MultiLogRequest, error) {
	return nil, apperr.New(apperr.CodeNotFound, "collection not found")
}

func TestMirrorLogs_IncludeRelated_GraphFixture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	gf := newGraphHTTPFixture()
	defer gf.close()
	gf.setServiceGraph()

	fake := &relatedFakeMulti{}
	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-related", Version: "test"}, nil)
	Register(server, gf.client(), &RegisterOptions{MultiLog: fake})
	cs, ss := connectMCPLocal(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "service", "build_number": 5},
			},
			"include_related":   true,
			"related_max":       4,
			"related_direction": "both",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSONLocal(t, res)
	logs, ok := payload["logs"].([]any)
	if !ok || len(logs) < 3 {
		t.Fatalf("want primary+upstream+downstream, got %v", payload["logs"])
	}
	byJob := map[string]string{}
	for _, row := range logs {
		m := row.(map[string]any)
		job, _ := m["job_name"].(string)
		rel, _ := m["relation"].(string)
		byJob[job] = rel
	}
	if byJob["service"] != RelationPrimary {
		t.Fatalf("service relation=%q", byJob["service"])
	}
	if byJob["deploy"] != RelationUpstream {
		t.Fatalf("deploy relation=%q want upstream", byJob["deploy"])
	}
	if byJob["smoke"] != RelationDownstream {
		t.Fatalf("smoke relation=%q want downstream", byJob["smoke"])
	}
	// AcquireMulti saw all three (policy allow-all).
	fake.mu.Lock()
	n := len(fake.LastReqs)
	fake.mu.Unlock()
	if n != 3 {
		t.Fatalf("AcquireMulti reqs=%d want 3: %+v", n, fake.LastReqs)
	}
	// Residuals should note discovery addition (no secrets).
	residuals, _ := payload["residuals"].([]any)
	var sawAdd bool
	for _, r := range residuals {
		if s, ok := r.(string); ok && strings.Contains(s, "related discovery added") {
			sawAdd = true
		}
	}
	if !sawAdd {
		t.Fatalf("expected related discovery residual note: %v", residuals)
	}
}

func TestMirrorLogs_IncludeRelated_SoftFailGraph(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gf := newGraphHTTPFixture()
	defer gf.close()
	gf.mu.Lock()
	gf.failAll = true
	gf.mu.Unlock()

	fake := &relatedFakeMulti{}
	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-soft", Version: "test"}, nil)
	Register(server, gf.client(), &RegisterOptions{MultiLog: fake})
	cs, ss := connectMCPLocal(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "service", "build_number": 5},
			},
			"include_related": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("soft-fail must not fail whole tool: %+v", res)
	}
	payload := toolStructuredJSONLocal(t, res)
	logs, _ := payload["logs"].([]any)
	if len(logs) != 1 {
		t.Fatalf("primaries still acquired only: %v", payload["logs"])
	}
	// Soft-fail paths: graph call hard error, root-only / empty graph, or no extras.
	// Never fails the whole tool; primaries still acquire.
	residuals, _ := payload["residuals"].([]any)
	var sawRelatedNote bool
	for _, r := range residuals {
		s, ok := r.(string)
		if !ok {
			continue
		}
		if strings.Contains(s, "soft-failed") ||
			strings.Contains(s, "related discovery") ||
			strings.Contains(s, "root-only") {
			sawRelatedNote = true
		}
	}
	if !sawRelatedNote {
		t.Fatalf("expected related discovery residual note: %v", residuals)
	}
	// No related jobs invented when graph is unavailable.
	for _, row := range logs {
		m := row.(map[string]any)
		if m["job_name"] != "service" {
			t.Fatalf("unexpected job when graph failed: %v", m)
		}
	}
	fake.mu.Lock()
	n := len(fake.LastReqs)
	fake.mu.Unlock()
	if n != 1 || fake.LastReqs[0].Job != "service" {
		t.Fatalf("LastReqs=%+v", fake.LastReqs)
	}
}

func TestMirrorLogs_IncludeRelated_FailClosedRelatedMax(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &relatedFakeMulti{}
	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-cap", Version: "test"}, nil)
	Register(server, &jenkins.Client{}, &RegisterOptions{MultiLog: fake})
	cs, ss := connectMCPLocal(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "service", "build_number": 5},
			},
			"include_related": true,
			"related_max":     HardRelatedMax + 1,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected tool error for related_max > hard max")
	}
	// Must not call acquire on invalid args.
	if fake.Calls != 0 {
		t.Fatalf("AcquireCalls=%d want 0", fake.Calls)
	}
}

func TestMirrorLogs_IncludeRelated_PolicyOnRelatedJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	gf := newGraphHTTPFixture()
	defer gf.close()
	gf.setServiceGraph()

	fake := &relatedFakeMulti{}
	doc := policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"deploy"},
	}
	ev := policy.NewDenyOnlyEvaluator(doc)
	subject := policy.NewSubject("corp", "alice", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-rel-deny", Version: "test"}, nil)
	Register(server, gf.client(), &RegisterOptions{
		MultiLog: fake,
		Policy:   ev,
		Subject:  subject,
	})
	cs, ss := connectMCPLocal(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "service", "build_number": 5},
			},
			"include_related": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("partial deny should not fail tool: %+v", res)
	}
	payload := toolStructuredJSONLocal(t, res)
	logs, _ := payload["logs"].([]any)
	var sawDeployDenied, sawService, sawSmoke bool
	for _, row := range logs {
		m := row.(map[string]any)
		job, _ := m["job_name"].(string)
		status, _ := m["status"].(string)
		switch job {
		case "deploy":
			if status != MirrorStatusDenied {
				t.Fatalf("deploy status=%q want denied", status)
			}
			sawDeployDenied = true
		case "service":
			sawService = true
		case "smoke":
			sawSmoke = true
		}
	}
	if !sawDeployDenied || !sawService || !sawSmoke {
		t.Fatalf("expected deploy denied + service + smoke: %v", payload["logs"])
	}
	for _, r := range fake.LastReqs {
		if strings.HasPrefix(r.Job, "deploy") {
			t.Fatalf("denied related job must not acquire: %+v", r)
		}
	}
}

// Wave 30 review: denied primary must not call GetBuildGraph (no metadata side-channel).
func TestMirrorLogs_IncludeRelated_PrimaryDeniedSkipsGraph(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	gf := newGraphHTTPFixture()
	defer gf.close()
	gf.setServiceGraph()

	fake := &relatedFakeMulti{}
	doc := policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"service"},
	}
	ev := policy.NewDenyOnlyEvaluator(doc)
	subject := policy.NewSubject("corp", "alice", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-seed-deny", Version: "test"}, nil)
	Register(server, gf.client(), &RegisterOptions{
		MultiLog: fake,
		Policy:   ev,
		Subject:  subject,
	})
	cs, ss := connectMCPLocal(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "service", "build_number": 5},
			},
			"include_related": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSONLocal(t, res)
	// Zero Jenkins graph HTTP hits when primary is denied.
	gf.mu.Lock()
	hits := gf.hits
	gf.mu.Unlock()
	if hits != 0 {
		t.Fatalf("GetBuildGraph must not run for denied primary: hits=%d", hits)
	}
	residuals, _ := payload["residuals"].([]any)
	var sawSkip bool
	for _, r := range residuals {
		if s, ok := r.(string); ok && strings.Contains(s, "related discovery skipped") {
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Fatalf("expected related discovery skipped residual: %v", residuals)
	}
	// No related jobs acquired.
	for _, r := range fake.LastReqs {
		if r.Job == "deploy" || r.Job == "smoke" {
			t.Fatalf("must not acquire related when primary denied: %+v", r)
		}
	}
}

func TestDiscoverRelated_FirstPrimaryOnly(t *testing.T) {
	t.Parallel()
	gf := newGraphHTTPFixture()
	defer gf.close()
	gf.setServiceGraph()

	seen := map[string]struct{}{
		"service|5": {},
		"other|1":   {},
	}
	seeds := []MultiLogRequest{
		{Job: "service", Build: 5, Relation: RelationPrimary},
		{Job: "other", Build: 1, Relation: RelationPrimary},
	}
	extra, notes := discoverRelatedMirrorRequests(
		context.Background(), gf.client(), seeds, seen, 4, jenkins.GraphDirectionBoth,
	)
	if len(extra) < 1 {
		t.Fatalf("expected extras from first seed: %+v notes=%v", extra, notes)
	}
	var sawBoundNote bool
	for _, n := range notes {
		if strings.Contains(n, "first primary only") {
			sawBoundNote = true
		}
	}
	if !sawBoundNote {
		t.Fatalf("expected first-primary-only note: %v", notes)
	}
	// other is seed; deploy/smoke from service graph only.
	for _, e := range extra {
		if e.Job == "other" {
			t.Fatal("must not invent other relations")
		}
	}
}

// connectMCPLocal / toolStructuredJSONLocal avoid depending on tools_test helpers.
func connectMCPLocal(t *testing.T, ctx context.Context, server *mcp.Server) (*mcp.ClientSession, *mcp.ServerSession) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		_ = ss.Close()
		t.Fatalf("client connect: %v", err)
	}
	return cs, ss
}

func toolStructuredJSONLocal(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("nil result")
	}
	// Prefer structured content.
	if res.StructuredContent != nil {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok && tc != nil {
			var m map[string]any
			if err := json.Unmarshal([]byte(tc.Text), &m); err == nil {
				return m
			}
		}
	}
	t.Fatalf("no structured JSON in result: %+v", res)
	return nil
}
