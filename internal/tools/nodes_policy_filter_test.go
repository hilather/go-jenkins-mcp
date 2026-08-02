package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFilterDeniedNodes_Unit(t *testing.T) {
	nodes := []jenkins.NodeSummary{
		{Name: "prod-agent-01", Offline: false, NumExecutors: 2, BusyExecutors: 1, IdleExecutors: 1},
		{Name: "ci-1", Offline: false, NumExecutors: 1, IdleExecutors: 1},
		{Name: "prod-agent-02", Offline: true, NumExecutors: 1, IdleExecutors: 1},
		{Name: "master", Offline: false, NumExecutors: 2, BusyExecutors: 0, IdleExecutors: 2},
	}
	kept, omitted := tools.FilterDeniedNodes([]string{"prod-agent-*"}, nodes)
	if omitted != 2 {
		t.Fatalf("omitted=%d want 2", omitted)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d want 2: %+v", len(kept), kept)
	}
	if kept[0].Name != "ci-1" || kept[1].Name != "master" {
		t.Fatalf("kept names: %v %v", kept[0].Name, kept[1].Name)
	}
	// Empty patterns: keep all.
	keptAll, om0 := tools.FilterDeniedNodes(nil, nodes)
	if om0 != 0 || len(keptAll) != 4 {
		t.Fatalf("empty patterns: kept=%d omitted=%d", len(keptAll), om0)
	}
	// Exact match.
	keptExact, omExact := tools.FilterDeniedNodes([]string{"secret-node"}, []jenkins.NodeSummary{
		{Name: "secret-node"}, {Name: "secret-node-other"},
	})
	if omExact != 1 || len(keptExact) != 1 || keptExact[0].Name != "secret-node-other" {
		t.Fatalf("exact: kept=%+v omitted=%d", keptExact, omExact)
	}
}

// nodesListFixture serves /computer/api/json for get_nodes policy filter tests.
type nodesListFixture struct {
	srv      *httptest.Server
	body     string
	status   int
	hitCount int
}

func newNodesListFixture(body string) *nodesListFixture {
	f := &nodesListFixture{body: body, status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/computer/api/json") {
			http.NotFound(w, r)
			return
		}
		f.hitCount++
		if f.status == http.StatusForbidden {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.body))
	}))
	return f
}

func (f *nodesListFixture) close() { f.srv.Close() }

func (f *nodesListFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

const fixtureNodesJSON = `{
	"computer": [
		{
			"displayName": "master",
			"offline": false,
			"numExecutors": 2,
			"idle": true,
			"assignedLabels": [{"name": "master"}],
			"executors": [{"idle": true}, {"idle": true}]
		},
		{
			"displayName": "prod-agent-01",
			"offline": false,
			"numExecutors": 1,
			"idle": false,
			"assignedLabels": [{"name": "prod-agent-01"}, {"name": "prod"}],
			"executors": [{"idle": false}]
		},
		{
			"displayName": "ci-1",
			"offline": false,
			"numExecutors": 1,
			"idle": true,
			"assignedLabels": [{"name": "ci-1"}],
			"executors": [{"idle": true}]
		},
		{
			"displayName": "prod-agent-02",
			"offline": true,
			"numExecutors": 1,
			"idle": true,
			"assignedLabels": [{"name": "prod-agent-02"}],
			"executors": [{"idle": true}]
		}
	]
}`

// Wave 36: jenkins_get_nodes omits deny_node_names rows; keeps others; sets policy flags.
func TestGetNodes_PolicyFilter_OmitsDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newNodesListFixture(fixtureNodesJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "nodes-filter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_nodes",
		Arguments: map[string]any{"offset": 0, "limit": 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}

	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.GetNodesToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		// StructuredContent may be map — re-decode via json round-trip of content.
		t.Fatalf("decode: %v raw=%s", err, raw)
	}

	// Accept either typed StructuredContent or map shape.
	if len(out.Nodes) == 0 {
		// try map path
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil {
			if nodes, ok := m["nodes"].([]any); ok {
				out.Nodes = make([]jenkins.NodeSummary, 0, len(nodes))
				for _, n := range nodes {
					nb, _ := json.Marshal(n)
					var ns jenkins.NodeSummary
					_ = json.Unmarshal(nb, &ns)
					out.Nodes = append(out.Nodes, ns)
				}
			}
			if pf, ok := m["policy_filtered"].(bool); ok {
				out.PolicyFiltered = pf
			}
			if pc, ok := m["policy_omitted_count"].(float64); ok {
				out.PolicyOmittedCount = int(pc)
			}
			if sum, ok := m["summary"].(map[string]any); ok {
				if v, ok := sum["totalNodes"].(float64); ok {
					out.Summary.TotalNodes = int(v)
				}
				if v, ok := sum["offlineNodes"].(float64); ok {
					out.Summary.OfflineNodes = int(v)
				}
			}
		}
	}

	names := make([]string, 0, len(out.Nodes))
	for _, n := range out.Nodes {
		names = append(names, n.Name)
		if strings.HasPrefix(n.Name, "prod-agent-") {
			t.Fatalf("denied node leaked: %q full=%s", n.Name, raw)
		}
	}
	if len(out.Nodes) != 2 {
		t.Fatalf("want 2 kept nodes, got %d names=%v raw=%s", len(out.Nodes), names, raw)
	}
	want := map[string]bool{"master": true, "ci-1": true}
	for _, n := range names {
		if !want[n] {
			t.Fatalf("unexpected kept %q", n)
		}
	}
	if !out.PolicyFiltered {
		t.Fatalf("policy_filtered want true: %s", raw)
	}
	if out.PolicyOmittedCount != 2 {
		t.Fatalf("policy_omitted_count=%d want 2 raw=%s", out.PolicyOmittedCount, raw)
	}
	// Summary is over returned/kept set (controller-wide after filter).
	if out.Summary.TotalNodes != 2 {
		t.Fatalf("summary.totalNodes=%d want 2 (after filter)", out.Summary.TotalNodes)
	}
	if out.Summary.OfflineNodes != 0 {
		t.Fatalf("offline after filter should be 0 (prod-agent-02 omitted): %+v", out.Summary)
	}
	// Must not leak denied names in message.
	if strings.Contains(string(raw), "prod-agent-01") || strings.Contains(string(raw), "prod-agent-02") {
		t.Fatalf("denied node name leaked in response: %s", raw)
	}
}

// Empty deny_node_names → full list, no policy flags.
func TestGetNodes_PolicyFilter_EmptyPatternsUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newNodesListFixture(fixtureNodesJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "nodes-nofilter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_nodes",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.GetNodesToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Nodes) != 4 {
		t.Fatalf("want all 4 nodes, got %d raw=%s", len(out.Nodes), raw)
	}
	if out.PolicyFiltered || out.PolicyOmittedCount != 0 {
		t.Fatalf("no filter flags expected: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	if out.Summary.TotalNodes != 4 {
		t.Fatalf("summary total=%d", out.Summary.TotalNodes)
	}
}

// Unauthorized (403) path unchanged — no policy filter metadata required.
func TestGetNodes_PolicyFilter_UnauthorizedUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newNodesListFixture(`{}`)
	f.status = http.StatusForbidden
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "nodes-unauth", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_nodes",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("unauthorized is success payload not tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.GetNodesToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Unauthorized {
		t.Fatalf("want unauthorized: %s", raw)
	}
	if len(out.Nodes) != 0 {
		t.Fatal("nodes must be empty when unauthorized")
	}
	if out.PolicyFiltered || out.PolicyOmittedCount != 0 {
		t.Fatalf("no policy filter on unauthorized: %s", raw)
	}
}

// Wave 37: after FilterDeniedNodes, paginate with limit=1 across 2+ kept nodes.
// Assert nextOffset walk, no denied names on any page, stable policy_omitted_count.
func TestFilterDeniedNodes_PaginateLimit1(t *testing.T) {
	t.Parallel()
	nodes := []jenkins.NodeSummary{
		{Name: "prod-agent-01"},
		{Name: "ci-1"},
		{Name: "prod-agent-02"},
		{Name: "master"},
	}
	// Deny 2 prod agents → keep ci-1, master (order preserved).
	kept, omitted := tools.FilterDeniedNodes([]string{"prod-agent-*"}, nodes)
	if omitted != 2 || len(kept) != 2 {
		t.Fatalf("kept=%d omitted=%d want kept=2 omitted=2", len(kept), omitted)
	}
	if kept[0].Name != "ci-1" || kept[1].Name != "master" {
		t.Fatalf("kept order: %+v", kept)
	}

	// Page 0 limit=1 → first kept only.
	page0, trunc0, next0, off0, lim0 := tools.PaginateNodes(kept, 0, 1)
	if !trunc0 || next0 != 1 || off0 != 0 || lim0 != 1 || len(page0) != 1 || page0[0].Name != "ci-1" {
		t.Fatalf("page0: page=%+v trunc=%v next=%d off=%d lim=%d", page0, trunc0, next0, off0, lim0)
	}
	// Page 1 limit=1 → second kept; final page.
	page1, trunc1, next1, off1, lim1 := tools.PaginateNodes(kept, next0, 1)
	if trunc1 || next1 != 0 || off1 != 1 || lim1 != 1 || len(page1) != 1 || page1[0].Name != "master" {
		t.Fatalf("page1: page=%+v trunc=%v next=%d off=%d lim=%d", page1, trunc1, next1, off1, lim1)
	}
	// Walk collected names: no denied.
	for _, p := range [][]jenkins.NodeSummary{page0, page1} {
		for _, n := range p {
			if strings.HasPrefix(n.Name, "prod-agent-") {
				t.Fatalf("denied name on page: %q", n.Name)
			}
		}
	}
	// Omitted count is independent of pagination (stable across pages).
	if omitted != 2 {
		t.Fatalf("policy_omitted_count must stay 2, got %d", omitted)
	}
}

// Wave 37: MCP path — limit=1 walk after deny_node_names; stable policy_omitted_count.
func TestGetNodes_PolicyFilter_PaginationLimit1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newNodesListFixture(fixtureNodesJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "nodes-page", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	decode := func(res *mcp.CallToolResult) jenkins.GetNodesToolResponse {
		t.Helper()
		if res == nil || res.IsError {
			t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
		}
		raw, _ := json.Marshal(res.StructuredContent)
		var out jenkins.GetNodesToolResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v raw=%s", err, raw)
		}
		return out
	}

	// Page 0: limit=1 → one kept node.
	res0, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_nodes",
		Arguments: map[string]any{"offset": 0, "limit": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	p0 := decode(res0)
	if len(p0.Nodes) != 1 {
		t.Fatalf("page0 nodes=%d want 1 raw names", len(p0.Nodes))
	}
	if strings.HasPrefix(p0.Nodes[0].Name, "prod-agent-") {
		t.Fatalf("denied leaked on page0: %q", p0.Nodes[0].Name)
	}
	if !p0.Truncated || p0.NextOffset != 1 {
		t.Fatalf("page0 truncated=%v nextOffset=%d want true/1", p0.Truncated, p0.NextOffset)
	}
	if !p0.PolicyFiltered || p0.PolicyOmittedCount != 2 {
		t.Fatalf("page0 policy: filtered=%v omitted=%d", p0.PolicyFiltered, p0.PolicyOmittedCount)
	}
	// Summary is controller-wide after filter (stable across pages).
	if p0.Summary.TotalNodes != 2 {
		t.Fatalf("page0 summary.totalNodes=%d want 2", p0.Summary.TotalNodes)
	}

	// Page 1: follow nextOffset.
	res1, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_nodes",
		Arguments: map[string]any{"offset": p0.NextOffset, "limit": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	p1 := decode(res1)
	if len(p1.Nodes) != 1 {
		t.Fatalf("page1 nodes=%d want 1", len(p1.Nodes))
	}
	if strings.HasPrefix(p1.Nodes[0].Name, "prod-agent-") {
		t.Fatalf("denied leaked on page1: %q", p1.Nodes[0].Name)
	}
	if p1.Nodes[0].Name == p0.Nodes[0].Name {
		t.Fatalf("pages must not repeat the same node: %q", p0.Nodes[0].Name)
	}
	if p1.Truncated {
		t.Fatalf("page1 should be final: truncated=%v next=%d", p1.Truncated, p1.NextOffset)
	}
	// Stable policy_omitted_count on every page.
	if !p1.PolicyFiltered || p1.PolicyOmittedCount != 2 {
		t.Fatalf("page1 policy: filtered=%v omitted=%d want true/2", p1.PolicyFiltered, p1.PolicyOmittedCount)
	}
	if p1.PolicyOmittedCount != p0.PolicyOmittedCount {
		t.Fatalf("policy_omitted_count unstable: p0=%d p1=%d", p0.PolicyOmittedCount, p1.PolicyOmittedCount)
	}
	if p1.Summary.TotalNodes != 2 {
		t.Fatalf("page1 summary.totalNodes=%d want 2", p1.Summary.TotalNodes)
	}

	// Combined walk covers both kept names; no denied.
	seen := map[string]bool{p0.Nodes[0].Name: true, p1.Nodes[0].Name: true}
	if !seen["master"] || !seen["ci-1"] {
		t.Fatalf("walk should cover master+ci-1, got %v", seen)
	}
	// Must not leak denied names in either response payload.
	for _, res := range []*mcp.CallToolResult{res0, res1} {
		raw, _ := json.Marshal(res.StructuredContent)
		if strings.Contains(string(raw), "prod-agent-01") || strings.Contains(string(raw), "prod-agent-02") {
			t.Fatalf("denied node name leaked: %s", raw)
		}
	}
}

// Nil policy evaluator → no filter (same as empty patterns).
func TestGetNodes_PolicyFilter_NilEvaluator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newNodesListFixture(fixtureNodesJSON)
	defer f.close()

	server := mcp.NewServer(&mcp.Implementation{Name: "nodes-nil-pol", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_nodes",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.GetNodesToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Nodes) != 4 {
		t.Fatalf("want 4 nodes without policy, got %d", len(out.Nodes))
	}
}
