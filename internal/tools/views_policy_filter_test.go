package tools_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

func TestFilterDeniedViews_Unit(t *testing.T) {
	views := []jenkins.ViewSummary{
		{Name: "all"},
		{Name: "secret-view"},
		{Name: "ci"},
		{Name: "hr/payroll"},
	}
	kept, omitted := tools.FilterDeniedViews([]string{"secret-view", "hr/**"}, views)
	if omitted != 2 {
		t.Fatalf("omitted=%d want 2", omitted)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d want 2: %+v", len(kept), kept)
	}
	if kept[0].Name != "all" || kept[1].Name != "ci" {
		t.Fatalf("kept names: %v %v", kept[0].Name, kept[1].Name)
	}
	// Empty patterns: keep all.
	keptAll, om0 := tools.FilterDeniedViews(nil, views)
	if om0 != 0 || len(keptAll) != 4 {
		t.Fatalf("empty patterns: kept=%d omitted=%d", len(keptAll), om0)
	}
	// Exact match only for secret-view.
	keptExact, omExact := tools.FilterDeniedViews([]string{"secret-view"}, []jenkins.ViewSummary{
		{Name: "secret-view"}, {Name: "secret-view-other"},
	})
	if omExact != 1 || len(keptExact) != 1 || keptExact[0].Name != "secret-view-other" {
		t.Fatalf("exact: kept=%+v omitted=%d", keptExact, omExact)
	}
}

// viewsListFixture serves /api/json for list_views policy filter tests.
type viewsListFixture struct {
	srv      *httptest.Server
	body     string
	status   int
	hitCount int
}

func newViewsListFixture(body string) *viewsListFixture {
	f := &viewsListFixture{body: body, status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" {
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

func (f *viewsListFixture) close() { f.srv.Close() }

func (f *viewsListFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

const fixtureViewsJSON = `{
	"views": [
		{"name": "all", "description": "All jobs", "_class": "hudson.model.AllView"},
		{"name": "secret-view", "description": "restricted", "_class": "hudson.model.ListView"},
		{"name": "ci", "description": "CI", "_class": "hudson.model.ListView"},
		{"name": "hr/payroll", "description": "HR", "_class": "hudson.model.ListView"}
	]
}`

// Wave 38: jenkins_list_views omits deny_view_names rows; keeps others; sets policy flags.
func TestListViews_PolicyFilter_OmitsDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newViewsListFixture(fixtureViewsJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyViewNames: []string{"secret-view", "hr/**"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "views-filter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_views",
		Arguments: map[string]any{"offset": 0, "limit": 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}

	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListViewsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v raw=%s", err, raw)
	}

	names := make([]string, 0, len(out.Views))
	for _, v := range out.Views {
		names = append(names, v.Name)
		if v.Name == "secret-view" || strings.HasPrefix(v.Name, "hr/") {
			t.Fatalf("denied view leaked: %q full=%s", v.Name, raw)
		}
	}
	if len(out.Views) != 2 {
		t.Fatalf("want 2 kept views, got %d names=%v raw=%s", len(out.Views), names, raw)
	}
	want := map[string]bool{"all": true, "ci": true}
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
	if out.Summary.TotalViews != 2 {
		t.Fatalf("summary.totalViews=%d want 2 (after filter)", out.Summary.TotalViews)
	}
	// Must not leak denied names in message/payload.
	if strings.Contains(string(raw), "secret-view") || strings.Contains(string(raw), "hr/payroll") {
		t.Fatalf("denied view name leaked in response: %s", raw)
	}
}

// Empty deny_view_names → full list, no policy flags.
func TestListViews_PolicyFilter_EmptyPatternsUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newViewsListFixture(fixtureViewsJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "views-nofilter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_views",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListViewsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Views) != 4 {
		t.Fatalf("want all 4 views, got %d raw=%s", len(out.Views), raw)
	}
	if out.PolicyFiltered || out.PolicyOmittedCount != 0 {
		t.Fatalf("no filter flags expected: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	if out.Summary.TotalViews != 4 {
		t.Fatalf("summary total=%d", out.Summary.TotalViews)
	}
}

// Unauthorized (403) path unchanged — no policy filter metadata required.
func TestListViews_PolicyFilter_UnauthorizedUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newViewsListFixture(`{}`)
	f.status = http.StatusForbidden
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyViewNames: []string{"secret-view"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "views-unauth", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_views",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("unauthorized is success payload not tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListViewsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !out.Unauthorized {
		t.Fatalf("want unauthorized: %s", raw)
	}
	if len(out.Views) != 0 {
		t.Fatal("views must be empty when unauthorized")
	}
	if out.PolicyFiltered || out.PolicyOmittedCount != 0 {
		t.Fatalf("no policy filter on unauthorized: %s", raw)
	}
}

// Nil policy evaluator → no filter (same as empty patterns).
func TestListViews_PolicyFilter_NilEvaluator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newViewsListFixture(fixtureViewsJSON)
	defer f.close()

	server := mcp.NewServer(&mcp.Implementation{Name: "views-nil-pol", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_views",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListViewsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Views) != 4 {
		t.Fatalf("want 4 views without policy, got %d", len(out.Views))
	}
}

// Wave 38: after FilterDeniedViews, paginate with limit=1 across kept views.
func TestFilterDeniedViews_PaginateLimit1(t *testing.T) {
	t.Parallel()
	views := []jenkins.ViewSummary{
		{Name: "all"},
		{Name: "secret-view"},
		{Name: "ci"},
		{Name: "secret-other"},
	}
	kept, omitted := tools.FilterDeniedViews([]string{"secret-*"}, views)
	if omitted != 2 || len(kept) != 2 {
		t.Fatalf("kept=%d omitted=%d want kept=2 omitted=2", len(kept), omitted)
	}
	if kept[0].Name != "all" || kept[1].Name != "ci" {
		t.Fatalf("kept order: %+v", kept)
	}

	page0, trunc0, next0, off0, lim0 := tools.PaginateViews(kept, 0, 1)
	if !trunc0 || next0 != 1 || off0 != 0 || lim0 != 1 || len(page0) != 1 || page0[0].Name != "all" {
		t.Fatalf("page0: page=%+v trunc=%v next=%d off=%d lim=%d", page0, trunc0, next0, off0, lim0)
	}
	page1, trunc1, next1, off1, lim1 := tools.PaginateViews(kept, next0, 1)
	if trunc1 || next1 != 0 || off1 != 1 || lim1 != 1 || len(page1) != 1 || page1[0].Name != "ci" {
		t.Fatalf("page1: page=%+v trunc=%v next=%d off=%d lim=%d", page1, trunc1, next1, off1, lim1)
	}
	if omitted != 2 {
		t.Fatalf("policy_omitted_count must stay 2, got %d", omitted)
	}
}
