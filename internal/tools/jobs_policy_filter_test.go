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

func TestFilterDeniedJobs_Unit(t *testing.T) {
	jobs := []jenkins.JobSummary{
		{FullName: "public/app", Name: "app"},
		{FullName: "secret-folder/job-a", Name: "job-a"},
		{FullName: "secret-folder/nested/x", Name: "x"},
		{FullName: "team/public", Name: "public"},
	}
	kept, omitted := tools.FilterDeniedJobs([]string{"secret-folder/**"}, jobs)
	if omitted != 2 {
		t.Fatalf("omitted=%d want 2", omitted)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d want 2: %+v", len(kept), kept)
	}
	if kept[0].FullName != "public/app" || kept[1].FullName != "team/public" {
		t.Fatalf("kept full names: %q %q", kept[0].FullName, kept[1].FullName)
	}
	// Empty patterns: keep all.
	keptAll, om0 := tools.FilterDeniedJobs(nil, jobs)
	if om0 != 0 || len(keptAll) != 4 {
		t.Fatalf("empty patterns: kept=%d omitted=%d", len(keptAll), om0)
	}
	// Exact / path-prefix form without /**.
	keptExact, omExact := tools.FilterDeniedJobs([]string{"secret-folder"}, jobs)
	if omExact != 2 || len(keptExact) != 2 {
		t.Fatalf("literal prefix: kept=%+v omitted=%d", keptExact, omExact)
	}
	// public must not match secret-folder-other style.
	keptOther, omOther := tools.FilterDeniedJobs([]string{"secret-folder"}, []jenkins.JobSummary{
		{FullName: "secret-folder-other"},
		{FullName: "secret-folder"},
	})
	if omOther != 1 || len(keptOther) != 1 || keptOther[0].FullName != "secret-folder-other" {
		t.Fatalf("path prefix not bare string: kept=%+v omitted=%d", keptOther, omOther)
	}
}

// listJobsFixture serves root /api/json and nested folder job paths for ListJobs.
type listJobsFixture struct {
	srv      *httptest.Server
	hitCount int // root /api/json hits (ListJobs walk entry)
}

func newListJobsFixture() *listJobsFixture {
	// Flat + one secret folder tree (secret-folder/job-a under folder).
	root := `{
		"jobs": [
			{
				"name": "public-app",
				"fullName": "public-app",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/public-app/",
				"color": "blue",
				"buildable": true
			},
			{
				"name": "secret-folder",
				"fullName": "secret-folder",
				"_class": "com.cloudbees.hudson.plugins.folder.Folder",
				"url": "http://jenkins/job/secret-folder/",
				"color": "blue",
				"buildable": false
			},
			{
				"name": "team-ci",
				"fullName": "team-ci",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/team-ci/",
				"color": "blue",
				"buildable": true
			}
		]
	}`
	secretFolder := `{
		"name": "secret-folder",
		"fullName": "secret-folder",
		"_class": "com.cloudbees.hudson.plugins.folder.Folder",
		"jobs": [
			{
				"name": "job-a",
				"fullName": "secret-folder/job-a",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/secret-folder/job/job-a/",
				"color": "red",
				"buildable": true
			},
			{
				"name": "job-b",
				"fullName": "secret-folder/job-b",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/secret-folder/job/job-b/",
				"color": "blue",
				"buildable": true
			}
		]
	}`

	f := &listJobsFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch {
		case path == "/api/json" || strings.HasPrefix(path, "/api/json"):
			f.hitCount++
			_, _ = w.Write([]byte(root))
		case strings.Contains(path, "/job/secret-folder/") && strings.Contains(path, "/api/json"):
			_, _ = w.Write([]byte(secretFolder))
		case strings.HasSuffix(path, "/job/secret-folder/api/json") ||
			strings.Contains(path, "/job/secret-folder/api/json"):
			_, _ = w.Write([]byte(secretFolder))
		default:
			// ListJobs may request folder via BuildJobPath.
			if strings.Contains(path, "secret-folder") && strings.Contains(path, "api/json") {
				_, _ = w.Write([]byte(secretFolder))
				return
			}
			http.NotFound(w, r)
		}
	}))
	return f
}

// newListJobsPageBoundaryFixture builds jobs where denied names sort first so
// page-level filter with limit=1 would return an empty first page, while
// collect+filter+repaginate returns the first kept job.
func newListJobsPageBoundaryFixture() *listJobsFixture {
	// Lexicographic order: aaa-denied, bbb-denied, ccc-kept, ddd-kept
	root := `{
		"jobs": [
			{
				"name": "aaa-denied",
				"fullName": "aaa-denied",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/aaa-denied/",
				"color": "blue",
				"buildable": true
			},
			{
				"name": "bbb-denied",
				"fullName": "bbb-denied",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/bbb-denied/",
				"color": "blue",
				"buildable": true
			},
			{
				"name": "ccc-kept",
				"fullName": "ccc-kept",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/ccc-kept/",
				"color": "blue",
				"buildable": true
			},
			{
				"name": "ddd-kept",
				"fullName": "ddd-kept",
				"_class": "hudson.model.FreeStyleProject",
				"url": "http://jenkins/job/ddd-kept/",
				"color": "blue",
				"buildable": true
			}
		]
	}`
	f := &listJobsFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path != "/api/json" && !strings.HasPrefix(path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		f.hitCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(root))
	}))
	return f
}

func (f *listJobsFixture) close() { f.srv.Close() }

func (f *listJobsFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

// Wave 37: jenkins_list_jobs omits deny_job_prefixes rows; keeps others; sets policy flags.
func TestListJobs_PolicyFilter_OmitsDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newListJobsFixture()
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder/**"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "jobs-filter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"offset": 0, "limit": 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}

	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListJobsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v raw=%s", err, raw)
	}

	// Accept map-shaped StructuredContent if typed decode left empty.
	if len(out.Jobs) == 0 && !out.PolicyFiltered {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil {
			if jobs, ok := m["jobs"].([]any); ok {
				out.Jobs = make([]jenkins.JobSummary, 0, len(jobs))
				for _, j := range jobs {
					jb, _ := json.Marshal(j)
					var js jenkins.JobSummary
					_ = json.Unmarshal(jb, &js)
					out.Jobs = append(out.Jobs, js)
				}
			}
			if pf, ok := m["policy_filtered"].(bool); ok {
				out.PolicyFiltered = pf
			}
			if pc, ok := m["policy_omitted_count"].(float64); ok {
				out.PolicyOmittedCount = int(pc)
			}
			if tot, ok := m["total"].(float64); ok {
				out.Total = int(tot)
			}
		}
	}

	names := make([]string, 0, len(out.Jobs))
	for _, j := range out.Jobs {
		names = append(names, j.FullName)
		if strings.HasPrefix(j.FullName, "secret-folder") {
			t.Fatalf("denied job leaked: %q full=%s", j.FullName, raw)
		}
	}
	// Expect public-app + team-ci (secret-folder/* omitted; folders excluded by default).
	if len(out.Jobs) != 2 {
		t.Fatalf("want 2 kept jobs, got %d names=%v raw=%s", len(out.Jobs), names, raw)
	}
	want := map[string]bool{"public-app": true, "team-ci": true}
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
	if out.Total != 2 {
		t.Fatalf("total=%d want 2 after filter raw=%s", out.Total, raw)
	}
	// Must not leak denied names in response body.
	if strings.Contains(string(raw), "secret-folder/job-a") ||
		strings.Contains(string(raw), "secret-folder/job-b") {
		t.Fatalf("denied job name leaked in response: %s", raw)
	}
}

// Empty deny_job_prefixes → full list, no policy flags.
func TestListJobs_PolicyFilter_EmptyPatternsUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newListJobsFixture()
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "jobs-nofilter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListJobsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	// public-app, secret-folder/job-a, secret-folder/job-b, team-ci
	if len(out.Jobs) != 4 {
		t.Fatalf("want all 4 leaf jobs, got %d raw=%s", len(out.Jobs), raw)
	}
	if out.PolicyFiltered || out.PolicyOmittedCount != 0 {
		t.Fatalf("no filter flags expected: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	if out.Total != 4 {
		t.Fatalf("total=%d want 4", out.Total)
	}
}

// Nil policy evaluator → no filter (same as empty patterns).
func TestListJobs_PolicyFilter_NilEvaluator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newListJobsFixture()
	defer f.close()

	server := mcp.NewServer(&mcp.Implementation{Name: "jobs-nil-pol", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListJobsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Jobs) != 4 {
		t.Fatalf("want 4 jobs without policy, got %d raw=%s", len(out.Jobs), raw)
	}
}

// Wave 39: empty deny patterns → single ListJobs path (no multi-fetch collect).
func TestListJobs_PolicyFilter_EmptyPatternsSingleFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newListJobsFixture()
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "jobs-single", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"limit": 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}
	// Root /api/json should be hit exactly once (single ListJobs; folder walk is extra).
	if f.hitCount != 1 {
		t.Fatalf("empty patterns must not multi-fetch collect: root hitCount=%d want 1", f.hitCount)
	}
}

// Wave 39: collect+filter+repaginate — denied jobs first alphabetically would
// empty a page-level limit=1 response; after full filter limit=1 walks clean kept rows.
func TestListJobs_PolicyFilter_CollectRepaginateLimit1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newListJobsPageBoundaryFixture()
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"aaa-denied", "bbb-denied"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "jobs-page", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	decode := func(res *mcp.CallToolResult) jenkins.ListJobsToolResponse {
		t.Helper()
		if res == nil || res.IsError {
			t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
		}
		raw, _ := json.Marshal(res.StructuredContent)
		var out jenkins.ListJobsToolResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v raw=%s", err, raw)
		}
		return out
	}

	// Page 0: limit=1 → first KEPT job (ccc-kept), not empty / not denied.
	res0, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"offset": 0, "limit": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	p0 := decode(res0)
	if len(p0.Jobs) != 1 {
		t.Fatalf("page0 jobs=%d want 1 (collect+filter; page-level would be empty) raw jobs=%+v", len(p0.Jobs), p0.Jobs)
	}
	if p0.Jobs[0].FullName != "ccc-kept" {
		t.Fatalf("page0 job=%q want ccc-kept", p0.Jobs[0].FullName)
	}
	if !p0.PolicyFiltered || p0.PolicyOmittedCount != 2 {
		t.Fatalf("page0 policy: filtered=%v omitted=%d want true/2", p0.PolicyFiltered, p0.PolicyOmittedCount)
	}
	if p0.Total != 2 {
		t.Fatalf("page0 total=%d want 2 (kept)", p0.Total)
	}
	if p0.NextPageToken == "" {
		t.Fatal("page0 must have next_page_token (2 kept, limit=1)")
	}

	// Page 1: follow next_page_token → ddd-kept; stable policy_omitted_count.
	res1, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"page_token": p0.NextPageToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	p1 := decode(res1)
	if len(p1.Jobs) != 1 || p1.Jobs[0].FullName != "ddd-kept" {
		t.Fatalf("page1 jobs=%+v want ddd-kept", p1.Jobs)
	}
	if p1.NextPageToken != "" {
		t.Fatalf("page1 should be final: next=%q", p1.NextPageToken)
	}
	if !p1.PolicyFiltered || p1.PolicyOmittedCount != 2 {
		t.Fatalf("page1 policy: filtered=%v omitted=%d want true/2", p1.PolicyFiltered, p1.PolicyOmittedCount)
	}
	if p1.PolicyOmittedCount != p0.PolicyOmittedCount {
		t.Fatalf("policy_omitted_count unstable: p0=%d p1=%d", p0.PolicyOmittedCount, p1.PolicyOmittedCount)
	}
	// No denied names on any page / payload.
	for _, res := range []*mcp.CallToolResult{res0, res1} {
		raw, _ := json.Marshal(res.StructuredContent)
		if strings.Contains(string(raw), "aaa-denied") || strings.Contains(string(raw), "bbb-denied") {
			t.Fatalf("denied job name leaked: %s", raw)
		}
	}
}

// Wave 39: empty after filter → empty jobs, total 0, no crash.
func TestListJobs_PolicyFilter_AllDeniedEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newListJobsPageBoundaryFixture()
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"aaa-denied", "bbb-denied", "ccc-kept", "ddd-kept"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "jobs-alldeny", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"limit": 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ListJobsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Jobs) != 0 {
		t.Fatalf("want empty jobs, got %d: %+v", len(out.Jobs), out.Jobs)
	}
	if out.Total != 0 {
		t.Fatalf("total=%d want 0", out.Total)
	}
	if !out.PolicyFiltered || out.PolicyOmittedCount != 4 {
		t.Fatalf("policy: filtered=%v omitted=%d want true/4", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	if out.NextPageToken != "" {
		t.Fatalf("no next token on empty: %q", out.NextPageToken)
	}
}

// Wave 39 unit: PaginateJobs slices kept list like ListJobs.
func TestPaginateJobs_Unit(t *testing.T) {
	t.Parallel()
	jobs := []jenkins.JobSummary{
		{FullName: "a"}, {FullName: "b"}, {FullName: "c"},
	}
	page, off, lim := tools.PaginateJobs(jobs, 1, 1)
	if off != 1 || lim != 1 || len(page) != 1 || page[0].FullName != "b" {
		t.Fatalf("page=%+v off=%d lim=%d", page, off, lim)
	}
	page2, _, _ := tools.PaginateJobs(jobs, 10, 5)
	if len(page2) != 0 {
		t.Fatalf("offset past end: %+v", page2)
	}
	// Defaults.
	page3, off3, lim3 := tools.PaginateJobs(jobs, -1, 0)
	if off3 != 0 || lim3 != jenkins.DefaultListJobsLimit || len(page3) != 3 {
		t.Fatalf("defaults: page=%d off=%d lim=%d", len(page3), off3, lim3)
	}
}

// Wave 39: list_jobs branch filter uses BranchDenyCandidates (slashy).
func TestFilterDeniedBranchJobs_SlashyIntermediate(t *testing.T) {
	t.Parallel()
	jobs := []jenkins.JobSummary{
		{FullName: "team/mb/release/1.2", Name: "1.2", Kind: jenkins.JobKindBranch},
		{FullName: "team/mb/main", Name: "main", Kind: jenkins.JobKindBranch},
		{FullName: "team/app", Name: "app", Kind: jenkins.JobKindJob},
	}
	kept, omitted := tools.FilterDeniedBranchJobs([]string{"release/*"}, jobs)
	if omitted != 1 {
		t.Fatalf("omitted=%d want 1", omitted)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d want 2: %+v", len(kept), kept)
	}
	for _, j := range kept {
		if j.FullName == "team/mb/release/1.2" {
			t.Fatal("slashy branch must be omitted from list")
		}
	}
}
