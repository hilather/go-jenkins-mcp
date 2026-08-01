package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 39/40: when collect hits the page safety cap with more jobs remaining,
// Truncated is forced true and a non-secret incomplete Message is set.
// Wave 41: collect uses the process override (SetListJobsCollectMaxPages / package var).
func TestListJobs_PolicyFilter_SafetyIncompleteForcesTruncated(t *testing.T) {
	// MaxListJobsLimit=200 → 201 jobs need 2 collect pages; cap at 1 page.
	const nJobs = 201
	var b strings.Builder
	b.WriteString(`{"jobs":[`)
	for i := 0; i < nJobs; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("job-%04d", i)
		fmt.Fprintf(&b, `{"name":%q,"fullName":%q,"_class":"hudson.model.FreeStyleProject","url":"http://jenkins/job/%s/","color":"blue","buildable":true}`,
			name, name, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" && !strings.HasPrefix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}

	// Wave 41: exercise SetListJobsCollectMaxPages path (serve wiring).
	old := ListJobsCollectMaxPages()
	SetListJobsCollectMaxPages(1)
	defer SetListJobsCollectMaxPages(old)

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"job-0000"}, // omit one so collect path is active
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{
		Offset: 0,
		Limit:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	if !out.Truncated {
		t.Fatalf("incomplete collect must force truncated=true; total=%d jobs=%d next=%q",
			out.Total, len(out.Jobs), out.NextPageToken)
	}
	// Wave 40: non-secret incomplete honesty message (mirror nodes/views).
	// Wave 41: message text unchanged when collect cap is hit.
	if !strings.Contains(out.Message, "collection capped") || !strings.Contains(out.Message, "incomplete") {
		t.Fatalf("incomplete Message want collection capped/incomplete; got %q", out.Message)
	}
	// Message must not leak denied names or secrets.
	if strings.Contains(out.Message, "job-0000") || strings.Contains(out.Message, "token") {
		t.Fatalf("Message must not leak policy/secret material: %q", out.Message)
	}
	// Deny-only: still never invents; omitted at least the denied job from collected page.
	if !out.PolicyFiltered || out.PolicyOmittedCount < 1 {
		t.Fatalf("policy: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	for _, j := range out.Jobs {
		if j.FullName == "job-0000" {
			t.Fatalf("denied job leaked: %q", j.FullName)
		}
	}
}

// Wave 41: resolved higher collect cap allows multi-page complete collection
// (override used by collectAllJobs).
func TestListJobs_PolicyFilter_CollectUsesResolvedCap(t *testing.T) {
	// 201 jobs → 2 pages at MaxListJobsLimit=200; with cap=2 collection completes.
	const nJobs = 201
	var b strings.Builder
	b.WriteString(`{"jobs":[`)
	for i := 0; i < nJobs; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("job-%04d", i)
		fmt.Fprintf(&b, `{"name":%q,"fullName":%q,"_class":"hudson.model.FreeStyleProject","url":"http://jenkins/job/%s/","color":"blue","buildable":true}`,
			name, name, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" && !strings.HasPrefix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}

	// Resolve env "2" (as serve would) and apply.
	n, err := ResolveListJobsCollectMaxPages("", "2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("resolve: got %d want 2", n)
	}
	old := ListJobsCollectMaxPages()
	SetListJobsCollectMaxPages(n)
	defer SetListJobsCollectMaxPages(old)

	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"job-0000"},
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{
		Offset: 0,
		Limit:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	// With cap=2, 201 jobs fit → complete (not truncated by collect safety).
	if out.Truncated {
		t.Fatalf("cap=2 should complete 201 jobs: truncated message=%q total=%d hits=%d",
			out.Message, out.Total, hits)
	}
	if strings.Contains(out.Message, "collection capped") {
		t.Fatalf("complete collect must not set incomplete Message: %q", out.Message)
	}
	// 200 kept after omitting job-0000.
	if out.Total != nJobs-1 {
		t.Fatalf("total=%d want %d (deny one)", out.Total, nJobs-1)
	}
	if hits < 2 {
		t.Fatalf("expected multi-page collect hits≥2 got %d", hits)
	}
}

// Wave 40: page_token minted under deny policy A fails closed when resolved
// under different deny policy B (filter fingerprint mismatch).
func TestListJobs_PolicyFilter_PageTokenPolicyMismatch(t *testing.T) {
	body := `{"jobs":[
		{"name":"aaa","fullName":"aaa","_class":"hudson.model.FreeStyleProject","url":"http://j/job/aaa/","color":"blue","buildable":true},
		{"name":"bbb","fullName":"bbb","_class":"hudson.model.FreeStyleProject","url":"http://j/job/bbb/","color":"blue","buildable":true},
		{"name":"ccc","fullName":"ccc","_class":"hudson.model.FreeStyleProject","url":"http://j/job/ccc/","color":"blue","buildable":true}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" && !strings.HasPrefix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	ctx := context.Background()

	stA := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"aaa"},
	})}
	page0, err := listJobsWithPolicyFilter(ctx, client, stA, jenkins.ListJobsToolArgs{
		Offset: 0,
		Limit:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page0.NextPageToken == "" {
		t.Fatalf("need next_page_token under policy A: total=%d jobs=%d", page0.Total, len(page0.Jobs))
	}

	// Same token under different deny set → fail closed.
	stB := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"bbb"},
	})}
	_, err = listJobsWithPolicyFilter(ctx, client, stB, jenkins.ListJobsToolArgs{
		PageToken: page0.NextPageToken,
	})
	if err == nil {
		t.Fatal("expected filter mismatch when policy changes")
	}
	if !strings.Contains(err.Error(), "filter") {
		t.Fatalf("want filter mismatch message: %v", err)
	}

	// Empty vs non-empty deny: token from A under empty policy still collect-path
	// only when keeps non-empty; empty patterns go to single ListJobs with different FP.
	stEmpty := regState{} // no policy
	// Empty patterns uses Client.ListJobs fingerprint (user-only) — different path.
	// Token from collect path must not be accepted as a silent continue.
	_, err = listJobsWithPolicyFilter(ctx, client, stEmpty, jenkins.ListJobsToolArgs{
		PageToken: page0.NextPageToken,
	})
	// Empty path uses Jenkins fingerprint; mismatch is still fail-closed if
	// Client.ListJobs checks the token — or succeeds with wrong FP and fails.
	// Client.ListJobs resolves with user-only FP → mismatch → invalid_argument.
	if err == nil {
		t.Fatal("expected mismatch when resolving policy-bound token under empty deny")
	}
	if !strings.Contains(err.Error(), "filter") {
		t.Fatalf("want filter mismatch under empty deny: %v", err)
	}
}

// Wave 40: same-policy page tokens still work across pages.
func TestListJobs_PolicyFilter_PageTokenSamePolicyWorks(t *testing.T) {
	body := `{"jobs":[
		{"name":"aaa-deny","fullName":"aaa-deny","_class":"hudson.model.FreeStyleProject","url":"http://j/job/aaa-deny/","color":"blue","buildable":true},
		{"name":"bbb-keep","fullName":"bbb-keep","_class":"hudson.model.FreeStyleProject","url":"http://j/job/bbb-keep/","color":"blue","buildable":true},
		{"name":"ccc-keep","fullName":"ccc-keep","_class":"hudson.model.FreeStyleProject","url":"http://j/job/ccc-keep/","color":"blue","buildable":true}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" && !strings.HasPrefix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"aaa-deny"},
	})}
	ctx := context.Background()

	p0, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(p0.Jobs) != 1 || p0.Jobs[0].FullName != "bbb-keep" {
		t.Fatalf("page0=%+v want bbb-keep", p0.Jobs)
	}
	if p0.NextPageToken == "" {
		t.Fatal("expected next_page_token")
	}

	p1, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{
		PageToken: p0.NextPageToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Jobs) != 1 || p1.Jobs[0].FullName != "ccc-keep" {
		t.Fatalf("page1=%+v want ccc-keep", p1.Jobs)
	}
	if p1.NextPageToken != "" {
		t.Fatalf("page1 should be final: next=%q", p1.NextPageToken)
	}
	if p0.PolicyOmittedCount != p1.PolicyOmittedCount || p0.PolicyOmittedCount != 1 {
		t.Fatalf("omitted unstable: p0=%d p1=%d", p0.PolicyOmittedCount, p1.PolicyOmittedCount)
	}
}

// Wave 40: PolicyFingerprintMaterial is sorted and namespaced; empty when no denies.
func TestPolicyFingerprintMaterial(t *testing.T) {
	if got := PolicyFingerprintMaterial(regState{}); got != nil {
		t.Fatalf("empty policy: got %v", got)
	}
	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"z-job", "a-job"},
		DenyBranchNames: []string{"main", "dev"},
	})}
	got := PolicyFingerprintMaterial(st)
	// Expected: deny_job_prefixes, a-job, z-job, deny_branch_names, dev, main
	want := []string{"deny_job_prefixes", "a-job", "z-job", "deny_branch_names", "dev", "main"}
	if len(got) != len(want) {
		t.Fatalf("len=%d got=%v want=%v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("part[%d]=%q want %q full=%v", i, got[i], want[i], got)
		}
	}
	// Document order change must not change material.
	st2 := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"a-job", "z-job"},
		DenyBranchNames: []string{"dev", "main"},
	})}
	got2 := PolicyFingerprintMaterial(st2)
	for i := range want {
		if got2[i] != want[i] {
			t.Fatalf("order-insensitive fail: got2=%v", got2)
		}
	}
}

// Wave 39: empty patterns → single ListJobs (no collect multi-page).
func TestListJobs_PolicyFilter_EmptyPatternsNoCollect(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" && !strings.HasPrefix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jobs":[
			{"name":"a","fullName":"a","_class":"hudson.model.FreeStyleProject","url":"http://j/job/a/","color":"blue","buildable":true}
		]}`))
	}))
	defer srv.Close()

	client := &jenkins.Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	st := regState{} // nil policy
	ctx := context.Background()
	out, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("empty patterns must call ListJobs once: hits=%d", hits)
	}
	if out.PolicyFiltered || len(out.Jobs) != 1 {
		t.Fatalf("out=%+v", out)
	}
}
