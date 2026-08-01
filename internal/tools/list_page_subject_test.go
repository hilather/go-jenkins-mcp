package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Regression HOST-004: Alice's list_jobs page_token is rejected for Bob when
// SubjectKey is set on the tools path (serve wire).
func TestListJobs_SubjectKey_AliceTokenRejectedForBob(t *testing.T) {
	body := `{"jobs":[
		{"name":"j1","fullName":"j1","_class":"hudson.model.FreeStyleProject","url":"http://j/job/j1/","color":"blue","buildable":true},
		{"name":"j2","fullName":"j2","_class":"hudson.model.FreeStyleProject","url":"http://j/job/j2/","color":"blue","buildable":true},
		{"name":"j3","fullName":"j3","_class":"hudson.model.FreeStyleProject","url":"http://j/job/j3/","color":"blue","buildable":true}
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

	alice := regState{subjectKey: "tenant-a|alice|corp"}
	bob := regState{subjectKey: "tenant-a|bob|corp"}

	page0, err := listJobsWithPolicyFilter(ctx, client, alice, jenkins.ListJobsToolArgs{
		Offset: 0,
		Limit:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page0.NextPageToken == "" {
		t.Fatalf("need next_page_token: total=%d jobs=%d", page0.Total, len(page0.Jobs))
	}

	// Alice continues with her token — ok.
	page1, err := listJobsWithPolicyFilter(ctx, client, alice, jenkins.ListJobsToolArgs{
		PageToken: page0.NextPageToken,
	})
	if err != nil {
		t.Fatalf("alice continue: %v", err)
	}
	if len(page1.Jobs) < 1 {
		t.Fatalf("alice page1 empty: %#v", page1)
	}

	// Bob using Alice's token — fail closed.
	_, err = listJobsWithPolicyFilter(ctx, client, bob, jenkins.ListJobsToolArgs{
		PageToken: page0.NextPageToken,
	})
	if err == nil {
		t.Fatal("expected Alice page_token rejected for Bob")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want invalid_argument, got %v (%v)", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "filter") && !strings.Contains(err.Error(), "page_token") {
		t.Fatalf("want filter/page_token mismatch message: %v", err)
	}
}

// HOST-004: subject isolation also applies on the policy collect path.
func TestListJobs_SubjectKey_PolicyCollectPathIsolation(t *testing.T) {
	body := `{"jobs":[
		{"name":"aaa-deny","fullName":"aaa-deny","_class":"hudson.model.FreeStyleProject","url":"http://j/job/aaa-deny/","color":"blue","buildable":true},
		{"name":"bbb-keep","fullName":"bbb-keep","_class":"hudson.model.FreeStyleProject","url":"http://j/job/bbb-keep/","color":"blue","buildable":true},
		{"name":"ccc-keep","fullName":"ccc-keep","_class":"hudson.model.FreeStyleProject","url":"http://j/job/ccc-keep/","color":"blue","buildable":true}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	pol := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"aaa"},
	})
	alice := regState{policy: pol, subjectKey: "t|alice|corp"}
	bob := regState{policy: pol, subjectKey: "t|bob|corp"}

	page0, err := listJobsWithPolicyFilter(ctx, client, alice, jenkins.ListJobsToolArgs{
		Offset: 0,
		Limit:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if page0.NextPageToken == "" {
		t.Fatalf("need next_page_token under policy: total=%d", page0.Total)
	}

	_, err = listJobsWithPolicyFilter(ctx, client, bob, jenkins.ListJobsToolArgs{
		PageToken: page0.NextPageToken,
	})
	if err == nil {
		t.Fatal("expected subject mismatch on policy collect path")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
}

// Empty SubjectKey keeps prior unbound page_token behavior (stdio residual).
func TestListJobs_EmptySubjectKey_UnboundCompatible(t *testing.T) {
	body := `{"jobs":[
		{"name":"j1","fullName":"j1","_class":"hudson.model.FreeStyleProject","url":"http://j/job/j1/","color":"blue","buildable":true},
		{"name":"j2","fullName":"j2","_class":"hudson.model.FreeStyleProject","url":"http://j/job/j2/","color":"blue","buildable":true}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	st := regState{} // empty subjectKey

	page0, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page0.NextPageToken == "" {
		t.Fatal("expected next_page_token")
	}
	page1, err := listJobsWithPolicyFilter(ctx, client, st, jenkins.ListJobsToolArgs{
		PageToken: page0.NextPageToken,
	})
	if err != nil {
		t.Fatalf("unbound continue: %v", err)
	}
	if len(page1.Jobs) < 1 {
		t.Fatalf("page1 empty: %#v", page1)
	}
}

// get_jobs subject isolation unit path (no full MCP round-trip).
func TestGetJobs_SubjectKey_AliceTokenRejectedForBob(t *testing.T) {
	body := `{"jobs":[
		{"name":"j1","url":"http://j/job/j1/","color":"blue"},
		{"name":"j2","url":"http://j/job/j2/","color":"blue"},
		{"name":"j3","url":"http://j/job/j3/","color":"blue"}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	alice := regState{subjectKey: "tenant|alice|p"}
	bob := regState{subjectKey: "tenant|bob|p"}

	page0, err := getJobsWithSubject(ctx, client, alice, jenkins.GetJobsToolArgs{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if page0.NextPageToken == "" {
		t.Fatal("need next_page_token")
	}
	_, err = getJobsWithSubject(ctx, client, bob, jenkins.GetJobsToolArgs{PageToken: page0.NextPageToken})
	if err == nil {
		t.Fatal("expected Alice get_jobs token rejected for Bob")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
}
