package jenkins

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestGetNodes_SummaryAndPagination(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// Two online nodes, one offline; include labels; no env props.
	f.runningJSON = `{
		"computer": [
			{
				"displayName": "master",
				"description": "controller",
				"offline": false,
				"temporarilyOffline": false,
				"numExecutors": 2,
				"idle": false,
				"offlineCauseReason": "",
				"assignedLabels": [{"name": "master"}, {"name": "linux"}],
				"executors": [{"idle": false}, {"idle": true}]
			},
			{
				"displayName": "agent-1",
				"description": "",
				"offline": true,
				"temporarilyOffline": true,
				"numExecutors": 1,
				"idle": true,
				"offlineCauseReason": "Connection was broken",
				"assignedLabels": [{"name": "agent-1"}, {"name": "gpu"}],
				"executors": [{"idle": true}]
			},
			{
				"displayName": "agent-2",
				"offline": false,
				"numExecutors": 2,
				"idle": true,
				"assignedLabels": [{"name": "agent-2"}],
				"executors": [{"idle": true}, {"idle": true}]
			}
		]
	}`

	res, err := f.opts().GetNodes(context.Background(), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unauthorized {
		t.Fatal("unexpected unauthorized")
	}
	if len(res.Nodes) != 2 {
		t.Fatalf("page size: %d", len(res.Nodes))
	}
	if !res.Truncated || res.NextOffset != 2 {
		t.Fatalf("truncation: %+v", res)
	}
	if res.Summary.TotalNodes != 3 || res.Summary.OfflineNodes != 1 || res.Summary.OnlineNodes != 2 {
		t.Fatalf("summary: %+v", res.Summary)
	}
	if res.Summary.BusyExecutors != 1 {
		t.Fatalf("busy: %+v", res.Summary)
	}
	for _, n := range res.Nodes {
		if strings.Contains(strings.ToLower(n.Description), "password") {
			t.Fatal("sensitive text")
		}
	}

	res2, err := f.opts().GetNodes(context.Background(), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Nodes) != 1 || res2.Truncated {
		t.Fatalf("page2: %+v", res2)
	}
}

func TestGetNodes_Unauthorized(t *testing.T) {
	srv := newStatusServer(t, "/computer/api/json", http.StatusForbidden, `{"message":"forbidden"}`)
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	res, err := c.GetNodes(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unauthorized {
		t.Fatalf("want unauthorized: %+v", res)
	}
	if len(res.Nodes) != 0 {
		t.Fatal("nodes must be empty when unauthorized")
	}
}

func TestGetNode_Success(t *testing.T) {
	const body = `{
		"displayName": "agent-1",
		"description": "gpu worker",
		"offline": false,
		"temporarilyOffline": false,
		"numExecutors": 2,
		"idle": false,
		"offlineCauseReason": "",
		"assignedLabels": [{"name": "agent-1"}, {"name": "gpu"}],
		"executors": [{"idle": false}, {"idle": true}]
	}`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if !strings.HasPrefix(r.URL.Path, "/computer/") || !strings.HasSuffix(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		// Ensure tree excludes env/system props.
		if strings.Contains(r.URL.RawQuery, "environment") || strings.Contains(r.URL.RawQuery, "systemProperties") {
			t.Errorf("forbidden tree fields in query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	res, err := c.GetNode(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Node.Name != "agent-1" || res.Node.Offline || res.Node.NumExecutors != 2 {
		t.Fatalf("node: %+v", res.Node)
	}
	if res.Node.BusyExecutors != 1 || res.Node.IdleExecutors != 1 {
		t.Fatalf("executors: %+v", res.Node)
	}
	if len(res.Node.Labels) != 2 {
		t.Fatalf("labels: %v", res.Node.Labels)
	}
	if gotPath != "/computer/agent-1/api/json" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestGetNode_BuiltInMasterEncoding(t *testing.T) {
	// Regression: Jenkins built-in uses path segment "(master)" → %28master%29.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"displayName": "Built-In Node",
			"offline": false,
			"numExecutors": 2,
			"idle": true,
			"assignedLabels": [{"name": "master"}],
			"executors": [{"idle": true}, {"idle": true}]
		}`))
	}))
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	res, err := c.GetNode(context.Background(), "(master)")
	if err != nil {
		t.Fatal(err)
	}
	if res.Node.Name != "Built-In Node" {
		t.Fatalf("name=%q", res.Node.Name)
	}
	// PathEscape of "(master)" is %28master%29
	if !strings.Contains(gotPath, "%28master%29") {
		t.Fatalf("expected encoded (master) path, got %q", gotPath)
	}
}

func TestGetNode_EmptyName(t *testing.T) {
	c := &Client{URL: "http://127.0.0.1:1", User: "u", Token: "t"}
	_, err := c.GetNode(context.Background(), "  ")
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("want invalid_argument, got %v", err)
	}
}

func TestGetNode_RejectsPathTraversal(t *testing.T) {
	c := &Client{URL: "http://127.0.0.1:1", User: "u", Token: "t"}
	for _, name := range []string{"../etc", "a/b", "/master"} {
		_, err := c.GetNode(context.Background(), name)
		if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
			t.Fatalf("%q: want invalid_argument, got %v", name, err)
		}
	}
}

func TestGetNode_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"No such agent"}`))
	}))
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	_, err := c.GetNode(context.Background(), "missing-agent")
	if !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestGetNode_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	_, err := c.GetNode(context.Background(), "secret-node")
	if !apperr.IsCode(err, apperr.CodeAuthorization) {
		t.Fatalf("want authorization, got %v", err)
	}
}

func TestGetQueuePressure(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	old := time.Now().Add(-90 * time.Second).UnixMilli()
	newer := time.Now().Add(-10 * time.Second).UnixMilli()
	f.queueAPIJSON = fmt.Sprintf(`{
		"items": [
			{"id": 1, "task": {"name": "slow-job"}, "why": "Waiting for next available executor", "inQueueSince": %d, "stuck": true, "buildable": true},
			{"id": 2, "task": {"name": "other"}, "why": "Build is blocked", "inQueueSince": %d, "stuck": false, "buildable": false}
		]
	}`, old, newer)
	res, err := f.opts().GetQueuePressure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Depth != 2 || res.StuckCount != 1 || res.BuildableCount != 1 {
		t.Fatalf("%+v", res)
	}
	if res.OldestQueueID != 1 || res.OldestJobName != "slow-job" {
		t.Fatalf("oldest: %+v", res)
	}
	if res.OldestWaitSeconds < 80 {
		t.Fatalf("oldest wait too small: %d", res.OldestWaitSeconds)
	}
	if len(res.Samples) != 2 {
		t.Fatalf("samples: %d", len(res.Samples))
	}
}

func TestGetQueuePressure_Empty(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	res, err := f.opts().GetQueuePressure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Depth != 0 || res.Unauthorized {
		t.Fatalf("%+v", res)
	}
}

func TestGetQueuePressure_Unauthorized(t *testing.T) {
	srv := newStatusServer(t, "/queue/api/json", http.StatusForbidden, `{}`)
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	res, err := c.GetQueuePressure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unauthorized {
		t.Fatalf("%+v", res)
	}
}

// newStatusServer returns a test server that responds with status/body for paths
// with the given prefix (query string ignored).
func newStatusServer(t *testing.T, pathPrefix string, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, pathPrefix) || r.URL.Path == pathPrefix {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		http.NotFound(w, r)
	}))
}

func TestGetQueuePressure_ScrubsWhySecrets(t *testing.T) {
	// Regression: queue sample Why must scrub bearer/password-like text before MCP.
	f := newJenkinsFixture()
	defer f.close()
	f.queueAPIJSON = `{"items":[{"id":1,"stuck":false,"blocked":false,"buildable":true,"inQueueSince":1700000000000,"why":"Waiting for executor password=supersecret123 Bearer tokvalue","task":{"name":"demo","url":"http://j/job/demo/"}}]}`
	qp, err := f.opts().GetQueuePressure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(qp.Samples) == 0 {
		t.Fatal("expected sample")
	}
	why := qp.Samples[0].Why
	if strings.Contains(why, "supersecret123") || strings.Contains(why, "tokvalue") {
		t.Fatalf("secret leaked in Why: %q", why)
	}
}
