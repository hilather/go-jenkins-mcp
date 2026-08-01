package jenkins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListViews_SummaryAndPagination(t *testing.T) {
	const body = `{
		"views": [
			{"name": "all", "description": "All jobs", "_class": "hudson.model.AllView"},
			{"name": "ci", "description": "CI pipelines", "_class": "hudson.model.ListView"},
			{"name": "secret-view", "description": "restricted", "_class": "hudson.model.ListView"}
		]
	}`
	var gotTree string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" {
			http.NotFound(w, r)
			return
		}
		gotTree = r.URL.Query().Get("tree")
		// Ensure tree does not request jobs graphs or secrets.
		if strings.Contains(gotTree, "jobs") {
			t.Errorf("tree must not include jobs: %s", gotTree)
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

	res, err := c.ListViews(context.Background(), 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unauthorized {
		t.Fatal("unexpected unauthorized")
	}
	if len(res.Views) != 2 {
		t.Fatalf("page size: %d", len(res.Views))
	}
	if !res.Truncated || res.NextOffset != 2 {
		t.Fatalf("truncation: %+v", res)
	}
	if res.Summary.TotalViews != 3 {
		t.Fatalf("summary: %+v", res.Summary)
	}
	if res.Views[0].Name != "all" || res.Views[0].Class == "" {
		t.Fatalf("first view: %+v", res.Views[0])
	}
	if !strings.Contains(gotTree, "views[name,description") {
		t.Fatalf("unexpected tree: %s", gotTree)
	}

	res2, err := c.ListViews(context.Background(), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Views) != 1 || res2.Truncated {
		t.Fatalf("page2: %+v", res2)
	}
	if res2.Views[0].Name != "secret-view" {
		t.Fatalf("page2 name: %q", res2.Views[0].Name)
	}
}

func TestListViews_PaginationClamps(t *testing.T) {
	const body = `{"views":[{"name":"a"},{"name":"b"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// limit <= 0 → default 50
	res, err := c.ListViews(context.Background(), -5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Offset != 0 || res.Limit != DefaultViewsPageSize {
		t.Fatalf("clamp defaults: offset=%d limit=%d", res.Offset, res.Limit)
	}
	if len(res.Views) != 2 {
		t.Fatalf("want both views with large default limit: %d", len(res.Views))
	}

	// limit > max → MaxViewsPageSize
	res2, err := c.ListViews(context.Background(), 0, 9999)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Limit != MaxViewsPageSize {
		t.Fatalf("limit clamp: %d", res2.Limit)
	}
}

func TestListViews_Unauthorized(t *testing.T) {
	srv := newStatusServer(t, "/api/json", http.StatusForbidden, `{"message":"forbidden"}`)
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	res, err := c.ListViews(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Unauthorized {
		t.Fatalf("want unauthorized: %+v", res)
	}
	if len(res.Views) != 0 {
		t.Fatal("views must be empty when unauthorized")
	}
	if res.PolicyFiltered || res.PolicyOmittedCount != 0 {
		t.Fatal("no policy metadata on unauthorized")
	}
}

func TestListViews_SanitizesDescription(t *testing.T) {
	// Control chars stripped (sanitizeNodeText drops C0 except tab).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"views":[{"name":"v1","description":"hello\u0000world"}]}`))
	}))
	defer srv.Close()
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		LogsClient: srv.Client(),
	}
	res, err := c.ListViews(context.Background(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Views) != 1 {
		t.Fatalf("views: %d", len(res.Views))
	}
	if strings.Contains(res.Views[0].Description, "\x00") {
		t.Fatalf("NUL not stripped: %q", res.Views[0].Description)
	}
	if res.Views[0].Description != "helloworld" {
		t.Fatalf("description=%q", res.Views[0].Description)
	}
}
