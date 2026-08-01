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

// Wave 42: when collect hits the page safety cap with more views remaining,
// Truncated is forced true and a non-secret incomplete Message is set.
// collect uses the process override (SetViewsCollectMaxPages / package var).
func TestListViews_PolicyFilter_SafetyIncompleteForcesTruncated(t *testing.T) {
	// MaxViewsPageSize=200 → 201 views need 2 collect pages; cap at 1 page.
	const nViews = 201
	var b strings.Builder
	b.WriteString(`{"views":[`)
	for i := 0; i < nViews; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("view-%04d", i)
		fmt.Fprintf(&b, `{"name":%q,"description":"d","_class":"hudson.model.ListView"}`, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" {
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

	old := ViewsCollectMaxPages()
	SetViewsCollectMaxPages(1)
	defer SetViewsCollectMaxPages(old)

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyViewNames: []string{"view-0000"},
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := listViewsWithPolicyFilter(ctx, client, st, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	if !out.Truncated {
		t.Fatalf("incomplete collect must force truncated=true; summary=%+v views=%d next=%d",
			out.Summary, len(out.Views), out.NextOffset)
	}
	if !strings.Contains(out.Message, "collection capped") || !strings.Contains(out.Message, "incomplete") {
		t.Fatalf("incomplete Message want collection capped/incomplete; got %q", out.Message)
	}
	if strings.Contains(out.Message, "view-0000") || strings.Contains(out.Message, "token") {
		t.Fatalf("Message must not leak policy/secret material: %q", out.Message)
	}
	if !out.PolicyFiltered || out.PolicyOmittedCount < 1 {
		t.Fatalf("policy: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	for _, v := range out.Views {
		if v.Name == "view-0000" {
			t.Fatalf("denied view leaked: %q", v.Name)
		}
	}
}

// Wave 42: resolved higher collect cap allows multi-page complete collection.
func TestListViews_PolicyFilter_CollectUsesResolvedCap(t *testing.T) {
	const nViews = 201
	var b strings.Builder
	b.WriteString(`{"views":[`)
	for i := 0; i < nViews; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("view-%04d", i)
		fmt.Fprintf(&b, `{"name":%q,"description":"d","_class":"hudson.model.ListView"}`, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/json" {
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

	n, err := ResolveViewsCollectMaxPages("", "2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("resolve: got %d want 2", n)
	}
	old := ViewsCollectMaxPages()
	SetViewsCollectMaxPages(n)
	defer SetViewsCollectMaxPages(old)

	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyViewNames: []string{"view-0000"},
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := listViewsWithPolicyFilter(ctx, client, st, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	if strings.Contains(out.Message, "collection capped") {
		t.Fatalf("complete collect must not set incomplete Message: %q hits=%d", out.Message, hits)
	}
	if out.Summary.TotalViews != nViews-1 {
		t.Fatalf("summary.totalViews=%d want %d (deny one)", out.Summary.TotalViews, nViews-1)
	}
	if hits < 2 {
		t.Fatalf("expected multi-page collect hits≥2 got %d", hits)
	}
}
