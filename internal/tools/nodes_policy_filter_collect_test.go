package tools

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// Wave 42: when collect hits the page safety cap with more nodes remaining,
// Truncated is forced true and a non-secret incomplete Message is set.
// collect uses the process override (SetNodesCollectMaxPages / package var).
func TestGetNodes_PolicyFilter_SafetyIncompleteForcesTruncated(t *testing.T) {
	// MaxNodesPageSize=200 → 201 nodes need 2 collect pages; cap at 1 page.
	const nNodes = 201
	var b strings.Builder
	b.WriteString(`{"computer":[`)
	for i := 0; i < nNodes; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("node-%04d", i)
		fmt.Fprintf(&b, `{"displayName":%q,"offline":false,"numExecutors":1,"idle":true,"assignedLabels":[{"name":%q}],"executors":[{"idle":true}]}`,
			name, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/computer/api/json") {
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

	old := NodesCollectMaxPages()
	SetNodesCollectMaxPages(1)
	defer SetNodesCollectMaxPages(old)

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"node-0000"}, // omit one so collect path is active
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := getNodesWithPolicyFilter(ctx, client, st, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	if !out.Truncated {
		t.Fatalf("incomplete collect must force truncated=true; summary=%+v nodes=%d next=%d",
			out.Summary, len(out.Nodes), out.NextOffset)
	}
	if !strings.Contains(out.Message, "collection capped") || !strings.Contains(out.Message, "incomplete") {
		t.Fatalf("incomplete Message want collection capped/incomplete; got %q", out.Message)
	}
	if strings.Contains(out.Message, "node-0000") || strings.Contains(out.Message, "token") {
		t.Fatalf("Message must not leak policy/secret material: %q", out.Message)
	}
	if !out.PolicyFiltered || out.PolicyOmittedCount < 1 {
		t.Fatalf("policy: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
	for _, n := range out.Nodes {
		if n.Name == "node-0000" {
			t.Fatalf("denied node leaked: %q", n.Name)
		}
	}
}

// Wave 42: resolved higher collect cap allows multi-page complete collection.
func TestGetNodes_PolicyFilter_CollectUsesResolvedCap(t *testing.T) {
	const nNodes = 201
	var b strings.Builder
	b.WriteString(`{"computer":[`)
	for i := 0; i < nNodes; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		name := fmt.Sprintf("node-%04d", i)
		fmt.Fprintf(&b, `{"displayName":%q,"offline":false,"numExecutors":1,"idle":true,"assignedLabels":[{"name":%q}],"executors":[{"idle":true}]}`,
			name, name)
	}
	b.WriteString(`]}`)
	body := b.String()

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/computer/api/json") {
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

	n, err := ResolveNodesCollectMaxPages("", "2")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("resolve: got %d want 2", n)
	}
	old := NodesCollectMaxPages()
	SetNodesCollectMaxPages(n)
	defer SetNodesCollectMaxPages(old)

	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"node-0000"},
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out, err := getNodesWithPolicyFilter(ctx, client, st, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("nil response")
	}
	// With cap=2, 201 nodes fit → complete (not truncated by collect safety).
	// User limit=10 of kept → Truncated for page, but Message must not be incomplete.
	if strings.Contains(out.Message, "collection capped") {
		t.Fatalf("complete collect must not set incomplete Message: %q hits=%d", out.Message, hits)
	}
	// Summary over kept (nNodes-1).
	if out.Summary.TotalNodes != nNodes-1 {
		t.Fatalf("summary.totalNodes=%d want %d (deny one)", out.Summary.TotalNodes, nNodes-1)
	}
	if hits < 2 {
		t.Fatalf("expected multi-page collect hits≥2 got %d", hits)
	}
}
