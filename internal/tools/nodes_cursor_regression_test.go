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

// Regression: when collection hit the page safety cap (incomplete) AND the
// requested page of the policy-filtered list is empty, the response forced
// truncated=true with next_offset == the just-requested offset — a
// non-advancing cursor. An auto-paginating client looped indefinitely, and
// every iteration re-collected the entire fleet. An empty filtered page must
// offer no continuation (next_offset=0) while keeping truncated=true honesty.
func TestGetNodes_PolicyFilter_IncompleteEmptyPageNoCursorLoop(t *testing.T) {
	// 201 nodes > one 200-node collect page; deny all of them.
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
		DenyNodeNames: []string{"node-*"}, // deny everything collected
	})
	st := regState{policy: ev}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Page past the (empty) filtered list: offset 5 with 0 kept rows.
	out, err := getNodesWithPolicyFilter(ctx, client, st, 5, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated {
		t.Fatal("incomplete collect must keep truncated=true")
	}
	if len(out.Nodes) != 0 {
		t.Fatalf("want empty page, got %d nodes", len(out.Nodes))
	}
	if out.NextOffset != 0 {
		t.Fatalf("empty filtered page must not offer a continuation cursor (got next=%d); a non-advancing cursor loops the client", out.NextOffset)
	}
	if !strings.Contains(out.Message, "collection capped") {
		t.Fatalf("incomplete message missing: %q", out.Message)
	}
}
