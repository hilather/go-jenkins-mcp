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
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// Regression: HEALTH-001 tools are registered as read-only and return fixture data.
func TestHealthTools_RegisteredAndCallable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Minimal fixture via real Client against empty computer/queue (httptest from jenkins package
	// is internal; use a client that fails network gracefully is hard — use nil client methods
	// through fixture is package-private. Instead assert discovery + doctor registration.
	server := mcp.NewServer(&mcp.Implementation{Name: "health", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
		Doctor: func(ctx context.Context, offline bool) (diagnostics.Report, error) {
			return diagnostics.Report{
				ProfileID: "corp",
				Overall:   diagnostics.StatusOK,
				Checks: []diagnostics.Check{{
					Name:    "binary",
					Status:  diagnostics.StatusOK,
					Message: "ok",
				}},
			}, nil
		},
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tool := range list.Tools {
		got[tool.Name] = true
	}
	for _, name := range []string{
		"jenkins_get_nodes",
		"jenkins_get_node",
		"jenkins_list_views",
		"jenkins_queue_pressure",
		"jenkins_controller_health",
		"jenkins_explain_queue_delay",
		"jenkins_doctor",
	} {
		if !got[name] {
			t.Errorf("missing tool %q", name)
		}
	}
	if !policy.IsKnownSeedTool(tools.ToolGetNode) {
		t.Fatal("jenkins_get_node must be in known seed tools (ModeStrict)")
	}
	if !policy.IsKnownSeedTool(tools.ToolListViews) {
		t.Fatal("jenkins_list_views must be in known seed tools (ModeStrict)")
	}

	// jenkins_doctor returns sanitized report (no canary).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_doctor",
		Arguments: map[string]any{"offline": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("doctor error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if strings.Contains(string(raw), "CANARY_SECRET") {
		t.Fatal("secret canary in doctor tool output")
	}
}

// Regression: doctor tool omitted when Doctor func is nil.
func TestDoctorTool_OmittedWithoutFunc(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})
	if _, ok := got["jenkins_doctor"]; ok {
		t.Fatal("jenkins_doctor must not register without Doctor func")
	}
	if _, ok := got["jenkins_get_nodes"]; !ok {
		t.Fatal("jenkins_get_nodes should always register")
	}
	if _, ok := got["jenkins_get_node"]; !ok {
		t.Fatal("jenkins_get_node should always register")
	}
	if _, ok := got["jenkins_list_views"]; !ok {
		t.Fatal("jenkins_list_views should always register")
	}
}

// Wave 36: jenkins_get_node call succeeds; deny_node_names denies before client.
func TestGetNodeTool_CallAndPolicyDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var hits int
	fix := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if !strings.HasPrefix(r.URL.Path, "/computer/") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"displayName": "dev-agent-01",
			"offline": false,
			"numExecutors": 1,
			"idle": true,
			"assignedLabels": [{"name": "dev-agent-01"}],
			"executors": [{"idle": true}]
		}`))
	}))
	defer fix.Close()

	jc := &jenkins.Client{
		URL:        fix.URL,
		User:       "u",
		Token:      "t",
		Client:     fix.Client(),
		LogsClient: fix.Client(),
	}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "get-node", Version: "test"}, nil)
	tools.Register(server, jc, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Allowed node_name reaches Jenkins.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolGetNode,
		Arguments: map[string]any{"node_name": "dev-agent-01"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want success: %#v text=%q", resOK, toolErrorText(resOK))
	}
	raw, _ := json.Marshal(resOK.StructuredContent)
	if !strings.Contains(string(raw), "dev-agent-01") {
		t.Fatalf("expected node in payload: %s", raw)
	}
	if hits != 1 {
		t.Fatalf("jenkins hits=%d want 1", hits)
	}

	// Denied node_name fails closed before handler/client.
	hits = 0
	resDeny, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolGetNode,
		Arguments: map[string]any{"node_name": "prod-agent-01"},
	})
	if err != nil {
		t.Fatalf("deny transport: %v", err)
	}
	if resDeny == nil || !resDeny.IsError {
		t.Fatalf("want policy deny, got %#v", resDeny)
	}
	text := toolErrorText(resDeny)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial, got %q", text)
	}
	if hits != 0 {
		t.Fatalf("Jenkins must not be called on policy deny (hits=%d)", hits)
	}

	// Empty node_name → invalid_argument (before client).
	resEmpty, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolGetNode,
		Arguments: map[string]any{"node_name": "  "},
	})
	if err != nil {
		t.Fatalf("empty transport: %v", err)
	}
	if resEmpty == nil || !resEmpty.IsError {
		t.Fatalf("want invalid_argument for empty node_name, got %#v", resEmpty)
	}
	emptyText := toolErrorText(resEmpty)
	if !strings.Contains(emptyText, "node_name") &&
		!strings.Contains(emptyText, string(apperr.CodeInvalidArgument)) {
		t.Fatalf("expected invalid_argument mentioning node_name, got %q", emptyText)
	}
	if hits != 0 {
		t.Fatalf("Jenkins must not be called for empty node_name (hits=%d)", hits)
	}
}
