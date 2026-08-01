package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// Regression: policy/RO denials emit audit + increment counters without secrets.
func TestToolDenyAuditsAndMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mem := &audit.Memory{}
	metrics := telemetry.NewMetrics()

	// Deny a read tool via MCP RBAC and force-register it for dispatch deny.
	server := mcp.NewServer(&mcp.Implementation{Name: "aud-obs", Version: "test"}, nil)
	doc := policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_jobs": {}},
	}
	ev := policy.NewDenyOnlyEvaluator(doc)
	opts := &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Policy:      ev,
		Subject:     policy.NewSubject("corp", "alice", true),
		Audit:       mem,
		Metrics:     metrics,
		ProfileID:   "corp",
		PrincipalID: "alice",
	}
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "test",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobsToolArgs) (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
		t.Fatal("handler must not run on policy deny")
		return nil, jenkins.GetJobsToolResponse{}, nil
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

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_get_jobs", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error, got %#v", res)
	}

	if metrics.GetCounter(telemetry.MetricToolCalls) != 1 {
		t.Fatalf("tool_calls=%d", metrics.GetCounter(telemetry.MetricToolCalls))
	}
	if metrics.GetCounter(telemetry.MetricMCPToolDeny) != 1 {
		t.Fatalf("mcp_tool_deny=%d", metrics.GetCounter(telemetry.MetricMCPToolDeny))
	}
	if metrics.GetCounter(telemetry.MetricPolicyDenials) != 1 {
		t.Fatalf("policy_denials alias=%d", metrics.GetCounter(telemetry.MetricPolicyDenials))
	}
	if metrics.GetCounter(telemetry.MetricMCPToolOK) != 0 || metrics.GetCounter(telemetry.MetricMCPToolError) != 0 {
		t.Fatalf("ok/error should be 0 on deny path")
	}
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("audit events=%d", len(evs))
	}
	e := evs[0]
	if e.Type != audit.TypeToolDeny || e.Decision != audit.DecisionDeny {
		t.Fatalf("event=%+v", e)
	}
	if e.Tool != "jenkins_get_jobs" || e.ProfileID != "corp" || e.PrincipalID != "alice" {
		t.Fatalf("attribution=%+v", e)
	}
	if e.ReasonCode == "" {
		t.Fatal("expected reason code")
	}
	// Canary: no token-like material in serialized event fields.
	const canary = "CANARY_should_not_appear"
	for _, s := range []string{e.Type, e.Tool, e.ReasonCode, e.ProfileID, e.PrincipalID, e.Action, e.Decision} {
		if strings.Contains(s, canary) {
			t.Fatalf("canary in %q", s)
		}
	}
}

// Registration under RO emits tool_deny for omitted mutation tools (AUD-001).
func TestRegisterROOmitsMutationsWithAudit(t *testing.T) {
	t.Parallel()
	mem := &audit.Memory{}
	metrics := telemetry.NewMetrics()
	server := mcp.NewServer(&mcp.Implementation{Name: "aud-ro", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Audit:       mem,
		Metrics:     metrics,
		ProfileID:   "corp",
		PrincipalID: "alice",
	})
	// start_job + stop_build should each produce a registration deny event.
	var denied int
	for _, e := range mem.Events() {
		if e.Type == audit.TypeToolDeny && e.ReasonCode == "read_only" {
			denied++
		}
	}
	want := len(policy.MutationToolNames())
	if denied != want {
		t.Fatalf("read_only deny events=%d want %d (events=%+v)", denied, want, mem.Events())
	}
	if metrics.GetCounter(telemetry.MetricPolicyDenials) != int64(want) {
		t.Fatalf("policy_denials=%d want %d", metrics.GetCounter(telemetry.MetricPolicyDenials), want)
	}
}
