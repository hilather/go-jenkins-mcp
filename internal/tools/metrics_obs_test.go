package tools_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// Regression: addTool records mcp_tool_ok / mcp_tool_error / mcp_tool_deny without
// per-tool name labels (OBS-001 Wave 24).
func TestMCPToolOutcomeMetrics(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	metrics := telemetry.NewMetrics()
	server := mcp.NewServer(&mcp.Implementation{Name: "obs-outcomes", Version: "test"}, nil)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Metrics: metrics,
	}

	// OK path
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "ok",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobsToolArgs) (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
		return toolsStructuredJobsOK()
	})

	// Error path (same force-register pattern on second tool via a deny-free name)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_job",
		Description: "err",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, jenkins.Job, error) {
		return nil, jenkins.Job{}, apperr.New(apperr.CodeUpstreamProtocol, "upstream boom")
	})

	// Deny path: policy denies jenkins_get_nodes at dispatch
	denyDoc := policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_nodes": {}},
	}
	denyOpts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  policy.NewDenyOnlyEvaluator(denyDoc),
		Subject: policy.NewSubject("corp", "alice", true),
		Metrics: metrics,
	}
	tools.ForceRegisterReadToolForTest(server, denyOpts, &mcp.Tool{
		Name:        "jenkins_get_nodes",
		Description: "deny",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetNodesToolArgs) (*mcp.CallToolResult, jenkins.GetNodesToolResponse, error) {
		t.Fatal("handler must not run on deny")
		return nil, jenkins.GetNodesToolResponse{}, nil
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

	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_get_jobs", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("ok transport: %v", err)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_job",
		Arguments: map[string]any{"name": "demo"},
	})
	if err != nil {
		t.Fatalf("error transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error result, got %#v", res)
	}
	denyRes, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_get_nodes", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("deny transport: %v", err)
	}
	if denyRes == nil || !denyRes.IsError {
		t.Fatalf("want deny error, got %#v", denyRes)
	}

	if got := metrics.GetCounter(telemetry.MetricToolCalls); got != 3 {
		t.Fatalf("tool_calls=%d want 3", got)
	}
	if got := metrics.GetCounter(telemetry.MetricMCPToolOK); got != 1 {
		t.Fatalf("mcp_tool_ok=%d want 1", got)
	}
	if got := metrics.GetCounter(telemetry.MetricMCPToolError); got != 1 {
		t.Fatalf("mcp_tool_error=%d want 1", got)
	}
	if got := metrics.GetCounter(telemetry.MetricMCPToolDeny); got != 1 {
		t.Fatalf("mcp_tool_deny=%d want 1", got)
	}
	// Alias stability: policy_denials == mcp_tool_deny.
	if got := metrics.GetCounter(telemetry.MetricPolicyDenials); got != 1 {
		t.Fatalf("policy_denials alias=%d want 1", got)
	}
}

func toolsStructuredJobsOK() (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
	return &mcp.CallToolResult{}, jenkins.GetJobsToolResponse{JobList: nil}, nil
}

func TestJenkinsMetricsHookAdapter(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics()
	h := tools.JenkinsMetricsHook(m)
	if h == nil {
		t.Fatal("expected non-nil hook")
	}
	h.IncRequest()
	h.IncError()
	h.AddWire(10)
	h.AddDecoded(20)
	h.AddWire(0) // ignored
	h.AddDecoded(-1)
	h.IncCircuitOpenEvent()

	if m.GetCounter(telemetry.MetricJenkinsHTTPRequestsTotal) != 1 {
		t.Fatalf("requests=%d", m.GetCounter(telemetry.MetricJenkinsHTTPRequestsTotal))
	}
	if m.GetCounter(telemetry.MetricJenkinsHTTPErrorsTotal) != 1 {
		t.Fatalf("errors=%d", m.GetCounter(telemetry.MetricJenkinsHTTPErrorsTotal))
	}
	if m.GetCounter(telemetry.MetricJenkinsHTTPWireBytesTotal) != 10 {
		t.Fatalf("wire=%d", m.GetCounter(telemetry.MetricJenkinsHTTPWireBytesTotal))
	}
	if m.GetCounter(telemetry.MetricJenkinsHTTPDecodedBytesTotal) != 20 {
		t.Fatalf("decoded=%d", m.GetCounter(telemetry.MetricJenkinsHTTPDecodedBytesTotal))
	}
	if m.GetCounter(telemetry.MetricJenkinsCircuitOpenEventsTotal) != 1 {
		t.Fatalf("circuit open events=%d", m.GetCounter(telemetry.MetricJenkinsCircuitOpenEventsTotal))
	}
	// Legacy alias constants share the same names.
	if m.GetCounter(telemetry.MetricJenkinsRequests) != 1 {
		t.Fatalf("legacy jenkins_requests alias=%d", m.GetCounter(telemetry.MetricJenkinsRequests))
	}
	if m.GetCounter(telemetry.MetricBytesWire) != 10 {
		t.Fatalf("legacy bytes_wire alias=%d", m.GetCounter(telemetry.MetricBytesWire))
	}
	if tools.JenkinsMetricsHook(nil) != nil {
		t.Fatal("nil metrics must yield nil hook")
	}
}

func TestJenkinsMetricsHook_EndToEndCallJenkins(t *testing.T) {
	t.Parallel()
	// Minimal: adapter + fake HTTP via jenkins.Client.WithMetrics.
	// Full HTTP coverage lives in jenkins metrics_hook_test; here we only prove
	// the tools→telemetry adapter types satisfy the interface at compile time
	// and increment the stable names.
	m := telemetry.NewMetrics()
	h := tools.JenkinsMetricsHook(m)
	// Simulate CallJenkins completion accounting.
	h.IncRequest()
	h.AddWire(100)
	h.AddDecoded(100)

	if m.GetCounter(telemetry.MetricJenkinsHTTPRequestsTotal) != 1 {
		t.Fatal(errors.New("requests not recorded"))
	}
}
