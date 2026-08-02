package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
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

// Multi-user residual foundation: tool_deny audit uses effectiveSubject +
// SubjectKeyHash (opaque), never raw subject keys or vault canaries.
func TestToolDenyAudit_MultiUserCorrelation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const (
		canary = "CANARY_vault_token_must_never_appear_in_audit_xyz"
		sk     = "tid-1|entra-alice|corp"
	)
	wantHash := audit.HashOpaque(sk)
	if wantHash == "" || strings.Contains(wantHash, "|") {
		t.Fatalf("HashOpaque: %q", wantHash)
	}

	mem := &audit.Memory{}
	server := mcp.NewServer(&mcp.Implementation{Name: "aud-mu", Version: "test"}, nil)
	doc := policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_jobs": {}},
	}
	ev := policy.NewDenyOnlyEvaluator(doc)
	alice := policy.NewSubject("corp", "alice-j", true).
		WithExternal("entra-alice").
		WithGateway("tid-1", "", nil)
	opts := &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Policy:      ev,
		Subject:     policy.NewSubject("corp", "process-user", true), // process fallback
		Audit:       mem,
		ProfileID:   "corp",
		PrincipalID: "process-user",
		SubjectKey:  "tid-default|process-ext|corp",
		SubjectFromContext: func(context.Context) (policy.Subject, bool) {
			return alice, true
		},
		SubjectKeyFromContext: func(context.Context) string {
			// Production never puts tokens in SubjectKey; canary proves audit hash path.
			_ = canary
			return sk
		},
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

	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("audit events=%d", len(evs))
	}
	e := evs[0]
	if e.Type != audit.TypeToolDeny {
		t.Fatalf("type=%s", e.Type)
	}
	// Effective multi-user subject, not process defaults.
	if e.ProfileID != "corp" || e.PrincipalID != "alice-j" {
		t.Fatalf("profile/principal: %+v", e)
	}
	if e.ExternalSubject != "entra-alice" {
		t.Fatalf("ExternalSubject=%q", e.ExternalSubject)
	}
	if e.SubjectKeyHash != wantHash {
		t.Fatalf("SubjectKeyHash=%q want %q", e.SubjectKeyHash, wantHash)
	}
	// Stability: same key → same hash.
	if audit.HashOpaque(sk) != e.SubjectKeyHash {
		t.Fatal("SubjectKeyHash not stable")
	}
	// Canary / raw key never in event fields.
	blob := e.Type + e.ProfileID + e.PrincipalID + e.ExternalSubject + e.SubjectKeyHash +
		e.Tool + e.Action + e.Decision + e.ReasonCode + e.TargetHash + e.RequestID
	if strings.Contains(blob, canary) {
		t.Fatalf("canary in audit: %+v", e)
	}
	if strings.Contains(blob, sk) || strings.Contains(e.SubjectKeyHash, "|") {
		t.Fatalf("raw subject key in audit: %+v", e)
	}
}

// Regression: handler tool_error path emits audit + mcp_tool_error without secrets.
func TestToolErrorAuditsAndMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const canary = "CANARY_should_not_appear_in_tool_error_audit"
	mem := &audit.Memory{}
	metrics := telemetry.NewMetrics()
	server := mcp.NewServer(&mcp.Implementation{Name: "aud-err", Version: "test"}, nil)
	opts := &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Audit:       mem,
		Metrics:     metrics,
		ProfileID:   "corp",
		PrincipalID: "alice",
	}
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_job",
		Description: "err",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, jenkins.Job, error) {
		// Deliberate secret-shaped message — audit must use Code only.
		return nil, jenkins.Job{}, apperr.New(apperr.CodeUpstreamProtocol,
			"upstream failed Authorization: Bearer "+canary)
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

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_job",
		Arguments: map[string]any{"name": "demo"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error, got %#v", res)
	}

	if metrics.GetCounter(telemetry.MetricToolCalls) != 1 {
		t.Fatalf("tool_calls=%d", metrics.GetCounter(telemetry.MetricToolCalls))
	}
	if metrics.GetCounter(telemetry.MetricMCPToolError) != 1 {
		t.Fatalf("mcp_tool_error=%d", metrics.GetCounter(telemetry.MetricMCPToolError))
	}
	if metrics.GetCounter(telemetry.MetricMCPToolOK) != 0 || metrics.GetCounter(telemetry.MetricMCPToolDeny) != 0 {
		t.Fatalf("ok/deny should be 0 on error path")
	}
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("audit events=%d want 1: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Type != audit.TypeToolError || e.Decision != audit.DecisionError {
		t.Fatalf("event=%+v", e)
	}
	if e.Tool != "jenkins_get_job" || e.ProfileID != "corp" || e.PrincipalID != "alice" {
		t.Fatalf("attribution=%+v", e)
	}
	if e.ReasonCode != string(apperr.CodeUpstreamProtocol) {
		t.Fatalf("ReasonCode=%q want %q", e.ReasonCode, apperr.CodeUpstreamProtocol)
	}
	// Canary: never put ModelMessage / tokens into audit fields.
	blob := e.Type + e.Tool + e.ReasonCode + e.ProfileID + e.PrincipalID + e.Action + e.Decision +
		e.ExternalSubject + e.SubjectKeyHash + e.TargetHash + e.RequestID
	if strings.Contains(blob, canary) || strings.Contains(strings.ToLower(blob), "bearer") {
		t.Fatalf("canary/secret in audit: %+v", e)
	}
}

// Multi-user: tool_error audit uses effectiveSubject + SubjectKeyHash (opaque),
// never process principal or raw subject keys / vault canaries.
func TestToolErrorAudit_MultiUserCorrelation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const (
		canary = "CANARY_vault_token_must_never_appear_in_tool_error_audit_xyz"
		sk     = "tid-1|entra-alice|corp"
	)
	wantHash := audit.HashOpaque(sk)
	if wantHash == "" || strings.Contains(wantHash, "|") {
		t.Fatalf("HashOpaque: %q", wantHash)
	}

	mem := &audit.Memory{}
	metrics := telemetry.NewMetrics()
	server := mcp.NewServer(&mcp.Implementation{Name: "aud-err-mu", Version: "test"}, nil)
	alice := policy.NewSubject("corp", "alice-j", true).
		WithExternal("entra-alice").
		WithGateway("tid-1", "", nil)
	opts := &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Subject:     policy.NewSubject("corp", "process-user", true), // process fallback
		Audit:       mem,
		Metrics:     metrics,
		ProfileID:   "corp",
		PrincipalID: "process-user",
		SubjectKey:  "tid-default|process-ext|corp",
		SubjectFromContext: func(context.Context) (policy.Subject, bool) {
			return alice, true
		},
		SubjectKeyFromContext: func(context.Context) string {
			_ = canary
			return sk
		},
	}
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_job",
		Description: "err",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, jenkins.Job, error) {
		return nil, jenkins.Job{}, apperr.New(apperr.CodeQuota, "quota exceeded secret="+canary)
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

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_get_job",
		Arguments: map[string]any{"name": "demo"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error, got %#v", res)
	}

	if metrics.GetCounter(telemetry.MetricMCPToolError) != 1 {
		t.Fatalf("mcp_tool_error=%d", metrics.GetCounter(telemetry.MetricMCPToolError))
	}
	evs := mem.Events()
	if len(evs) != 1 {
		t.Fatalf("audit events=%d want 1: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Type != audit.TypeToolError || e.Decision != audit.DecisionError {
		t.Fatalf("event=%+v", e)
	}
	// Effective multi-user Alice subject, not process defaults.
	if e.ProfileID != "corp" || e.PrincipalID != "alice-j" {
		t.Fatalf("profile/principal: %+v", e)
	}
	if e.ExternalSubject != "entra-alice" {
		t.Fatalf("ExternalSubject=%q", e.ExternalSubject)
	}
	if e.SubjectKeyHash != wantHash {
		t.Fatalf("SubjectKeyHash=%q want %q", e.SubjectKeyHash, wantHash)
	}
	if e.ReasonCode != string(apperr.CodeQuota) {
		t.Fatalf("ReasonCode=%q want %q", e.ReasonCode, apperr.CodeQuota)
	}
	if audit.HashOpaque(sk) != e.SubjectKeyHash {
		t.Fatal("SubjectKeyHash not stable")
	}
	blob := e.Type + e.ProfileID + e.PrincipalID + e.ExternalSubject + e.SubjectKeyHash +
		e.Tool + e.Action + e.Decision + e.ReasonCode + e.TargetHash + e.RequestID
	if strings.Contains(blob, canary) {
		t.Fatalf("canary in audit: %+v", e)
	}
	if strings.Contains(blob, sk) || strings.Contains(e.SubjectKeyHash, "|") {
		t.Fatalf("raw subject key in audit: %+v", e)
	}
	if strings.Contains(blob, "process-user") {
		t.Fatalf("process principal elevated into multi-user tool_error audit: %+v", e)
	}
}

// tool_success is filtered off by DefaultTypeFilter (unless env seeds on);
// metrics still record mcp_tool_ok. Bare Memory would receive every emit.
func TestToolOKAudit_TypeFilterDefaultOffAndEnable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// DefaultTypeFilter: tool_success off when env unset/false.
	t.Setenv(tools.EnvAuditToolOK, "0")
	dir := t.TempDir()
	mem := &audit.Memory{}
	filtered := audit.NewReloadingFilterSink(dir, mem)
	metrics := telemetry.NewMetrics()
	server := mcp.NewServer(&mcp.Implementation{Name: "aud-ok-off", Version: "test"}, nil)
	opts := &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Audit:       filtered,
		Metrics:     metrics,
		ProfileID:   "corp",
		PrincipalID: "alice",
	}
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "ok",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobsToolArgs) (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
		return &mcp.CallToolResult{}, jenkins.GetJobsToolResponse{}, nil
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
		t.Fatalf("transport: %v", err)
	}
	if metrics.GetCounter(telemetry.MetricMCPToolOK) != 1 {
		t.Fatalf("mcp_tool_ok=%d want 1", metrics.GetCounter(telemetry.MetricMCPToolOK))
	}
	if len(mem.Events()) != 0 {
		t.Fatalf("tool_success must be filtered off by default: %+v", mem.Events())
	}

	// Admin enable: persist type_filter.json so ReloadingFilterSink allows tool_success.
	f := audit.DefaultTypeFilter()
	f.Enabled[audit.TypeToolSuccess] = true
	if err := audit.SaveTypeFilter(dir, f); err != nil {
		t.Fatal(err)
	}
	mem2 := &audit.Memory{}
	filtered2 := audit.NewReloadingFilterSink(dir, mem2)
	server2 := mcp.NewServer(&mcp.Implementation{Name: "aud-ok-on", Version: "test"}, nil)
	alice := policy.NewSubject("corp", "alice-j", true).WithExternal("entra-alice")
	opts2 := &tools.RegisterOptions{
		Gate:        policy.NewDefaultReadOnlyGate(),
		Subject:     policy.NewSubject("corp", "process-user", true),
		Audit:       filtered2,
		ProfileID:   "corp",
		PrincipalID: "process-user",
		SubjectFromContext: func(context.Context) (policy.Subject, bool) {
			return alice, true
		},
	}
	tools.ForceRegisterReadToolForTest(server2, opts2, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "ok",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobsToolArgs) (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
		return &mcp.CallToolResult{}, jenkins.GetJobsToolResponse{}, nil
	})
	ct2, st2 := mcp.NewInMemoryTransports()
	ss2, err := server2.Connect(ctx, st2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss2.Close()
	cs2, err := client.Connect(ctx, ct2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs2.Close()
	if _, err := cs2.CallTool(ctx, &mcp.CallToolParams{Name: "jenkins_get_jobs", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("transport enable: %v", err)
	}
	evs := mem2.Events()
	if len(evs) != 1 {
		t.Fatalf("enabled tool_success events=%d: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Type != audit.TypeToolSuccess || e.Decision != audit.DecisionSuccess {
		t.Fatalf("event=%+v", e)
	}
	if e.PrincipalID != "alice-j" || e.ExternalSubject != "entra-alice" {
		t.Fatalf("multi-user ok audit: %+v", e)
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
