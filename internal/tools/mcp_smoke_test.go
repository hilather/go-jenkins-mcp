package tools_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Declared MCP protocol versions supported by the pinned SDK (FND-006 / ADR 0006).
// Keep in sync with github.com/modelcontextprotocol/go-sdk@v1.7.0 mcp.supportedProtocolVersions
// (newest first in SDK; map membership only here).
var declaredProtocolVersions = map[string]struct{}{
	"2026-07-28": {}, // latest / preferred negotiate (v1.7.0)
	"2025-11-25": {},
	"2025-06-18": {},
	"2025-03-26": {},
	"2024-11-05": {},
}

// Read-only seed tool names (default Register omits mutations — POL-001).
// Optional tools (jenkins_search_logs, jenkins_mirror_logs, jenkins_doctor) require RegisterOptions.
var readOnlySeedToolNames = []string{
	"jenkins_get_jobs",
	"jenkins_get_job",
	"jenkins_get_running_builds",
	"jenkins_get_build",
	"jenkins_get_build_logs",
	"jenkins_get_build_log_tail",
	"jenkins_get_queue_item",
	"jenkins_wait_for_queue_item",
	"jenkins_search_builds",
	"jenkins_wait_for_running_build",
	"jenkins_get_nodes",      // HEALTH-001
	"jenkins_get_node",       // Wave 36 named-node (deny_node_names)
	"jenkins_list_views",     // Wave 38 list-all views + deny_view_names
	"jenkins_queue_pressure", // HEALTH-001
}

// Full seed inventory including mutations (when --allow-mutations and no stronger RO).
var allSeedToolNames = append(append([]string{}, readOnlySeedToolNames...),
	policy.ToolStartJob,
	policy.ToolStopBuild,
	policy.ToolCancelQueueItem,
)

// TestMCPServerToolRegistrationSmoke constructs an MCP server, registers seed tools,
// and completes an in-memory initialize + tools/list without contacting Jenkins.
// FND-006: official SDK pin smoke (not a full Cursor integration or SDK conformance suite).
// POL-001: default registration is read-only and omits start/stop.
func TestMCPServerToolRegistrationSmoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "jenkins-mcp-go-smoke",
		Version: "test",
	}, nil)

	// Client is unused for ListTools; nil-safe for discovery-only smoke.
	// Default opts: read-only true (POL-001 pilot default).
	tools.Register(server, &jenkins.Client{}, nil)

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "jenkins-mcp-smoke-client",
		Version: "test",
	}, nil)

	ct, st := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	defer serverSession.Close()

	clientSession, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer clientSession.Close()

	initRes := clientSession.InitializeResult()
	if initRes == nil {
		t.Fatal("InitializeResult is nil")
	}
	if initRes.ProtocolVersion == "" {
		t.Fatal("negotiated protocol version is empty")
	}
	if _, ok := declaredProtocolVersions[initRes.ProtocolVersion]; !ok {
		t.Fatalf("negotiated protocol version %q not in declared set %v",
			initRes.ProtocolVersion, mapsKeys(declaredProtocolVersions))
	}

	list, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if list == nil || len(list.Tools) == 0 {
		t.Fatal("ListTools returned no tools")
	}

	got := make(map[string]struct{}, len(list.Tools))
	for _, tool := range list.Tools {
		if tool == nil || tool.Name == "" {
			t.Fatalf("tool entry missing name: %#v", tool)
		}
		got[tool.Name] = struct{}{}
	}
	for _, name := range readOnlySeedToolNames {
		if _, ok := got[name]; !ok {
			t.Errorf("missing registered tool %q", name)
		}
	}
	// POL-001: mutations must not be advertised under default read-only.
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("mutation tool %q must be omitted under default read-only", name)
		}
	}
}

// TestGoModPinsOfficialMCPSDK asserts go.mod requires the official module pin
// documented in ADR 0006 (FND-006).
func TestGoModPinsOfficialMCPSDK(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/tools -> repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	mod := string(data)
	const want = "github.com/modelcontextprotocol/go-sdk v1.7.0"
	if !strings.Contains(mod, want) {
		t.Fatalf("go.mod must pin %q (ADR 0006 / FND-006); not found", want)
	}
	// Guard against accidental non-official replacements without an ADR update.
	if strings.Contains(mod, "replace github.com/modelcontextprotocol/go-sdk") {
		t.Fatal("go.mod must not replace the official MCP Go SDK without a new ADR")
	}
}

// TestReadOnlyOmitsMutationsListTools is the POL-001 discovery contract.
func TestReadOnlyOmitsMutationsListTools(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("RO: %q must not be listed", name)
		}
	}
	for _, name := range readOnlySeedToolNames {
		if _, ok := got[name]; !ok {
			t.Errorf("RO: missing read tool %q", name)
		}
	}
}

// TestAllowMutationsRegistersStartStop proves test/pilot opt-in registration.
func TestAllowMutationsRegistersStartStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true}),
	})
	for _, name := range allSeedToolNames {
		if _, ok := got[name]; !ok {
			t.Errorf("allow-mutations: missing %q", name)
		}
	}
}

// TestEnvReadOnlyBlocksAllowMutations ensures env wins for Effective RO:
// ListTools still hides mutations (Wave 30 may register under opt-in; filter +
// DenyMutation enforce discovery/dispatch RO).
func TestEnvReadOnlyBlocksAllowMutations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Simulate JENKINS_MCP_READ_ONLY=true via Inputs.EnvReadOnly (not process env).
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewReadOnlyGate(policy.Inputs{
			AllowMutations: true,
			EnvReadOnly:    true,
		}),
	})
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("env RO must hide %q from ListTools even with allow-mutations", name)
		}
	}
}

// TestForceReadOnlyBlocksAllowMutations ensures enterprise force keeps
// Effective RO: ListTools hides mutations despite --allow-mutations.
// Wave 30 still registers under opt-in; filter + DenyMutation hide/deny.
func TestForceReadOnlyBlocksAllowMutations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewReadOnlyGate(policy.Inputs{
			AllowMutations: true,
			Force:          policy.StaticForce{Force: true, Present: true},
		}),
	})
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("enterprise force must hide %q from ListTools", name)
		}
	}
}

// TestCraftedMutationDeniedUnderReadOnly proves dispatch-time policy_denial
// when a mutation tool is somehow registered under RO (POL-001).
func TestCraftedMutationDeniedUnderReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "deny-smoke", Version: "test"}, nil)
	gate := policy.NewDefaultReadOnlyGate()
	// Intentionally register mutations under RO for deny-path coverage.
	tools.RegisterMutationToolsForTest(server, &jenkins.Client{}, gate)

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
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "example"},
	})
	if err != nil {
		t.Fatalf("CallTool transport err: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want tool error result, got %#v", res)
	}
	// Error text is in content; must be policy_denial-shaped and secret-free.
	text := toolErrorText(res)
	if !strings.Contains(text, string(apperr.CodePolicyDenial)) &&
		!strings.Contains(strings.ToLower(text), "read-only") &&
		!strings.Contains(strings.ToLower(text), "denied") {
		t.Fatalf("expected policy denial message, got %q", text)
	}
	if strings.Contains(text, "api_token") || strings.Contains(text, "Bearer ") {
		t.Fatalf("denial leaked secrets: %q", text)
	}

	// Gate helper unit path (stable code).
	if apperr.CodeOf(gate.DenyMutation(policy.ToolStopBuild)) != apperr.CodePolicyDenial {
		t.Fatal("DenyMutation code")
	}
}

func listToolNames(t *testing.T, ctx context.Context, opts *tools.RegisterOptions) map[string]struct{} {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "list-smoke", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, opts)

	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "test"}, nil)
	ct, st := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := make(map[string]struct{}, len(list.Tools))
	for _, tool := range list.Tools {
		if tool != nil {
			got[tool.Name] = struct{}{}
		}
	}
	return got
}

func toolErrorText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func mapsKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
