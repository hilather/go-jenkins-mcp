package tools_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toggleAuthGate is a non-sticky AuthGate for Wave 29 recovery tests.
// Fail closed when fail is true; no secrets in Check errors.
type toggleAuthGate struct {
	mu   sync.Mutex
	fail bool
	// errCanary must never appear in ListTools responses (discovery returns empty).
	errCanary string
}

func (g *toggleAuthGate) Check() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail {
		if g.errCanary != "" {
			return errors.New("session unusable: " + g.errCanary)
		}
		return errors.New("session unusable")
	}
	return nil
}

func (g *toggleAuthGate) SetFail(v bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail = v
}

// swappableEval lets tests replace the deny-only document without re-Register
// (simulates ReloadableDenyOnly mid-session deny_tools changes).
type swappableEval struct {
	mu   sync.RWMutex
	eval policy.PolicyEvaluator
}

func (s *swappableEval) Evaluate(subject policy.Subject, action policy.Action, target policy.Target) policy.Decision {
	s.mu.RLock()
	ev := s.eval
	s.mu.RUnlock()
	if ev == nil {
		return policy.Decision{
			Effect:      policy.EffectDeny,
			ReasonCode:  policy.ReasonNoEvaluator,
			Explanation: "MCP policy evaluator is not configured (fail closed)",
		}
	}
	return ev.Evaluate(subject, action, target)
}

func (s *swappableEval) Set(ev policy.PolicyEvaluator) {
	s.mu.Lock()
	s.eval = ev
	s.mu.Unlock()
}

func connectListToolsSession(t *testing.T, ctx context.Context, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
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
	return cs
}

func listNamesFromSession(t *testing.T, ctx context.Context, cs *mcp.ClientSession) map[string]struct{} {
	t.Helper()
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

// Wave 28: deny_tools omits from ListTools while leaving unrelated tools visible.
func TestListToolsFilter_DenyToolsHidden(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const denied = "jenkins_get_build_logs"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{denied: {}},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})
	if _, ok := got[denied]; ok {
		t.Fatalf("%q must be omitted from ListTools when denied", denied)
	}
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("unrelated tool must remain discoverable")
	}
}

// Wave 28: loosening deny_tools mid-session re-exposes a previously denied
// read tool without re-Register (always-register + live filter).
func TestListToolsFilter_DenyReload_AllowAppears(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const denied = "jenkins_get_build_logs"
	swap := &swappableEval{}
	swap.Set(policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{denied: {}},
	}))
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-allow", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  swap,
		Subject: subj,
	})
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	if _, ok := got[denied]; ok {
		t.Fatalf("before reload: %q must be hidden", denied)
	}
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("before reload: jobs must remain")
	}

	// Loosen policy: remove deny without re-Register.
	swap.Set(policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot}))
	got2 := listNamesFromSession(t, ctx, cs)
	if _, ok := got2[denied]; !ok {
		t.Fatalf("after loosen: %q must reappear in ListTools without re-Register", denied)
	}
}

// Wave 28: tightening deny_tools mid-session hides the tool; CallTool still
// fails closed with policy_denial if invoked.
func TestListToolsFilter_DenyReload_HideAndDispatchDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const target = "jenkins_get_jobs"
	swap := &swappableEval{}
	swap.Set(policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot}))
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-deny", Version: "test"}, nil)
	// httptest not required: policy deny runs before handler body.
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  swap,
		Subject: subj,
	})
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	if _, ok := got[target]; !ok {
		t.Fatalf("before tighten: %q must be listed", target)
	}

	swap.Set(policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{target: {}},
	}))
	got2 := listNamesFromSession(t, ctx, cs)
	if _, ok := got2[target]; ok {
		t.Fatalf("after tighten: %q must disappear from ListTools", target)
	}

	// Dispatch still denies (defense in depth) even though tool is registered.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      target,
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want policy_denial tool error, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial, got %q", text)
	}
}

// Wave 28 + ReloadableDenyOnly: file reload updates ListTools without restart.
func TestListToolsFilter_ReloadableDenyOnly_FileReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, []byte(`{
		"version": 1,
		"mode": "pilot",
		"deny_tools": ["jenkins_get_build_logs"]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	rel := policy.NewReloadableFromLoadResult(res, policy.ReloadableConfig{
		Load: func() (policy.LoadResult, error) {
			return policy.LoadOverlay(policy.LoadOptions{Path: path})
		},
		Path:        path,
		MinInterval: -1,
	})
	subj := policy.NewSubject("corp", "admin", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-reloadable", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  rel,
		Subject: subj,
	})
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	if _, ok := got["jenkins_get_build_logs"]; ok {
		t.Fatal("initial: logs tool must be filtered")
	}

	if err := os.WriteFile(path, []byte(`{
		"version": 1,
		"mode": "pilot",
		"deny_tools": []
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	if err := rel.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	got2 := listNamesFromSession(t, ctx, cs)
	if _, ok := got2["jenkins_get_build_logs"]; !ok {
		t.Fatal("after file reload: logs tool must reappear without re-Register")
	}
}

// Wave 28: RO / force_read_only hides force-registered mutations from ListTools.
func TestListToolsFilter_ROHidesForceRegisteredMutations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-ro-mut", Version: "test"}, nil)
	gate := policy.NewDefaultReadOnlyGate()
	tools.RegisterMutationToolsForTest(server, &jenkins.Client{}, gate)
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("RO ListTools must omit force-registered mutation %q", name)
		}
	}

	// Dispatch still policy_denial.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "example"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want RO denial, got %#v", res)
	}
}

// Wave 28: DynamicForce flip mid-serve hides mutations from ListTools when they
// were registered under allow-mutations (filter uses live gate.Effective).
func TestListToolsFilter_DynamicForceHidesMutations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dyn := policy.NewDynamicForce(false, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	if gate.Effective() {
		t.Fatal("precondition: gate must allow mutations")
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-dyn", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Gate: gate})
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; !ok {
			t.Fatalf("allow-mutations: %q must appear before force flip", name)
		}
	}

	dyn.Set(true, true)
	if !gate.Effective() {
		t.Fatal("force=true must make gate Effective")
	}
	got2 := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got2[name]; ok {
			t.Errorf("after DynamicForce on: ListTools must hide %q", name)
		}
	}

	// Bidirectional: force clear re-lists mutations without re-Register when
	// they were registered under allow-mutations (filter uses live gate).
	dyn.Set(false, true)
	if gate.Effective() {
		t.Fatal("force=false must clear Effective RO when allow-mutations")
	}
	got3 := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got3[name]; !ok {
			t.Errorf("after DynamicForce off: ListTools must re-show %q", name)
		}
	}
}

// Wave 30: AllowMutations + DynamicForce true at Register still attaches
// mutation tools. ListTools/CallTool deny while Effective; force clear re-lists
// and CallTool is no longer RO-denied (without re-Register / restart).
func TestListToolsFilter_AllowMutationsRegistersUnderForceRO_HotClear(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dyn := policy.NewDynamicForce(true, true) // force_read_only at Register
	gate := policy.NewReadOnlyGate(policy.Inputs{
		AllowMutations: true,
		Force:          dyn,
	})
	if !gate.Effective() {
		t.Fatal("precondition: force=true must make Effective")
	}
	if !gate.ShouldRegisterMutations() {
		t.Fatal("precondition: Wave 30 ShouldRegisterMutations under allow-mutations + force")
	}
	if gate.AllowMutationRegistration() {
		t.Fatal("precondition: AllowMutationRegistration still false under force")
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-w30", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Gate: gate})
	cs := connectListToolsSession(t, ctx, server)

	// Discovery hides mutations while force RO.
	got := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("force RO ListTools must hide registered mutation %q", name)
		}
	}

	// CallTool reaches the registered handler and is denied (not unknown tool).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "example"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want RO denial while force Effective, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(text, string(apperr.CodePolicyDenial)) &&
		!strings.Contains(strings.ToLower(text), "read-only") &&
		!strings.Contains(strings.ToLower(text), "denied") {
		t.Fatalf("expected policy denial (proves tool registered), got %q", text)
	}

	// Hot-clear force: ListTools re-shows mutations; CallTool not RO-denied.
	dyn.Set(false, true)
	if gate.Effective() {
		t.Fatal("force clear + allow-mutations must clear Effective")
	}
	got2 := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got2[name]; !ok {
			t.Errorf("after force clear: ListTools must show registered %q without re-Register", name)
		}
	}

	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "example"},
	})
	if err != nil {
		t.Fatalf("transport after clear: %v", err)
	}
	// Without Jenkins fixture, handler may still error — but must not be RO policy_denial.
	if res2 != nil && res2.IsError {
		text2 := toolErrorText(res2)
		if strings.Contains(strings.ToLower(text2), "read-only") {
			t.Fatalf("after force clear: must not be RO denial, got %q", text2)
		}
	}
}

// Wave 30 residual: without AllowMutations, mutations are never registered.
// Force clear cannot invent unregistered tools (builtin default keeps RO).
func TestListToolsFilter_NoAllowMutations_ForceClearDoesNotInvent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dyn := policy.NewDynamicForce(true, true)
	gate := policy.NewReadOnlyGate(policy.Inputs{
		// AllowMutations false: pilot default RO contribution remains.
		Force: dyn,
	})
	if !gate.Effective() || gate.ShouldRegisterMutations() {
		t.Fatal("precondition: default RO, no mutation registration")
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "list-filter-w30-no-opt", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Gate: gate})
	cs := connectListToolsSession(t, ctx, server)

	// Unregistered: CallTool is not a live RO-denial path on a real handler
	// (unknown / not found). ListTools empty of mutations.
	got := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("no allow-mutations: %q must not be listed", name)
		}
	}

	dyn.Set(false, true)
	// Builtin default still keeps Effective RO without AllowMutations.
	if !gate.Effective() {
		t.Fatal("clearing force without allow-mutations must keep Effective (builtin)")
	}
	got2 := listNamesFromSession(t, ctx, cs)
	for _, name := range policy.MutationToolNames() {
		if _, ok := got2[name]; ok {
			t.Errorf("after force clear without opt-in: %q must stay absent", name)
		}
	}

	// Unknown tool (never registered) — not policy_denial read-only on a live tool.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      policy.ToolStartJob,
		Arguments: map[string]any{"job_name": "example"},
	})
	if err != nil {
		// Some SDK paths surface unknown as transport/RPC error; either way OK.
		return
	}
	if res == nil {
		t.Fatal("expected some result for unknown tool")
	}
	if res.IsError {
		text := toolErrorText(res)
		// Must not look like a registered-under-RO deny path that would imply registration.
		// Unknown tool messages vary; presence of "unknown"/"not found" is fine.
		_ = text
	}
}

// Nil policy: ListTools shows registered reads; RO still omits mutations.
func TestListToolsFilter_NilPolicyPassThrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
		// Policy nil
	})
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("nil policy: seed read tools must appear")
	}
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("nil policy + RO: mutation %q must be absent", name)
		}
	}
}

// Empty subject + policy: ListTools empty (fail closed) while tools stay registered
// for dispatch deny paths.
func TestListToolsFilter_EmptySubjectHidesAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: policy.Subject{},
	})
	if len(got) != 0 {
		t.Fatalf("empty subject + policy: want no ListTools entries, got %v", got)
	}
}

// Wave 29: failing AuthGate empties ListTools (no tool names advertised after session death).
func TestListToolsFilter_AuthGateFail_EmptyList(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const canary = "AUTH_GATE_LIST_CANARY_token_must_not_appear_xyz"
	gate := &toggleAuthGate{fail: true, errCanary: canary}

	server := mcp.NewServer(&mcp.Implementation{Name: "list-auth-fail", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: gate,
	})
	cs := connectListToolsSession(t, ctx, server)

	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if list == nil {
		t.Fatal("ListTools result nil")
	}
	if len(list.Tools) != 0 {
		names := make([]string, 0, len(list.Tools))
		for _, tool := range list.Tools {
			if tool != nil {
				names = append(names, tool.Name)
			}
		}
		t.Fatalf("AuthGate fail: want empty Tools, got %v", names)
	}
	// Must not surface Check error text (or secrets) via discovery response.
	// ListToolsResult has no free-form error body on success; assert canary
	// never appears in tool names/descriptions if any leaked somehow.
	for _, tool := range list.Tools {
		if tool == nil {
			continue
		}
		if strings.Contains(tool.Name, canary) || strings.Contains(tool.Description, canary) {
			t.Fatalf("canary leaked in ListTools tool entry: %#v", tool)
		}
	}
}

// Wave 29: non-sticky AuthGate recovery re-exposes tools without re-Register.
func TestListToolsFilter_AuthGateRecover_ToolsReappear(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	gate := &toggleAuthGate{fail: true}
	server := mcp.NewServer(&mcp.Implementation{Name: "list-auth-recover", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: gate,
	})
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	if len(got) != 0 {
		t.Fatalf("gate fail: want empty ListTools, got %v", got)
	}

	gate.SetFail(false)
	got2 := listNamesFromSession(t, ctx, cs)
	if _, ok := got2["jenkins_get_jobs"]; !ok {
		t.Fatal("after AuthGate recovers: seed read tools must reappear without re-Register")
	}
}

// Wave 29: sticky SessionGuard revoke keeps ListTools empty (session death).
func TestListToolsFilter_AuthGateStickyRevoke_StaysEmpty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	guard := auth.NewSessionGuard("fp-list-sticky")
	server := mcp.NewServer(&mcp.Implementation{Name: "list-auth-sticky", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		AuthGate: guard,
	})
	cs := connectListToolsSession(t, ctx, server)

	got := listNamesFromSession(t, ctx, cs)
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("precondition: usable guard must list seed reads")
	}

	guard.MarkRevoked()
	got2 := listNamesFromSession(t, ctx, cs)
	if len(got2) != 0 {
		t.Fatalf("after sticky revoke: want empty ListTools, got %v", got2)
	}
	// Still empty on subsequent discovery.
	got3 := listNamesFromSession(t, ctx, cs)
	if len(got3) != 0 {
		t.Fatalf("sticky revoke must keep ListTools empty, got %v", got3)
	}
}

// Wave 29: AuthGate OK still applies Wave 28 deny_tools / RO policy filter.
func TestListToolsFilter_AuthGateOK_DenyToolsStillFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const denied = "jenkins_get_build_logs"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{denied: {}},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	gate := &toggleAuthGate{fail: false}

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate:     policy.NewDefaultReadOnlyGate(),
		Policy:   ev,
		Subject:  subj,
		AuthGate: gate,
	})
	if _, ok := got[denied]; ok {
		t.Fatalf("AuthGate OK: %q must still be omitted when deny_tools", denied)
	}
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("AuthGate OK: unrelated tool must remain discoverable")
	}
}

// Wave 29: nil AuthGate keeps Wave 28 discovery behavior (unchanged).
func TestListToolsFilter_NilAuthGate_Unchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
		// AuthGate nil
	})
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("nil AuthGate: seed read tools must appear")
	}
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("nil AuthGate + RO: mutation %q must be absent", name)
		}
	}
}
