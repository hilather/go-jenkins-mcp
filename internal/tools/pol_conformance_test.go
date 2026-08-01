package tools_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// POL-005 adversarial MCP-layer tests: discovery omission + dispatch deny,
// force RO vs allow-mutations, empty subject, crafted mutation registration.

func TestPOL005_ROOmitsStartStop_CraftedStillDenies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Discovery: mutations absent under default RO.
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("RO ListTools must omit %q", name)
		}
	}

	// Crafted registration: dispatch still DenyMutation (handler middleware).
	server := mcp.NewServer(&mcp.Implementation{Name: "pol005-ro", Version: "test"}, nil)
	gate := policy.NewDefaultReadOnlyGate()
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

	calls := []struct {
		name string
		args map[string]any
	}{
		{policy.ToolStartJob, map[string]any{"job_name": "example"}},
		{policy.ToolStopBuild, map[string]any{"job_name": "example", "build_number": 1}},
		{policy.ToolCancelQueueItem, map[string]any{"queue_id": 1}},
	}
	for _, tc := range calls {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if err != nil {
			t.Fatalf("%s transport: %v", tc.name, err)
		}
		if res == nil || !res.IsError {
			t.Fatalf("%s: want tool error, got %#v", tc.name, res)
		}
		text := toolErrorText(res)
		if !strings.Contains(strings.ToLower(text), "read-only") &&
			!strings.Contains(text, string(apperr.CodePolicyDenial)) &&
			!strings.Contains(strings.ToLower(text), "denied") {
			t.Fatalf("%s denial message %q", tc.name, text)
		}
	}
	// Direct gate path.
	if apperr.CodeOf(gate.DenyMutation(policy.ToolStartJob)) != apperr.CodePolicyDenial {
		t.Fatal("DenyMutation code")
	}
}

func TestPOL005_MCPDenyTool_OmittedAndHandlerDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const denied = "jenkins_get_build_logs"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			denied: {},
		},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	// Discovery omission.
	got := listToolNames(t, ctx, opts)
	if _, ok := got[denied]; ok {
		t.Fatalf("%q must be omitted from ListTools when denied", denied)
	}
	if _, ok := got["jenkins_get_jobs"]; !ok {
		t.Fatal("unrelated tool must remain")
	}

	// Force-register denied tool; handler middleware still denies.
	server := mcp.NewServer(&mcp.Implementation{Name: "pol005-deny", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        denied,
		Description: "force-registered for deny-path test",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildLogsToolArgs) (*mcp.CallToolResult, any, error) {
		t.Fatal("handler body must not run when policy denies")
		return nil, nil, nil
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
		Name: denied,
		Arguments: map[string]any{
			"job_name":     "example",
			"build_number": 1,
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want policy deny tool error, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial, got %q", text)
	}
}

func TestPOL005_AllowMutationsDefeatedByForceReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Effective RO still wins: ListTools must not advertise mutations while force is on.
	// Wave 30 registers under allow-mutations so force clear can re-list; discovery filter hides.
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate: policy.NewReadOnlyGate(policy.Inputs{
			AllowMutations: true,
			Force:          policy.StaticForce{Force: true, Present: true},
		}),
	})
	for _, name := range policy.MutationToolNames() {
		if _, ok := got[name]; ok {
			t.Errorf("force_read_only must hide %q from ListTools despite allow-mutations", name)
		}
	}
}

func TestPOL005_EmptySubjectDeniesWhenPolicyPresent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	// Empty subject: all tools omitted at registry when policy set.
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: policy.Subject{},
	})
	if len(got) != 0 {
		t.Fatalf("empty subject + policy: want no tools registered, got %v", got)
	}

	// Force-register + dispatch deny.
	server := mcp.NewServer(&mcp.Implementation{Name: "pol005-empty", Version: "test"}, nil)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: policy.Subject{},
	}
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_get_jobs",
		Description: "force",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobsToolArgs) (*mcp.CallToolResult, jenkins.GetJobsToolResponse, error) {
		t.Fatal("body must not run")
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
		t.Fatal(err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want deny, got %#v", res)
	}
}

func TestPOL005_AnonymousSubjectDeniesWhenPolicyPresent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: policy.NewSubject("corp", "anonymous", true),
	})
	if len(got) != 0 {
		t.Fatalf("anonymous subject: want no tools, got %v", got)
	}
}

func TestPOL005_NoGrantJenkinsFromEvaluator(t *testing.T) {
	// Unit-level narrative: MCP Allow never means grant_jenkins.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d := ev.Evaluate(
		policy.NewSubject("corp", "user", true),
		policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead},
		policy.Target{},
	)
	if d.Effect != policy.EffectAllow || d.ReasonCode != policy.ReasonOK {
		t.Fatalf("%+v", d)
	}
	if string(d.Effect) == "grant_jenkins" {
		t.Fatal("evaluator must not return grant_jenkins")
	}
	// Deny for admin proves no elevation path.
	evDeny := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:      policy.ModePilot,
		DenyTools: map[string]struct{}{"jenkins_get_jobs": {}},
	})
	d2 := evDeny.Evaluate(policy.NewSubject("corp", "jenkins-admin", true), policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if !d2.Denied() {
		t.Fatal("MCP deny restricts Jenkins admin")
	}
}

// POL-004 lite: tool is allowed globally, but deny_job_prefixes blocks a job
// at call time while another job succeeds. Registration still lists the tool.
func TestPOL004_JobScopedDenyAtCallTime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "jenkins_get_build"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	// Discovery: tool remains registered (empty target at registration).
	got := listToolNames(t, ctx, opts)
	if _, ok := got[toolName]; !ok {
		t.Fatalf("%q must remain discoverable under job-prefix deny only", toolName)
	}

	var handlerHits int
	server := mcp.NewServer(&mcp.Implementation{Name: "pol004-job", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        toolName,
		Description: "force-registered job-scope test",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildToolArgs) (*mcp.CallToolResult, any, error) {
		handlerHits++
		return &mcp.CallToolResult{}, map[string]any{
			"job":   args.JobName,
			"build": args.BuildNumber,
		}, nil
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

	// Denied job: handler must not run.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"job_name":     "secret-folder/job-a",
			"build_number": 1,
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want job-scoped policy deny, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial, got %q", text)
	}
	if handlerHits != 0 {
		t.Fatalf("handler ran on denied job (hits=%d)", handlerHits)
	}

	// Allowed job: succeeds.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"job_name":     "public/job",
			"build_number": 2,
		},
	})
	if err != nil {
		t.Fatalf("transport ok: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for public job, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if handlerHits != 1 {
		t.Fatalf("handler hits=%d want 1", handlerHits)
	}
}

// POL-004: deny_job_prefixes blocks jenkins_get_job when the job is passed as
// seed JSON field "name" (not job_name). Regression: target binding previously
// skipped Name/json:"name", so get_job bypassed job-prefix deny.
func TestPOL004_GetJob_NameFieldJobScopedDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "jenkins_get_job"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	// Discovery: tool remains registered (empty target at registration).
	got := listToolNames(t, ctx, opts)
	if _, ok := got[toolName]; !ok {
		t.Fatalf("%q must remain discoverable under job-prefix deny only", toolName)
	}

	var handlerHits int
	server := mcp.NewServer(&mcp.Implementation{Name: "pol004-get-job", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        toolName,
		Description: "force-registered get_job name-field target test",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, any, error) {
		handlerHits++
		return &mcp.CallToolResult{}, map[string]any{
			"name":     args.Name,
			"job_name": args.JobName,
		}, nil
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

	// Denied job via seed "name" field: handler must not run.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"name": "secret-folder/job",
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want job-scoped policy deny for get_job name=, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial, got %q", text)
	}
	if handlerHits != 0 {
		t.Fatalf("handler ran on denied job via name (hits=%d)", handlerHits)
	}

	// Denied via job_name alias as well.
	resAlias, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"job_name": "secret-folder/other",
		},
	})
	if err != nil {
		t.Fatalf("alias transport: %v", err)
	}
	if resAlias == nil || !resAlias.IsError {
		t.Fatalf("want job-scoped deny for get_job job_name=, got %#v", resAlias)
	}
	if handlerHits != 0 {
		t.Fatalf("handler ran on denied job via job_name (hits=%d)", handlerHits)
	}

	// Allowed job via name: succeeds.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"name": "public/job",
		},
	})
	if err != nil {
		t.Fatalf("transport ok: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for public job via name, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if handlerHits != 1 {
		t.Fatalf("handler hits=%d want 1", handlerHits)
	}

	// job_name preferred over name when both present: deny secret via job_name
	// even if name would be public.
	resBoth, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"name":     "public/job",
			"job_name": "secret-folder/via-alias",
		},
	})
	if err != nil {
		t.Fatalf("both transport: %v", err)
	}
	if resBoth == nil || !resBoth.IsError {
		t.Fatalf("want deny when job_name is secret (preferred over public name), got %#v", resBoth)
	}
	if handlerHits != 1 {
		t.Fatalf("handler hits=%d want 1 after both-field deny", handlerHits)
	}
}

// POL-004 lite: adapter-backed tools evaluate with job target when present.
func TestPOL004_AdapterTools_JobScopedDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:                    policy.NewDefaultReadOnlyGate(),
		Policy:                  ev,
		Subject:                 subj,
		ExternalLogs:            &mockExternalLogs{},
		EnableChangeCorrelation: true,
	}

	// Tools remain discoverable (registration empty target).
	got := listToolNames(t, ctx, opts)
	for _, name := range []string{tools.ToolQueryExternalLogs, tools.ToolGetChangeCorrelation} {
		if _, ok := got[name]; !ok {
			t.Fatalf("%q must be registered for adapter job-deny test", name)
		}
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "pol004-adapter", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, opts)

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

	for _, name := range []string{tools.ToolQueryExternalLogs, tools.ToolGetChangeCorrelation} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: name,
			Arguments: map[string]any{
				"job_name":     "secret/job",
				"build_number": 1,
			},
		})
		if err != nil {
			t.Fatalf("%s transport: %v", name, err)
		}
		if res == nil || !res.IsError {
			t.Fatalf("%s: want job-scoped deny, got %#v", name, res)
		}
		text := toolErrorText(res)
		if !strings.Contains(strings.ToLower(text), "denied") &&
			!strings.Contains(text, string(apperr.CodePolicyDenial)) {
			t.Fatalf("%s: expected policy denial, got %q", name, text)
		}
	}

	// Public job on external logs is allowed through policy (may still fail later
	// on validation/network — only assert not job_pattern_deny).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolQueryExternalLogs,
		Arguments: map[string]any{
			"job_name":     "public/job",
			"build_number": 1,
		},
	})
	if err != nil {
		t.Fatalf("public transport: %v", err)
	}
	if res != nil && res.IsError {
		text := toolErrorText(res)
		if strings.Contains(text, "denied by MCP policy") ||
			strings.Contains(text, policy.ReasonJobPatternDeny) {
			t.Fatalf("public job must not hit job-prefix deny: %q", text)
		}
	}
}

func TestPOL004_JobScopedDeny_NormalizedRawArgs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "jenkins_get_build"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder", "**/secret"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	var handlerHits int
	server := mcp.NewServer(&mcp.Implementation{Name: "pol004-job-norm", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        toolName,
		Description: "force-registered job-path normalize deny test",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetBuildToolArgs) (*mcp.CallToolResult, any, error) {
		handlerHits++
		return &mcp.CallToolResult{}, map[string]any{"job": args.JobName}, nil
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

	// Raw args that normalize onto denied jobs.
	rawDenied := []struct {
		job  string
		note string
	}{
		{"secret-folder//job-a", "collapse // under classic deny"},
		{"/secret-folder/job-a", "leading slash under classic deny"},
		{"prod//secret", "collapse // under **/secret"},
		{"/secret", "leading slash under **/secret"},
		{"//secret", "double leading under **/secret"},
	}
	for _, tc := range rawDenied {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: toolName,
			Arguments: map[string]any{
				"job_name":     tc.job,
				"build_number": 1,
			},
		})
		if err != nil {
			t.Fatalf("%s transport: %v", tc.note, err)
		}
		if res == nil || !res.IsError {
			t.Fatalf("%s: want job-scoped deny for raw %q, got %#v", tc.note, tc.job, res)
		}
		text := toolErrorText(res)
		if !strings.Contains(strings.ToLower(text), "denied") &&
			!strings.Contains(text, string(apperr.CodePolicyDenial)) {
			t.Fatalf("%s: expected policy denial, got %q", tc.note, text)
		}
	}
	if handlerHits != 0 {
		t.Fatalf("handler must not run on normalized deny paths (hits=%d)", handlerHits)
	}

	// Public job with empty segments still allowed (normalizes to public/job).
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"job_name":     "public//job",
			"build_number": 2,
		},
	})
	if err != nil {
		t.Fatalf("public transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for public//job, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if handlerHits != 1 {
		t.Fatalf("handler hits=%d want 1", handlerHits)
	}
}

// Wave 35: deny_node_names / deny_view_names at call time via ForceRegisterReadToolForTest.
// Wave 36 adds production jenkins_get_node; this test still covers generic node_name binding
// plus list_jobs view. See TestGetNodeTool_CallAndPolicyDeny for the production tool path.
func TestWave35_NodeAndViewResourceDeny_Dispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:          policy.ModePilot,
		DenyNodeNames: []string{"prod-agent-*"},
		DenyViewNames: []string{"secret-view"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	type nodeToolArgs struct {
		NodeName string `json:"node_name,omitempty"`
	}
	var nodeHits, viewHits int

	server := mcp.NewServer(&mcp.Implementation{Name: "wave35-resource", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "test_get_named_node",
		Description: "force-registered named node deny test (Wave 35)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args nodeToolArgs) (*mcp.CallToolResult, any, error) {
		nodeHits++
		return &mcp.CallToolResult{}, map[string]any{"node": args.NodeName}, nil
	})
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        "jenkins_list_jobs",
		Description: "force-registered list_jobs view deny test (Wave 35)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.ListJobsToolArgs) (*mcp.CallToolResult, any, error) {
		viewHits++
		return &mcp.CallToolResult{}, map[string]any{"view": args.View}, nil
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

	// Denied node_name must fail closed before handler.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_get_named_node",
		Arguments: map[string]any{"node_name": "prod-agent-01"},
	})
	if err != nil {
		t.Fatalf("node transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want node resource deny, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial for node, got %q", text)
	}
	if nodeHits != 0 {
		t.Fatalf("node handler must not run on deny (hits=%d)", nodeHits)
	}

	// Allowed node.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_get_named_node",
		Arguments: map[string]any{"node_name": "dev-agent-01"},
	})
	if err != nil {
		t.Fatalf("node ok transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for public node, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if nodeHits != 1 {
		t.Fatalf("node hits=%d want 1", nodeHits)
	}

	// Denied view (seed json:"view").
	resView, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"view": "secret-view"},
	})
	if err != nil {
		t.Fatalf("view transport: %v", err)
	}
	if resView == nil || !resView.IsError {
		t.Fatalf("want view resource deny, got %#v", resView)
	}
	if viewHits != 0 {
		t.Fatalf("view handler must not run on deny (hits=%d)", viewHits)
	}

	// Allowed view.
	resViewOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "jenkins_list_jobs",
		Arguments: map[string]any{"view": "public-view"},
	})
	if err != nil {
		t.Fatalf("view ok transport: %v", err)
	}
	if resViewOK == nil || resViewOK.IsError {
		t.Fatalf("want allow for public view, got %#v text=%q", resViewOK, toolErrorText(resViewOK))
	}
	if viewHits != 1 {
		t.Fatalf("view hits=%d want 1", viewHits)
	}

	// Empty target (no node/view) is not resource-denied.
	resEmpty, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_get_named_node",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("empty transport: %v", err)
	}
	if resEmpty == nil || resEmpty.IsError {
		t.Fatalf("empty node args must allow: %#v text=%q", resEmpty, toolErrorText(resEmpty))
	}
}

// Wave 38: deny_branch_names applies to multi-segment job_name leaf when tools
// have no branch_name arg (e.g. jenkins_get_job). Root freestyle "main" allows.
func TestWave38_JobNameLeafBranchDeny_GetJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "jenkins_get_job"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"main", "release/*"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	var handlerHits int
	server := mcp.NewServer(&mcp.Implementation{Name: "wave38-branch-leaf", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        toolName,
		Description: "force-registered get_job branch-leaf deny test (Wave 38)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, any, error) {
		handlerHits++
		return &mcp.CallToolResult{}, map[string]any{
			"name":     args.Name,
			"job_name": args.JobName,
		}, nil
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

	// Multi-segment multibranch path: leaf "main" denied; handler must not run.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{"name": "team/mb/main"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want branch-leaf deny for team/mb/main, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial for branch leaf, got %q", text)
	}
	if handlerHits != 0 {
		t.Fatalf("handler must not run on branch-leaf deny (hits=%d)", handlerHits)
	}

	// Single-segment root freestyle "main": allow (no branch leaf rule).
	resRoot, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{"name": "main"},
	})
	if err != nil {
		t.Fatalf("root transport: %v", err)
	}
	if resRoot == nil || resRoot.IsError {
		t.Fatalf("root freestyle main must allow: %#v text=%q", resRoot, toolErrorText(resRoot))
	}
	if handlerHits != 1 {
		t.Fatalf("handler hits=%d want 1 after root allow", handlerHits)
	}

	// Multi-segment public leaf allowed.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{"job_name": "team/mb/feature-x"},
	})
	if err != nil {
		t.Fatalf("ok transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for team/mb/feature-x, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if handlerHits != 2 {
		t.Fatalf("handler hits=%d want 2", handlerHits)
	}
}

// Wave 38 / POL-005: list_jobs response-row filter via deny_job_prefixes still
// works (public helpers FilterDeniedJobs / KeepUnlessJobPrefixDenied).
func TestWave38_ListJobs_DenyJobPrefixesFilterStillWorks(t *testing.T) {
	t.Parallel()

	jobs := []jenkins.JobSummary{
		{FullName: "public/app", Name: "app", Kind: jenkins.JobKindJob},
		{FullName: "secret-folder/job-a", Name: "job-a", Kind: jenkins.JobKindJob},
		{FullName: "secret-folder/nested/x", Name: "x", Kind: jenkins.JobKindJob},
		{FullName: "team/public", Name: "public", Kind: jenkins.JobKindJob},
		{FullName: "secret-folder-other", Name: "secret-folder-other", Kind: jenkins.JobKindJob},
	}
	kept, omitted := tools.FilterDeniedJobs([]string{"secret-folder"}, jobs)
	if omitted != 2 {
		t.Fatalf("omitted=%d want 2 (path prefix, not bare string)", omitted)
	}
	if len(kept) != 3 {
		t.Fatalf("kept=%d want 3: %+v", len(kept), kept)
	}
	for _, j := range kept {
		if j.FullName == "secret-folder/job-a" || j.FullName == "secret-folder/nested/x" {
			t.Fatalf("denied job leaked: %q", j.FullName)
		}
	}
	// secret-folder-other must remain (not a path child of secret-folder).
	foundOther := false
	for _, j := range kept {
		if j.FullName == "secret-folder-other" {
			foundOther = true
		}
	}
	if !foundOther {
		t.Fatal("secret-folder-other must not match secret-folder path prefix")
	}

	// Compose with branch filter: both keeps apply (AND).
	branchJobs := []jenkins.JobSummary{
		{FullName: "public/app", Name: "app", Kind: jenkins.JobKindJob},
		{FullName: "mb/main", Name: "main", Kind: jenkins.JobKindBranch},
		{FullName: "secret-folder/job-a", Name: "job-a", Kind: jenkins.JobKindJob},
		{FullName: "mb/feature", Name: "feature", Kind: jenkins.JobKindBranch},
	}
	kept2, om2 := tools.ApplyJobPolicyFilters(branchJobs,
		tools.KeepUnlessJobPrefixDenied([]string{"secret-folder"}),
		tools.KeepUnlessBranchDenied([]string{"main"}),
	)
	if om2 != 2 {
		t.Fatalf("composed omitted=%d want 2 (1 job + 1 branch)", om2)
	}
	if len(kept2) != 2 {
		t.Fatalf("composed kept=%d want 2: %+v", len(kept2), kept2)
	}
	names := map[string]bool{}
	for _, j := range kept2 {
		names[j.FullName] = true
	}
	if !names["public/app"] || !names["mb/feature"] {
		t.Fatalf("expected public/app + mb/feature, got %v", names)
	}
	if names["mb/main"] || names["secret-folder/job-a"] {
		t.Fatalf("denied rows must be omitted: %v", names)
	}
}

// Wave 38 / POL-005: production jenkins_get_node still enforces deny_node_names
// at dispatch (handler never runs; Jenkins not contacted).
func TestWave38_GetNode_DenyNodeNames_Dispatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No HTTP server: deny path must fail closed before client use.
	// Allow path uses a minimal fixture so the tool can complete.
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
		DenyNodeNames: []string{"prod-agent-*", "secret-node"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	// Tool remains discoverable (empty target at registration / ListTools).
	got := listToolNames(t, ctx, opts)
	if _, ok := got[tools.ToolGetNode]; !ok {
		t.Fatalf("%q must remain discoverable under deny_node_names only", tools.ToolGetNode)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "wave38-get-node", Version: "test"}, nil)
	tools.Register(server, jc, opts)

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

	// Denied node: policy_denial, zero Jenkins hits.
	hits = 0
	resDeny, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolGetNode,
		Arguments: map[string]any{"node_name": "prod-agent-01"},
	})
	if err != nil {
		t.Fatalf("deny transport: %v", err)
	}
	if resDeny == nil || !resDeny.IsError {
		t.Fatalf("want deny_node_names policy deny, got %#v", resDeny)
	}
	text := toolErrorText(resDeny)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial, got %q", text)
	}
	if hits != 0 {
		t.Fatalf("Jenkins must not be called on deny_node_names (hits=%d)", hits)
	}

	// Exact secret-node deny.
	resExact, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolGetNode,
		Arguments: map[string]any{"node_name": "secret-node"},
	})
	if err != nil {
		t.Fatalf("exact transport: %v", err)
	}
	if resExact == nil || !resExact.IsError {
		t.Fatalf("want exact node deny, got %#v", resExact)
	}
	if hits != 0 {
		t.Fatalf("Jenkins hits on exact deny=%d", hits)
	}

	// Allowed node reaches Jenkins.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      tools.ToolGetNode,
		Arguments: map[string]any{"node_name": "dev-agent-01"},
	})
	if err != nil {
		t.Fatalf("ok transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for public node, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if hits != 1 {
		t.Fatalf("jenkins hits=%d want 1", hits)
	}
}

// Wave 39: deny_branch_names release/* matches nested slashy JobName path
// team/mb/release/1.2 (intermediate suffix) at call time; root freestyle still
// allows; unrelated multi-segment leaf allows.
func TestWave39_SlashyBranchDeny_GetJob(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "jenkins_get_job"
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyBranchNames: []string{"release/*"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	}

	var handlerHits int
	server := mcp.NewServer(&mcp.Implementation{Name: "wave39-slashy-branch", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        toolName,
		Description: "force-registered get_job slashy branch deny test (Wave 39)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args jenkins.GetJobToolArgs) (*mcp.CallToolResult, any, error) {
		handlerHits++
		return &mcp.CallToolResult{}, map[string]any{
			"name":     args.Name,
			"job_name": args.JobName,
		}, nil
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

	// Nested slashy multibranch path: release/* denies; handler must not run.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{"name": "team/mb/release/1.2"},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want slashy branch deny for team/mb/release/1.2, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy denial for slashy branch, got %q", text)
	}
	if handlerHits != 0 {
		t.Fatalf("handler must not run on slashy branch deny (hits=%d)", handlerHits)
	}

	// Unrelated multi-segment leaf allows.
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{"job_name": "team/mb/main"},
	})
	if err != nil {
		t.Fatalf("ok transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for team/mb/main, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	if handlerHits != 1 {
		t.Fatalf("handler hits=%d want 1", handlerHits)
	}

	// Single-segment root freestyle "main" still allows (Wave 38).
	resRoot, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: map[string]any{"name": "main"},
	})
	if err != nil {
		t.Fatalf("root transport: %v", err)
	}
	if resRoot == nil || resRoot.IsError {
		t.Fatalf("root freestyle main must allow: %#v text=%q", resRoot, toolErrorText(resRoot))
	}
	if handlerHits != 2 {
		t.Fatalf("handler hits=%d want 2", handlerHits)
	}
}
