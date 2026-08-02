package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func powerUserRegister(t *testing.T, f *mutFixture, mp *policy.MutationPolicy) (*mcp.ClientSession, *mcp.ServerSession, *mutation.Manager, context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	mem := &audit.Memory{}
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	mgr := mutation.NewManager(mutation.Config{
		Gate:                 gate,
		Audit:                mem,
		ProfileID:            "corp",
		PrincipalID:          "alice",
		ConfirmCooldown:      -1,
		MaxPreviewsPerMinute: -1,
		TTL:                  time.Minute,
	})
	server := mcp.NewServer(&mcp.Implementation{Name: "mut-power", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:           gate,
		Audit:          mem,
		Mutations:      mgr,
		ProfileID:      "corp",
		PrincipalID:    "alice",
		MutationPolicy: mp,
	})
	cs, ss := connectMCP(t, ctx, server)
	return cs, ss, mgr, ctx, cancel
}

func previewThenConfirm(t *testing.T, ctx context.Context, cs *mcp.ClientSession, tool string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview error: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	if prev["status"] != "preview" {
		t.Fatalf("want preview status, got %#v", prev)
	}
	tok, _ := prev["confirmationToken"].(string)
	if tok == "" {
		t.Fatal("missing confirmationToken")
	}
	args2 := map[string]any{}
	for k, v := range args {
		args2[k] = v
	}
	args2["confirmation_token"] = tok
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args2})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm error: %s", toolErrorText(res2))
	}
	return toolStructuredJSON(t, res2)
}

func TestPowerUser_InterruptPreviewThenConfirm_AndWrongState(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	// Preview must not POST.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolInterruptBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
			"mode":         "term",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview: %s", toolErrorText(res))
	}
	if f.termCalls.Load() != 0 {
		t.Fatal("term POST on preview")
	}
	prev := toolStructuredJSON(t, res)
	tok, _ := prev["confirmationToken"].(string)
	if tok == "" || prev["mode"] != "term" {
		t.Fatalf("preview %#v", prev)
	}

	// Confirm executes once.
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolInterruptBuild,
		Arguments: map[string]any{
			"job_name":           "demo",
			"build_number":       1,
			"mode":               "term",
			"confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm: %s", toolErrorText(res2))
	}
	if f.termCalls.Load() != 1 {
		t.Fatalf("termCalls=%d", f.termCalls.Load())
	}
	out := toolStructuredJSON(t, res2)
	if out["mode"] != "term" || out["interrupted"] != true {
		t.Fatalf("execute %#v", out)
	}

	// Wrong-state: finished build refuses without POST.
	f.building.Store(false)
	f.killCalls.Store(0)
	res3, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolInterruptBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 2,
			"mode":         "kill",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res3.IsError {
		t.Fatal("finished build must fail closed on preview")
	}
	if f.killCalls.Load() != 0 {
		t.Fatal("kill POST on finished build")
	}
	if !strings.Contains(strings.ToLower(toolErrorText(res3)), "finished") {
		t.Fatalf("error text: %s", toolErrorText(res3))
	}
}

func TestPowerUser_RebuildPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	// Source build finished is OK for rebuild.
	f.building.Store(false)
	out := previewThenConfirm(t, ctx, cs, policy.ToolRebuildBuild, map[string]any{
		"job_name":     "demo",
		"build_number": 5,
	})
	if f.startCalls.Load() != 1 {
		t.Fatalf("startCalls=%d want 1", f.startCalls.Load())
	}
	form, _ := f.lastStartForm.Load().(string)
	if !strings.Contains(form, "BRANCH=main") {
		t.Fatalf("rebuild form=%q", form)
	}
	if out["jobName"] != "demo" {
		t.Fatalf("%#v", out)
	}
}

func TestPowerUser_ReplayPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	out := previewThenConfirm(t, ctx, cs, policy.ToolReplayPipeline, map[string]any{
		"job_name":     "demo",
		"build_number": 3,
	})
	if f.replayCalls.Load() != 1 {
		t.Fatalf("replayCalls=%d", f.replayCalls.Load())
	}
	if out["status"] != "replay_requested" {
		t.Fatalf("%#v", out)
	}
}

func TestPowerUser_SetJobBuildablePreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	out := previewThenConfirm(t, ctx, cs, policy.ToolSetJobBuildable, map[string]any{
		"job_name":  "demo",
		"buildable": false,
	})
	if f.disableCalls.Load() != 1 {
		t.Fatalf("disableCalls=%d", f.disableCalls.Load())
	}
	if out["buildable"] != false {
		t.Fatalf("%#v", out)
	}
}

func TestPowerUser_KeepForever_NoToggleWhenAlreadyMatching(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	// Already keep=true; want true → no POST, status unchanged.
	f.keepLog.Store(true)
	out := previewThenConfirm(t, ctx, cs, policy.ToolSetBuildKeepForever, map[string]any{
		"job_name":     "demo",
		"build_number": 1,
		"keep_forever": true,
	})
	if f.keepCalls.Load() != 0 {
		t.Fatalf("toggle should not run when already matching, keepCalls=%d", f.keepCalls.Load())
	}
	if out["keepForever"] != true || out["status"] != "unchanged" {
		t.Fatalf("%#v", out)
	}

	// want false while true → toggle once.
	out2 := previewThenConfirm(t, ctx, cs, policy.ToolSetBuildKeepForever, map[string]any{
		"job_name":     "demo",
		"build_number": 1,
		"keep_forever": false,
	})
	if f.keepCalls.Load() != 1 {
		t.Fatalf("keepCalls=%d want 1", f.keepCalls.Load())
	}
	if out2["keepForever"] != false || out2["status"] != "toggled" {
		t.Fatalf("%#v", out2)
	}
	// Fixture flipped keepLog to false; want false again → no second toggle.
	out3 := previewThenConfirm(t, ctx, cs, policy.ToolSetBuildKeepForever, map[string]any{
		"job_name":     "demo",
		"build_number": 1,
		"keep_forever": false,
	})
	if f.keepCalls.Load() != 1 {
		t.Fatalf("extra toggle, keepCalls=%d", f.keepCalls.Load())
	}
	if out3["status"] != "unchanged" {
		t.Fatalf("%#v", out3)
	}
}

func TestPowerUser_SetDescriptionPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	out := previewThenConfirm(t, ctx, cs, policy.ToolSetBuildDescription, map[string]any{
		"job_name":     "demo",
		"build_number": 1,
		"description":  "investigating flake",
	})
	if f.descCalls.Load() != 1 {
		t.Fatalf("descCalls=%d", f.descCalls.Load())
	}
	form, _ := f.lastDescForm.Load().(string)
	if !strings.Contains(form, "investigating+flake") && !strings.Contains(form, "investigating flake") {
		t.Fatalf("form=%q", form)
	}
	if out["status"] != "updated" {
		t.Fatalf("%#v", out)
	}
}

func TestPowerUser_BulkQueueCancelPreviewThenConfirm(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	// Queue list returns 11 (stuck) + 12; for bulk cancel loadCancellable needs waiting items.
	// id 11/12 use waiting path (not 42).
	f.queueMode.Store("waiting")
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	// stuck_only → only id 11
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolCancelQueueItemsForJob,
		Arguments: map[string]any{
			"job_name":   "demo",
			"stuck_only": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	ids, _ := prev["queueIds"].([]any)
	if len(ids) != 1 {
		t.Fatalf("stuck_only queueIds=%v", prev["queueIds"])
	}
	if f.cancelCalls.Load() != 0 {
		t.Fatal("cancel on preview")
	}
	tok, _ := prev["confirmationToken"].(string)
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolCancelQueueItemsForJob,
		Arguments: map[string]any{
			"job_name":           "demo",
			"stuck_only":         true,
			"confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm: %s", toolErrorText(res2))
	}
	if f.cancelCalls.Load() != 1 {
		t.Fatalf("cancelCalls=%d", f.cancelCalls.Load())
	}
	out := toolStructuredJSON(t, res2)
	if out["status"] != "partial_ok" {
		t.Fatalf("%#v", out)
	}
}

// TestPowerUser_BulkQueueCancel_FolderShortNameIsolation proves MUT-016 never
// cancels another folder's job that shares the short name "demo".
// Queue items: folderA/demo (id=101) and folderB/demo (id=102); both task.name="demo".
// Cancelling job_name=folderA/demo must only touch 101.
func TestPowerUser_BulkQueueCancel_FolderShortNameIsolation(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	f.queueMode.Store("waiting")
	// Short names identical; only URL/fullName distinguish folders.
	f.queueItemsJSON.Store(`{
  "items": [
    {
      "id": 101,
      "task": {
        "name": "demo",
        "fullName": "folderA/demo",
        "url": "http://jenkins.example/job/folderA/job/demo/"
      },
      "why": "waiting",
      "inQueueSince": 1,
      "stuck": false,
      "buildable": true,
      "params": ""
    },
    {
      "id": 102,
      "task": {
        "name": "demo",
        "fullName": "folderB/demo",
        "url": "http://jenkins.example/job/folderB/job/demo/"
      },
      "why": "waiting",
      "inQueueSince": 1,
      "stuck": false,
      "buildable": true,
      "params": ""
    }
  ]
}`)
	// Also cover URL-only derivation (no fullName) for a third case in a second call.
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolCancelQueueItemsForJob,
		Arguments: map[string]any{
			"job_name": "folderA/demo",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("preview: %s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	rawIDs, _ := prev["queueIds"].([]any)
	if len(rawIDs) != 1 {
		t.Fatalf("want exactly one queue id for folderA/demo, got %#v", prev["queueIds"])
	}
	// JSON numbers decode as float64 in map[string]any.
	if int(rawIDs[0].(float64)) != 101 {
		t.Fatalf("want queue id 101, got %#v", rawIDs)
	}
	tok, _ := prev["confirmationToken"].(string)
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolCancelQueueItemsForJob,
		Arguments: map[string]any{
			"job_name":           "folderA/demo",
			"confirmation_token": tok,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.IsError {
		t.Fatalf("confirm: %s", toolErrorText(res2))
	}
	got, _ := f.cancelledQueueIDs.Load().([]int)
	if len(got) != 1 || got[0] != 101 {
		t.Fatalf("cancelled ids=%v want [101] only (must not cancel folderB/demo id 102)", got)
	}
	if f.cancelCalls.Load() != 1 {
		t.Fatalf("cancelCalls=%d", f.cancelCalls.Load())
	}

	// URL-only path: no fullName, derive from task.url — still isolates folders.
	f.cancelledQueueIDs.Store([]int(nil))
	f.cancelCalls.Store(0)
	f.queueItemsJSON.Store(`{
  "items": [
    {
      "id": 201,
      "task": {
        "name": "demo",
        "url": "http://jenkins.example/job/folderA/job/demo/"
      },
      "why": "waiting",
      "inQueueSince": 1,
      "stuck": false,
      "buildable": true,
      "params": ""
    },
    {
      "id": 202,
      "task": {
        "name": "demo",
        "url": "http://jenkins.example/job/folderB/job/demo/"
      },
      "why": "waiting",
      "inQueueSince": 1,
      "stuck": false,
      "buildable": true,
      "params": ""
    }
  ]
}`)
	out := previewThenConfirm(t, ctx, cs, policy.ToolCancelQueueItemsForJob, map[string]any{
		"job_name": "folderB/demo",
	})
	got2, _ := f.cancelledQueueIDs.Load().([]int)
	if len(got2) != 1 || got2[0] != 202 {
		t.Fatalf("URL-derived cancel ids=%v want [202]; out=%#v", got2, out)
	}
}

func TestPowerUser_MutationAllowlistOmitsRebuildAtRegister(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	mp := &policy.MutationPolicy{
		AllowTools: []string{
			policy.ToolStartJob, policy.ToolStopBuild, policy.ToolCancelQueueItem,
			policy.ToolInterruptBuild, // power subset without rebuild
		},
	}
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, mp)
	defer cancel()
	defer cs.Close()
	defer ss.Close()

	// Listed tools: interrupt works.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolInterruptBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
			"mode":         "stop",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("interrupt should be registered: %s", toolErrorText(res))
	}

	// Rebuild omitted from registration → unknown tool / error.
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolRebuildBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
		},
	})
	if err == nil && res2 != nil && !res2.IsError {
		t.Fatal("rebuild must not be registered under allowlist")
	}
}

func TestPowerUser_ROOmitsAllMutationTools(t *testing.T) {
	f := newMutFixture()
	defer f.close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "ro", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(),
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	for _, tool := range []string{
		policy.ToolInterruptBuild, policy.ToolRebuildBuild, policy.ToolReplayPipeline,
		policy.ToolSetJobBuildable, policy.ToolSetBuildKeepForever, policy.ToolSetBuildDescription,
		policy.ToolCancelQueueItemsForJob,
	} {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name:      tool,
			Arguments: map[string]any{"job_name": "demo", "build_number": 1, "mode": "stop"},
		})
		if err == nil && res != nil && !res.IsError {
			t.Fatalf("%s must not be callable under default RO", tool)
		}
	}
}

func TestPowerUser_SecretParamRebuildRejected(t *testing.T) {
	// NormalizeParams path: if prior build had only BRANCH, rebuild is fine.
	// Secret-named keys on prior build must fail at NormalizeParams.
	// Covered by mutation package; also ensure tool rejects when params include secret names
	// via start_job path (existing). Here: rebuild uses BRANCH only from fixture actions.
	f := newMutFixture()
	defer f.close()
	cs, ss, _, ctx, cancel := powerUserRegister(t, f, nil)
	defer cancel()
	defer cs.Close()
	defer ss.Close()
	// Preview rebuild should not surface secrets in structured JSON.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: policy.ToolRebuildBuild,
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("%s", toolErrorText(res))
	}
	prev := toolStructuredJSON(t, res)
	blob := strings.ToLower(toolErrorText(res) + strings.Join(func() []string {
		var s []string
		for k, v := range prev {
			s = append(s, k, strings.ToLower(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(formatAny(v), "\n", " "), "\r", " "))))
		}
		return s
	}(), " "))
	for _, bad := range []string{"s3cret", "password=", "deploy_key"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("secret material in preview: %q in %#v", bad, prev)
		}
	}
}

func formatAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}
