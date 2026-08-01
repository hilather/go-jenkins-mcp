package tools_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
)

// fakeMultiLog is a MultiLogAcquirer test double (status only; no bodies).
type fakeMultiLog struct {
	mu sync.Mutex

	// ByKey maps "job|build" → outcome for AcquireMulti.
	ByKey map[string]tools.MultiLogEntry
	// TotalBudget when >0 marks TruncatedBudget and forces later entries skipped.
	TotalBudget int64
	// Sessions stores collection membership for ResidualMembers.
	Sessions map[string][]tools.MultiLogRequest

	AcquireCalls int
	LastReqs     []tools.MultiLogRequest
}

func (f *fakeMultiLog) MultiLogAvailable() bool { return true }

func (f *fakeMultiLog) AcquireMulti(ctx context.Context, reqs []tools.MultiLogRequest) (tools.MultiLogCollection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return tools.MultiLogCollection{}, err
	}
	f.AcquireCalls++
	f.LastReqs = append([]tools.MultiLogRequest(nil), reqs...)

	collID := "coll-test-1"
	if f.Sessions == nil {
		f.Sessions = make(map[string][]tools.MultiLogRequest)
	}
	f.Sessions[collID] = append([]tools.MultiLogRequest(nil), reqs...)

	out := tools.MultiLogCollection{
		CollectionID: collID,
		Profile:      "corp",
		Logs:         make([]tools.MultiLogEntry, 0, len(reqs)),
	}
	var total int64
	for i, r := range reqs {
		key := r.Job + "|" + itoaBuild(r.Build)
		e, ok := f.ByKey[key]
		if !ok {
			e = tools.MultiLogEntry{
				Job: r.Job, Build: r.Build, Relation: r.Relation,
				Status: tools.MirrorStatusSealed, Generation: 1, DurableBytes: 10, BytesFetched: 10,
			}
		}
		e.Job = r.Job
		e.Build = r.Build
		if e.Relation == "" {
			e.Relation = r.Relation
		}
		if f.TotalBudget > 0 && total >= f.TotalBudget {
			e.Status = tools.MirrorStatusSkipped
			e.ErrorCode = string(apperr.CodeQuota)
			e.BytesFetched = 0
			e.Residual = true
			out.TruncatedBudget = true
		} else {
			total += e.BytesFetched
			if f.TotalBudget > 0 && total > f.TotalBudget {
				out.TruncatedBudget = true
			}
		}
		// Deterministic: first entries win budget in request order.
		_ = i
		out.Logs = append(out.Logs, e)
	}
	out.TotalBytes = total
	if out.TruncatedBudget {
		// Count skipped.
		for _, e := range out.Logs {
			if e.Status == tools.MirrorStatusSkipped {
				// ok
			}
		}
	}
	return out, nil
}

func (f *fakeMultiLog) ResidualMembers(ctx context.Context, collectionID string) ([]tools.MultiLogRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	members, ok := f.Sessions[collectionID]
	if !ok {
		return nil, apperr.New(apperr.CodeNotFound, "collection not found")
	}
	// Residual = non-sealed from last known ByKey status.
	var out []tools.MultiLogRequest
	for _, m := range members {
		key := m.Job + "|" + itoaBuild(m.Build)
		e, ok := f.ByKey[key]
		if !ok || e.Status != tools.MirrorStatusSealed {
			out = append(out, m)
		}
	}
	return out, nil
}

func itoaBuild(n int64) string {
	return strconv.FormatInt(n, 10)
}

func TestMirrorLogs_KnownSeedTool(t *testing.T) {
	if !policy.IsKnownSeedTool(tools.ToolMirrorLogs) {
		t.Fatalf("%s must be in policy.knownSeedTools for RBAC strict mode", tools.ToolMirrorLogs)
	}
}

func TestMirrorLogs_NotRegisteredWithoutMultiLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Logs without MultiLogAcquirer → tool omitted.
	got := listToolNames(t, ctx, &tools.RegisterOptions{
		Logs: &fakeLogAccess{Body: "x", Sealed: true},
	})
	if _, ok := got[tools.ToolMirrorLogs]; ok {
		t.Fatalf("%s must not register without MultiLogAcquirer", tools.ToolMirrorLogs)
	}

	// Nil Logs → omitted.
	got2 := listToolNames(t, ctx, &tools.RegisterOptions{})
	if _, ok := got2[tools.ToolMirrorLogs]; ok {
		t.Fatalf("%s must not register when Logs nil", tools.ToolMirrorLogs)
	}
}

func TestMirrorLogs_SmokeListWhenMultiLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := listToolNames(t, ctx, &tools.RegisterOptions{
		MultiLog: &fakeMultiLog{},
	})
	if _, ok := got[tools.ToolMirrorLogs]; !ok {
		t.Fatalf("missing registered tool %q", tools.ToolMirrorLogs)
	}
}

func TestMirrorLogs_MultiJobFixture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeMultiLog{
		ByKey: map[string]tools.MultiLogEntry{
			"job-a|1": {
				Status: tools.MirrorStatusSealed, Generation: 2,
				BytesFetched: 100, DurableBytes: 100,
			},
			"job-b|2": {
				Status: tools.MirrorStatusMirrored, Generation: 1,
				BytesFetched: 50, DurableBytes: 50, Residual: true,
			},
		},
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-multi", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{MultiLog: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "job-a", "build_number": 1, "relation": "primary"},
				map[string]any{"job_name": "job-b", "build_number": 2, "relation": "related"},
				map[string]any{"job_name": "job-a", "build_number": 1}, // dedup
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	if payload["collection_id"] == "" {
		t.Fatalf("expected collection_id: %v", payload)
	}
	// Never return full log bodies.
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), `"logs":"")`) {
		// n/a
	}
	if _, hasBody := payload["body"]; hasBody {
		t.Fatal("must not include log body field")
	}
	logs, ok := payload["logs"].([]any)
	if !ok || len(logs) != 2 {
		t.Fatalf("want 2 deduped log rows, got %v", payload["logs"])
	}
	// Check statuses present without bodies.
	for _, row := range logs {
		m, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("row type %T", row)
		}
		if m["status"] == "" {
			t.Fatalf("missing status: %v", m)
		}
		if _, has := m["log_text"]; has {
			t.Fatal("must not return log_text")
		}
		if _, has := m["content"]; has {
			t.Fatal("must not return content")
		}
	}
	if fake.AcquireCalls != 1 {
		t.Fatalf("AcquireCalls=%d", fake.AcquireCalls)
	}
	if len(fake.LastReqs) != 2 {
		t.Fatalf("LastReqs len=%d want 2 (dedup)", len(fake.LastReqs))
	}
}

func TestMirrorLogs_DenyOneJobPerLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeMultiLog{
		ByKey: map[string]tools.MultiLogEntry{
			"public/job|1": {
				Status: tools.MirrorStatusSealed, Generation: 1,
				BytesFetched: 20, DurableBytes: 20,
			},
		},
	}
	doc := policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret"},
	}
	ev := policy.NewDenyOnlyEvaluator(doc)
	subject := policy.NewSubject("corp", "alice", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-deny", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		MultiLog: fake,
		Policy:   ev,
		Subject:  subject,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "public/job", "build_number": 1},
				map[string]any{"job_name": "secret/job", "build_number": 9},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("partial deny should not fail whole tool: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	logs, ok := payload["logs"].([]any)
	if !ok || len(logs) != 2 {
		t.Fatalf("want 2 rows (one denied, one sealed), got %v", payload["logs"])
	}
	var sawDenied, sawSealed bool
	for _, row := range logs {
		m := row.(map[string]any)
		job, _ := m["job_name"].(string)
		status, _ := m["status"].(string)
		code, _ := m["error_code"].(string)
		switch {
		case strings.HasPrefix(job, "secret"):
			if status != tools.MirrorStatusDenied {
				t.Fatalf("secret job status=%q want denied", status)
			}
			if code != string(apperr.CodePolicyDenial) {
				t.Fatalf("error_code=%q", code)
			}
			sawDenied = true
		case job == "public/job":
			if status != tools.MirrorStatusSealed {
				t.Fatalf("public status=%q", status)
			}
			sawSealed = true
		}
	}
	if !sawDenied || !sawSealed {
		t.Fatalf("sawDenied=%v sawSealed=%v payload=%v", sawDenied, sawSealed, payload)
	}
	// Denied job must never reach AcquireMulti.
	for _, r := range fake.LastReqs {
		if strings.HasPrefix(r.Job, "secret") {
			t.Fatalf("denied job must not be acquired: %+v", r)
		}
	}
	if len(fake.LastReqs) != 1 {
		t.Fatalf("LastReqs=%v want only public", fake.LastReqs)
	}
}

func TestMirrorLogs_BudgetTruncate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fake := &fakeMultiLog{
		TotalBudget: 30,
		ByKey: map[string]tools.MultiLogEntry{
			"a|1": {Status: tools.MirrorStatusSealed, BytesFetched: 20, DurableBytes: 20, Generation: 1},
			"b|1": {Status: tools.MirrorStatusSealed, BytesFetched: 20, DurableBytes: 20, Generation: 1},
			"c|1": {Status: tools.MirrorStatusSealed, BytesFetched: 20, DurableBytes: 20, Generation: 1},
		},
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-budget", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{MultiLog: fake})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "a", "build_number": 1},
				map[string]any{"job_name": "b", "build_number": 1},
				map[string]any{"job_name": "c", "build_number": 1},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	if truncated, _ := payload["truncated_budget"].(bool); !truncated {
		t.Fatalf("expected truncated_budget true: %v", payload)
	}
	logs, _ := payload["logs"].([]any)
	var skipped int
	for _, row := range logs {
		m := row.(map[string]any)
		if m["status"] == tools.MirrorStatusSkipped {
			skipped++
			if m["error_code"] != string(apperr.CodeQuota) {
				t.Fatalf("skipped error_code=%v", m["error_code"])
			}
		}
	}
	if skipped < 1 {
		t.Fatalf("expected at least one skipped log under budget, payload=%v", payload)
	}
	// Residuals note continue path.
	residuals, _ := payload["residuals"].([]any)
	if len(residuals) == 0 {
		t.Fatalf("expected residual notes for budget truncate: %v", payload)
	}
}

func TestMirrorLogs_IntegrationCoordinator(t *testing.T) {
	// End-to-end with real Coordinator + FakeSource (multi-job mirror fixture).
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	fr.TargetBytes = 64
	fr.MaxBytes = 256
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}

	srcA := &logmirror.FakeSource{Running: false}
	srcA.SetLog([]byte(strings.Repeat("A", 80)))
	srcB := &logmirror.FakeSource{Running: false}
	srcB.SetLog([]byte(strings.Repeat("B", 60)))
	route := &routeSource{byJob: map[string]*logmirror.FakeSource{
		"job-a": srcA,
		"job-b": srcB,
	}}

	machine := logmirror.NewMachine(meta, route)
	machine.Frames = fr
	machine.Reader = reader
	machine.FetchBytes = 32
	status := logmirror.NewFakeBuildStatus()
	status.Set("job-a", 1, true)
	status.Set("job-b", 2, true)

	coord := logmirror.NewCoordinator("corp", machine, logmirror.CollectionBounds{
		MaxConcurrency: 2,
		MaxTotalBytes:  1 << 20,
		MaxPerLogBytes: 1 << 20,
		MaxPollsPerLog: 64,
	})
	coord.Status = status
	coord.Catalog = meta

	access := logmirror.NewAccess("corp", machine)
	access.Status = status
	mla := tools.NewMirrorLogAccess(access).WithCoordinator(coord)

	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-int", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: mla})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	// Smoke: tool listed via LogAccess extension.
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, tool := range list.Tools {
		if tool != nil && tool.Name == tools.ToolMirrorLogs {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("jenkins_mirror_logs not listed with Coord-wired MirrorLogAccess")
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolMirrorLogs,
		Arguments: map[string]any{
			"logs": []any{
				map[string]any{"job_name": "job-a", "build_number": 1},
				map[string]any{"job_name": "job-b", "build_number": 2},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	if payload["collection_id"] == "" {
		t.Fatalf("missing collection_id: %v", payload)
	}
	logs, ok := payload["logs"].([]any)
	if !ok || len(logs) != 2 {
		t.Fatalf("logs=%v", payload["logs"])
	}
	for _, row := range logs {
		m := row.(map[string]any)
		st, _ := m["status"].(string)
		if st != tools.MirrorStatusSealed && st != tools.MirrorStatusMirrored {
			t.Fatalf("unexpected status %q row=%v", st, m)
		}
		// No body text keys.
		for _, bad := range []string{"logs", "log_text", "body", "content", "text"} {
			if v, has := m[bad]; has {
				if s, ok := v.(string); ok && len(s) > 32 {
					t.Fatalf("must not return log body in %q", bad)
				}
			}
		}
	}
}

// Regression: collection_id residual continue after process restart using store only.
func TestMirrorLogs_ContinueAfterRestartUsingStore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	fr.TargetBytes = 64
	fr.MaxBytes = 256
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}

	// Sealed + residual (running) so collection_id continue has work after restart.
	srcA := &logmirror.FakeSource{Running: false}
	srcA.SetLog([]byte(strings.Repeat("A", 80)))
	srcB := &logmirror.FakeSource{Running: true}
	srcB.SetLog([]byte(strings.Repeat("B", 40)))
	route := &routeSource{byJob: map[string]*logmirror.FakeSource{
		"job-a": srcA,
		"job-b": srcB,
	}}

	machine := logmirror.NewMachine(meta, route)
	machine.Frames = fr
	machine.Reader = reader
	machine.FetchBytes = 32
	status := logmirror.NewFakeBuildStatus()
	status.Set("job-a", 1, true)
	status.Set("job-b", 2, false)

	coord1 := logmirror.NewCoordinator("corp", machine, logmirror.CollectionBounds{
		MaxConcurrency: 2,
		MaxTotalBytes:  1 << 20,
		MaxPerLogBytes: 1 << 20,
		MaxPollsPerLog: 32,
	})
	coord1.Status = status
	coord1.Catalog = meta
	access1 := logmirror.NewAccess("corp", machine)
	access1.Status = status
	mla1 := tools.NewMirrorLogAccess(access1).WithCoordinator(coord1)

	// First acquire (process "before restart").
	coll, err := mla1.AcquireMulti(ctx, []tools.MultiLogRequest{
		{Job: "job-a", Build: 1, Relation: "primary"},
		{Job: "job-b", Build: 2, Relation: "downstream"},
	})
	if err != nil {
		t.Fatalf("AcquireMulti: %v", err)
	}
	if coll.CollectionID == "" {
		t.Fatal("empty collection_id")
	}
	// Durable catalog must hold membership independent of in-process map.
	members, err := meta.ListMembers(ctx, coll.CollectionID, "corp")
	if err != nil || len(members) != 2 {
		t.Fatalf("catalog members: err=%v n=%d", err, len(members))
	}

	// Restart simulation: brand-new Coordinator (empty collections map), same Meta.
	coord2 := logmirror.NewCoordinator("corp", machine, logmirror.CollectionBounds{
		MaxConcurrency: 2,
		MaxTotalBytes:  1 << 20,
		MaxPerLogBytes: 1 << 20,
		MaxPollsPerLog: 32,
	})
	coord2.Status = status
	coord2.Catalog = meta
	access2 := logmirror.NewAccess("corp", machine)
	access2.Status = status
	mla2 := tools.NewMirrorLogAccess(access2).WithCoordinator(coord2)

	// ResidualMembers must work from store only (no in-process session on coord2).
	residuals, err := mla2.ResidualMembers(ctx, coll.CollectionID)
	if err != nil {
		t.Fatalf("ResidualMembers after restart: %v", err)
	}
	if len(residuals) != 1 || residuals[0].Job != "job-b" {
		t.Fatalf("residuals after restart: %+v", residuals)
	}
	if residuals[0].Relation != "downstream" {
		t.Fatalf("relation lost: %+v", residuals[0])
	}

	// Tool path: continue with collection_id only (store-backed residual merge).
	// Seal job-b so continue can complete.
	srcB.Running = false
	status.Set("job-b", 2, true)

	server := mcp.NewServer(&mcp.Implementation{Name: "mirror-restart", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{Logs: mla2})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolMirrorLogs,
		Arguments: map[string]any{
			"collection_id": coll.CollectionID,
		},
	})
	if err != nil {
		t.Fatalf("CallTool continue: %v", err)
	}
	if res.IsError {
		t.Fatalf("continue tool error: %+v", res)
	}
	payload := toolStructuredJSON(t, res)
	logs, ok := payload["logs"].([]any)
	if !ok || len(logs) < 1 {
		t.Fatalf("continue logs: %v", payload["logs"])
	}
	// At least job-b re-acquired; status should be sealed or mirrored.
	var sawB bool
	for _, row := range logs {
		m := row.(map[string]any)
		if m["job_name"] == "job-b" {
			sawB = true
			st, _ := m["status"].(string)
			if st != tools.MirrorStatusSealed && st != tools.MirrorStatusMirrored {
				t.Fatalf("job-b status after continue: %q", st)
			}
		}
	}
	if !sawB {
		t.Fatalf("expected job-b in continue response: %v", payload)
	}
	// Never return log bodies.
	raw, _ := json.Marshal(payload)
	if strings.Contains(string(raw), strings.Repeat("B", 40)) {
		t.Fatal("must not embed log body in tool response")
	}
}

// routeSource dispatches progressive fetches by job name.
type routeSource struct {
	byJob map[string]*logmirror.FakeSource
}

func (r *routeSource) Fetch(ctx context.Context, job string, build int64, startOffset int64, maxBytes int) (
	data []byte, reportedNext int64, moreData bool, err error,
) {
	s := r.byJob[job]
	if s == nil {
		return nil, startOffset, false, apperr.New(apperr.CodeNotFound, "unknown job in test source")
	}
	return s.Fetch(ctx, job, build, startOffset, maxBytes)
}
