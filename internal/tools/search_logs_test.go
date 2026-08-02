package tools_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/search"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

func TestSearchLogsTool_RegistrationOptional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Without LogSearch: tool absent (default pilot Register).
	names := listToolNames(t, ctx, nil)
	if _, ok := names[tools.ToolSearchLogs]; ok {
		t.Fatal("jenkins_search_logs must not register without LogSearch")
	}

	// With LogSearch: tool present.
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	eng, err := search.New(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	names2 := listToolNames(t, ctx, &tools.RegisterOptions{LogSearch: eng})
	if _, ok := names2[tools.ToolSearchLogs]; !ok {
		t.Fatalf("expected %s in registered tools", tools.ToolSearchLogs)
	}
}

func TestSearchLogsTool_EndToEndLibrary(t *testing.T) {
	ctx := context.Background()
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
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	g := &store.LogGeneration{Profile: "corp", Job: "demo", Build: 1, Generation: 1}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Append(ctx, g.ID, []byte("alpha ERROR beta\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	eng, err := search.New(meta, dir)
	if err != nil {
		t.Fatal(err)
	}

	res, err := eng.Search(ctx, search.Query{
		Profile: "corp", Job: "demo", Build: 1,
		Pattern: "ERROR", CaseSensitive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches: %d", len(res.Matches))
	}
}

// searchFixture builds a local L1 store with two jobs for policy tests.
func searchFixture(t *testing.T) (eng *search.Engine, secretGenID, publicGenID int64) {
	t.Helper()
	ctx := context.Background()
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
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(ctx); err != nil {
		t.Fatal(err)
	}

	secret := &store.LogGeneration{Profile: "corp", Job: "secret-folder/job-a", Build: 1, Generation: 1}
	if err := meta.InsertGeneration(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Append(ctx, secret.ID, []byte("SECRET_TOKEN error in denied job\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, secret.ID); err != nil {
		t.Fatal(err)
	}

	public := &store.LogGeneration{Profile: "corp", Job: "public/job", Build: 2, Generation: 1}
	if err := meta.InsertGeneration(ctx, public); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Append(ctx, public.ID, []byte("PUBLIC_OK error in allowed job\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, public.ID); err != nil {
		t.Fatal(err)
	}

	eng, err = search.New(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	return eng, secret.ID, public.ID
}

// countingSearch wraps LogSearch to prove Search is not invoked on policy deny.
type countingSearch struct {
	inner *search.Engine
	calls atomic.Int64
}

func (c *countingSearch) Search(ctx context.Context, q search.Query) (search.Result, error) {
	c.calls.Add(1)
	return c.inner.Search(ctx, q)
}

func (c *countingSearch) Resolve(ctx context.Context, q search.Query) (search.Scope, error) {
	return c.inner.Resolve(ctx, q)
}

// Wave 19: deny_job_prefixes blocks job_name path (middleware) and generation_id
// path (handler resolve + re-eval) without scanning frames; other job succeeds.
func TestSearchLogsTool_JobPolicyDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	eng, secretGenID, publicGenID := searchFixture(t)
	counter := &countingSearch{inner: eng}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder"},
	})
	subj := policy.NewSubject("corp", "alice", true)
	opts := &tools.RegisterOptions{
		LogSearch: counter,
		Policy:    ev,
		Subject:   subj,
		ProfileID: "corp",
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "search-pol", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, opts)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	// --- job_name denied (middleware Target) ---
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"profile":      "corp",
			"job_name":     "secret-folder/job-a",
			"build_number": 1,
			"pattern":      "error",
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want job policy deny for secret job_name, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(text, string(apperr.CodePolicyDenial)) &&
		!strings.Contains(strings.ToLower(text), "denied") {
		t.Fatalf("expected policy denial, got %q", text)
	}
	if strings.Contains(text, "SECRET_TOKEN") {
		t.Fatal("secret log content leaked in denial")
	}
	if counter.calls.Load() != 0 {
		t.Fatalf("Search must not run on denied job_name (calls=%d)", counter.calls.Load())
	}

	// --- job_name allowed ---
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"profile":      "corp",
			"job_name":     "public/job",
			"build_number": 2,
			"pattern":      "error",
		},
	})
	if err != nil {
		t.Fatalf("transport ok: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want allow for public job, got %#v text=%q", resOK, toolErrorText(resOK))
	}
	payload := toolStructuredJSON(t, resOK)
	if job, _ := payload["job"].(string); job != "public/job" {
		t.Fatalf("job=%v", payload["job"])
	}
	matches, _ := payload["matches"].([]any)
	if len(matches) < 1 {
		t.Fatalf("expected matches for public job: %v", payload)
	}
	if counter.calls.Load() != 1 {
		t.Fatalf("Search calls=%d want 1 after public job", counter.calls.Load())
	}

	// --- generation_id for denied job (handler resolve; Target empty at middleware) ---
	before := counter.calls.Load()
	resGen, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"generation_id": secretGenID,
			"pattern":       "error",
		},
	})
	if err != nil {
		t.Fatalf("transport gen: %v", err)
	}
	if resGen == nil || !resGen.IsError {
		t.Fatalf("want policy deny for generation of secret job, got %#v", resGen)
	}
	genText := toolErrorText(resGen)
	if !strings.Contains(genText, string(apperr.CodePolicyDenial)) &&
		!strings.Contains(strings.ToLower(genText), "denied") {
		t.Fatalf("expected policy denial for generation_id, got %q", genText)
	}
	if strings.Contains(genText, "SECRET_TOKEN") {
		t.Fatal("secret leaked on generation_id deny")
	}
	if counter.calls.Load() != before {
		t.Fatalf("Search must not run on denied generation_id (before=%d after=%d)",
			before, counter.calls.Load())
	}

	// --- generation_id for allowed job ---
	resGenOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"generation_id": publicGenID,
			"pattern":       "PUBLIC_OK",
		},
	})
	if err != nil {
		t.Fatalf("transport gen ok: %v", err)
	}
	if resGenOK == nil || resGenOK.IsError {
		t.Fatalf("want allow for public generation, got %#v text=%q", resGenOK, toolErrorText(resGenOK))
	}
	if counter.calls.Load() != before+1 {
		t.Fatalf("Search calls=%d want %d", counter.calls.Load(), before+1)
	}

	// --- smuggle: generation_id of secret + public job_name must still deny ---
	// (engine prefers generation_id; handler must re-resolve job from generation)
	before = counter.calls.Load()
	resSmuggle, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"generation_id": secretGenID,
			"job_name":      "public/job",
			"build_number":  2,
			"profile":       "corp",
			"pattern":       "error",
		},
	})
	if err != nil {
		t.Fatalf("transport smuggle: %v", err)
	}
	if resSmuggle == nil || !resSmuggle.IsError {
		t.Fatalf("want deny when generation belongs to denied job despite public job_name, got %#v", resSmuggle)
	}
	if counter.calls.Load() != before {
		t.Fatalf("Search must not run on smuggled generation (calls delta=%d)",
			counter.calls.Load()-before)
	}
}

// Wave 33: CheckStoreRead (store_cached_read deny_tools) is distinct from
// deny_job_prefixes — tool Evaluate for jenkins_search_logs may allow while the
// store PEP denies. Search must not open frames.
func TestSearchLogsTool_CheckStoreReadDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	eng, secretGenID, publicGenID := searchFixture(t)
	counter := &countingSearch{inner: eng}

	// Deny only the synthetic store action — not jenkins_search_logs and not
	// any job prefix — so tool Evaluate allows and CheckStoreRead is the PEP
	// that must fail closed.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			policy.StoreReadAction: {},
		},
	})
	subj := policy.NewSubject("corp", "alice", true)
	opts := &tools.RegisterOptions{
		LogSearch: counter,
		Policy:    ev,
		Subject:   subj,
		ProfileID: "corp",
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "search-store-pep", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, opts)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	// job_name path: store PEP denies; no Search/frame scan.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"profile":      "corp",
			"job_name":     "public/job",
			"build_number": 2,
			"pattern":      "error",
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want CheckStoreRead deny for job_name, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(text, string(apperr.CodePolicyDenial)) &&
		!strings.Contains(strings.ToLower(text), "denied") {
		t.Fatalf("expected policy denial from store PEP, got %q", text)
	}
	if strings.Contains(text, "PUBLIC_OK") || strings.Contains(text, "SECRET_TOKEN") {
		t.Fatal("log content leaked in store PEP denial")
	}
	if counter.calls.Load() != 0 {
		t.Fatalf("Regression: Search must not run when CheckStoreRead denies (calls=%d)",
			counter.calls.Load())
	}

	// generation_id for previously-allowed job: still store PEP deny, no frame scan.
	before := counter.calls.Load()
	resGen, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"generation_id": publicGenID,
			"pattern":       "PUBLIC_OK",
		},
	})
	if err != nil {
		t.Fatalf("transport gen: %v", err)
	}
	if resGen == nil || !resGen.IsError {
		t.Fatalf("want CheckStoreRead deny for generation_id, got %#v", resGen)
	}
	genText := toolErrorText(resGen)
	if strings.Contains(genText, "PUBLIC_OK") || strings.Contains(genText, "SECRET_TOKEN") {
		t.Fatal("log content leaked on generation_id store deny")
	}
	if counter.calls.Load() != before {
		t.Fatalf("Regression: Search must not run on generation_id when store PEP denies (before=%d after=%d)",
			before, counter.calls.Load())
	}

	// generation_id for secret job under store_cached_read deny: same fail-closed.
	before = counter.calls.Load()
	resSecret, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"generation_id": secretGenID,
			"pattern":       "error",
		},
	})
	if err != nil {
		t.Fatalf("transport secret gen: %v", err)
	}
	if resSecret == nil || !resSecret.IsError {
		t.Fatalf("want store PEP deny for secret generation, got %#v", resSecret)
	}
	if counter.calls.Load() != before {
		t.Fatalf("Search must not run on secret generation under store deny (delta=%d)",
			counter.calls.Load()-before)
	}
}

// Wave 33: fail closed when tool Evaluate allows but store PEP would deny via
// job prefix alone is already covered by JobPolicyDeny; this covers disagreement
// where only store_cached_read is denied (above). Also assert allow still works
// when store PEP is open.
func TestSearchLogsTool_CheckStoreReadAllowStillSearches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	eng, _, publicGenID := searchFixture(t)
	counter := &countingSearch{inner: eng}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret-folder"},
	})
	subj := policy.NewSubject("corp", "alice", true)
	opts := &tools.RegisterOptions{
		LogSearch: counter,
		Policy:    ev,
		Subject:   subj,
		ProfileID: "corp",
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "search-store-allow", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, opts)
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolSearchLogs,
		Arguments: map[string]any{
			"generation_id": publicGenID,
			"pattern":       "PUBLIC_OK",
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("want allow when tool + store PEP open, got %#v text=%q", res, toolErrorText(res))
	}
	if counter.calls.Load() != 1 {
		t.Fatalf("Search calls=%d want 1", counter.calls.Load())
	}
	payload := toolStructuredJSON(t, res)
	matches, _ := payload["matches"].([]any)
	if len(matches) < 1 {
		t.Fatalf("expected matches: %v", payload)
	}
}
