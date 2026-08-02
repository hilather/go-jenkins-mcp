package tools_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestFilterDeniedArtifacts_Unit(t *testing.T) {
	arts := []jenkins.ArtifactMeta{
		{Path: "reports/out.txt", FileName: "out.txt"},
		{Path: "secrets/creds.txt", FileName: "creds.txt"},
		{Path: "dist/app.jar", FileName: "app.jar"},
		{Path: "key.pem", FileName: "key.pem"},
		{Path: "exact/./creds.txt", FileName: "creds.txt"}, // dot form
	}
	kept, omitted := tools.FilterDeniedArtifacts([]string{"secrets/**", "*.pem", "exact/creds.txt"}, arts)
	if omitted != 3 {
		t.Fatalf("omitted=%d want 3 (secrets/**, *.pem, exact after clean)", omitted)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d want 2: %+v", len(kept), kept)
	}
	if kept[0].Path != "reports/out.txt" || kept[1].Path != "dist/app.jar" {
		t.Fatalf("kept paths: %q %q", kept[0].Path, kept[1].Path)
	}
	// Empty patterns: keep all (shallow copy).
	keptAll, om0 := tools.FilterDeniedArtifacts(nil, arts)
	if om0 != 0 || len(keptAll) != 5 {
		t.Fatalf("empty patterns: kept=%d omitted=%d", len(keptAll), om0)
	}
	// Nil input + empty patterns.
	nilKept, omNil := tools.FilterDeniedArtifacts(nil, nil)
	if nilKept != nil || omNil != 0 {
		t.Fatalf("nil arts empty patterns: kept=%v omitted=%d", nilKept, omNil)
	}
	// Exact only.
	keptExact, omExact := tools.FilterDeniedArtifacts([]string{"exact/creds.txt"}, []jenkins.ArtifactMeta{
		{Path: "exact/creds.txt"},
		{Path: "exact/other.txt"},
		{Path: "exact/./creds.txt"},
	})
	if omExact != 2 || len(keptExact) != 1 || keptExact[0].Path != "exact/other.txt" {
		t.Fatalf("exact+dot: kept=%+v omitted=%d", keptExact, omExact)
	}
	// Glob folder children.
	keptGlob, omGlob := tools.FilterDeniedArtifacts([]string{"secrets/**"}, []jenkins.ArtifactMeta{
		{Path: "secrets/a/b.txt"},
		{Path: "not-secrets/a.txt"},
	})
	if omGlob != 1 || len(keptGlob) != 1 || keptGlob[0].Path != "not-secrets/a.txt" {
		t.Fatalf("glob: kept=%+v omitted=%d", keptGlob, omGlob)
	}
}

// Wave 39: unit filter for compare_builds artifact path diffs.
func TestFilterDeniedArtifactDiffs_Unit(t *testing.T) {
	diffs := []tools.CompareArtifactDiff{
		{Path: "reports/out.txt", Side: "only_a"},
		{Path: "secrets/creds.txt", Side: "only_b"},
		{Path: "dist/app.jar", Side: "only_a"},
		{Path: "key.pem", Side: "only_b"},
		{Path: "exact/./creds.txt", Side: "only_a"},
	}
	kept, omitted := tools.FilterDeniedArtifactDiffs([]string{"secrets/**", "*.pem", "exact/creds.txt"}, diffs)
	if omitted != 3 {
		t.Fatalf("omitted=%d want 3", omitted)
	}
	if len(kept) != 2 {
		t.Fatalf("kept=%d want 2: %+v", len(kept), kept)
	}
	if kept[0].Path != "reports/out.txt" || kept[1].Path != "dist/app.jar" {
		t.Fatalf("kept: %+v", kept)
	}
	// Empty patterns: unchanged shallow copy.
	all, om0 := tools.FilterDeniedArtifactDiffs(nil, diffs)
	if om0 != 0 || len(all) != 5 {
		t.Fatalf("empty patterns: kept=%d omitted=%d", len(all), om0)
	}
	nilKept, omNil := tools.FilterDeniedArtifactDiffs(nil, nil)
	if nilKept != nil || omNil != 0 {
		t.Fatalf("nil diffs: kept=%v omitted=%d", nilKept, omNil)
	}
}

// Wave 39: compare_builds omits deny_artifact_paths from artifact_path_diffs.
func TestCompareBuilds_ArtifactPathPolicyFilter_OmitsDenied(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	// Build 10 (A): allowed report + denied secret path only on A.
	// Build 9 (B): allowed log + denied pem only on B; shared log.txt on both would cancel.
	f.mu.Lock()
	f.artifacts["job/demo/10"] = []map[string]any{
		{"relativePath": "reports/out.txt", "fileName": "out.txt"},
		{"relativePath": "secrets/creds.txt", "fileName": "creds.txt"},
		{"relativePath": "log.txt", "fileName": "log.txt"},
	}
	f.artifacts["job/demo/9"] = []map[string]any{
		{"relativePath": "log.txt", "fileName": "log.txt"},
		{"relativePath": "key.pem", "fileName": "key.pem"},
		{"relativePath": "dist/app.jar", "fileName": "app.jar"},
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-art-filter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}

	raw, _ := json.Marshal(res.StructuredContent)
	// Denied paths must never appear in model-facing payload.
	if strings.Contains(string(raw), "secrets/creds") || strings.Contains(string(raw), "key.pem") {
		t.Fatalf("denied path leaked in compare response: %s", raw)
	}
	// Canary: no secret-looking content from fixture params either still stripped.
	if strings.Contains(string(raw), "super-secret") || strings.Contains(string(raw), "another-secret") {
		t.Fatalf("secret leaked: %s", raw)
	}

	var out tools.CompareBuildsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v raw=%s", err, raw)
	}
	// Allowed path diffs remain: reports/out.txt only_a, dist/app.jar only_b.
	if len(out.ArtifactPathDiffs) != 2 {
		t.Fatalf("want 2 allowed artifact diffs, got %d: %+v raw=%s", len(out.ArtifactPathDiffs), out.ArtifactPathDiffs, raw)
	}
	paths := map[string]string{}
	for _, d := range out.ArtifactPathDiffs {
		paths[d.Path] = d.Side
		if strings.HasPrefix(d.Path, "secrets/") || strings.HasSuffix(d.Path, ".pem") {
			t.Fatalf("denied path in diffs: %+v", d)
		}
	}
	if paths["reports/out.txt"] != "only_a" {
		t.Fatalf("reports/out.txt side=%q want only_a paths=%v", paths["reports/out.txt"], paths)
	}
	if paths["dist/app.jar"] != "only_b" {
		t.Fatalf("dist/app.jar side=%q want only_b paths=%v", paths["dist/app.jar"], paths)
	}
	if !out.ArtifactsPolicyFiltered {
		t.Fatalf("artifacts_policy_filtered want true: %s", raw)
	}
	if out.ArtifactsPolicyOmittedCount != 2 {
		t.Fatalf("artifacts_policy_omitted_count=%d want 2 raw=%s", out.ArtifactsPolicyOmittedCount, raw)
	}
	// Confidence note is integer-only (no denied path strings).
	var sawOmitNote bool
	for _, n := range out.ConfidenceNotes {
		if strings.Contains(n, "deny_artifact_paths") && strings.Contains(n, "2") {
			sawOmitNote = true
		}
		if strings.Contains(n, "secrets/") || strings.Contains(n, "key.pem") {
			t.Fatalf("denied path in confidence note: %q", n)
		}
	}
	if !sawOmitNote {
		t.Fatalf("expected omit note in confidence_notes: %v", out.ConfidenceNotes)
	}
}

// Wave 39: empty deny_artifact_paths → full diffs, no policy flags.
func TestCompareBuilds_ArtifactPathPolicyFilter_EmptyPatternsUnchanged(t *testing.T) {
	f := newDiagFixture()
	defer f.close()
	f.mu.Lock()
	f.artifacts["job/demo/10"] = []map[string]any{
		{"relativePath": "reports/out.txt", "fileName": "out.txt"},
		{"relativePath": "secrets/creds.txt", "fileName": "creds.txt"},
	}
	f.artifacts["job/demo/9"] = []map[string]any{
		{"relativePath": "log.txt", "fileName": "log.txt"},
	}
	f.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Policy present but empty DenyArtifactPaths.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "cmp-art-nofilter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})
	cs, ss := connectMCP(t, ctx, server)
	defer cs.Close()
	defer ss.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: tools.ToolCompareBuilds,
		Arguments: map[string]any{
			"job_name": "demo",
			"build_a":  10,
			"build_b":  9,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out tools.CompareBuildsToolResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	// Without deny patterns all three unique paths appear.
	if len(out.ArtifactPathDiffs) != 3 {
		t.Fatalf("want 3 path diffs, got %d: %+v raw=%s", len(out.ArtifactPathDiffs), out.ArtifactPathDiffs, raw)
	}
	sawSecret := false
	for _, d := range out.ArtifactPathDiffs {
		if d.Path == "secrets/creds.txt" {
			sawSecret = true
		}
	}
	if !sawSecret {
		t.Fatalf("empty policy must surface secrets path in diffs: %+v", out.ArtifactPathDiffs)
	}
	if out.ArtifactsPolicyFiltered || out.ArtifactsPolicyOmittedCount != 0 {
		t.Fatalf("no filter flags expected: filtered=%v omitted=%d", out.ArtifactsPolicyFiltered, out.ArtifactsPolicyOmittedCount)
	}
}

// artifactFixture serves list JSON and optional artifact downloads with hit counters.
type artifactFixture struct {
	srv            *httptest.Server
	listBody       string
	listHits       atomic.Int32
	artifactHits   atomic.Int32
	artifactBodies map[string][]byte // relative path → body
}

func newArtifactFixture(listBody string) *artifactFixture {
	f := &artifactFixture{
		listBody:       listBody,
		artifactBodies: map[string][]byte{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.Contains(p, "/artifact/") {
			f.artifactHits.Add(1)
			idx := strings.Index(p, "/artifact/")
			rel := strings.TrimPrefix(p[idx+len("/artifact/"):], "/")
			// URL path may be escaped per segment; fixture stores unescaped keys.
			if body, ok := f.artifactBodies[rel]; ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write(body)
				return
			}
			http.NotFound(w, r)
			return
		}
		// List: /job/.../<n>/api/json
		if strings.Contains(p, "/api/json") && strings.Contains(p, "/job/") {
			f.listHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(f.listBody))
			return
		}
		http.NotFound(w, r)
	}))
	return f
}

func (f *artifactFixture) close() { f.srv.Close() }

func (f *artifactFixture) client() *jenkins.Client {
	return &jenkins.Client{
		URL:        f.srv.URL,
		User:       "u",
		Token:      "t",
		Client:     f.srv.Client(),
		LogsClient: f.srv.Client(),
	}
}

func (f *artifactFixture) setArtifact(rel string, body []byte) {
	f.artifactBodies[rel] = body
}

const fixtureArtifactsJSON = `{
	"timestamp": 1700000000000,
	"artifacts": [
		{"fileName": "out.txt", "relativePath": "reports/out.txt"},
		{"fileName": "creds.txt", "relativePath": "secrets/creds.txt"},
		{"fileName": "app.jar", "relativePath": "dist/app.jar"},
		{"fileName": "key.pem", "relativePath": "key.pem"}
	]
}`

// Wave 37: jenkins_list_artifacts omits deny_artifact_paths rows; sets policy flags.
func TestListArtifacts_PolicyFilter_OmitsDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newArtifactFixture(fixtureArtifactsJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "art-filter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name":      "demo",
			"build_number":  7,
			"max_artifacts": 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}

	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ArtifactList
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v raw=%s", err, raw)
	}
	if len(out.Artifacts) != 2 {
		t.Fatalf("want 2 kept, got %d raw=%s", len(out.Artifacts), raw)
	}
	for _, a := range out.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") || strings.HasSuffix(a.Path, ".pem") {
			t.Fatalf("denied path leaked: %q full=%s", a.Path, raw)
		}
	}
	if out.Count != 2 {
		t.Fatalf("count=%d want 2", out.Count)
	}
	if !out.PolicyFiltered {
		t.Fatalf("policy_filtered want true: %s", raw)
	}
	if out.PolicyOmittedCount != 2 {
		t.Fatalf("policy_omitted_count=%d want 2 raw=%s", out.PolicyOmittedCount, raw)
	}
	if strings.Contains(string(raw), "secrets/creds") || strings.Contains(string(raw), "key.pem") {
		t.Fatalf("denied path leaked in response: %s", raw)
	}
	if f.listHits.Load() < 1 {
		t.Fatal("expected list Jenkins hit")
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("list must not download artifacts; hits=%d", f.artifactHits.Load())
	}
}

// Wave 40: denied paths first must not steal max_artifacts slots (MCP path).
func TestListArtifacts_PolicyFilter_DeniedDoNotStealUserMaxSlots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 6 denied first + 4 allowed; max_artifacts=3 → page of 3 allowed reports/*.
	var b strings.Builder
	b.WriteString(`{"timestamp":1700000000000,"artifacts":[`)
	for i := 0; i < 6; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"fileName":"s%d.txt","relativePath":"secrets/s%d.txt"}`, i, i)
	}
	for i := 0; i < 4; i++ {
		b.WriteByte(',')
		fmt.Fprintf(&b, `{"fileName":"a%d.txt","relativePath":"reports/a%d.txt"}`, i, i)
	}
	b.WriteString(`]}`)

	f := newArtifactFixture(b.String())
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "art-hardcap", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name":      "demo",
			"build_number":  7,
			"max_artifacts": 3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v text=%q", res, toolErrorText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ArtifactList
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v raw=%s", err, raw)
	}
	if out.Count != 3 || len(out.Artifacts) != 3 {
		t.Fatalf("want 3 allowed on page, got count=%d arts=%d raw=%s", out.Count, len(out.Artifacts), raw)
	}
	for _, a := range out.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") {
			t.Fatalf("denied path leaked: %q", a.Path)
		}
	}
	if !out.PolicyFiltered || out.PolicyOmittedCount != 6 {
		t.Fatalf("policy flags: filtered=%v omitted=%d want true/6 raw=%s",
			out.PolicyFiltered, out.PolicyOmittedCount, raw)
	}
	if !out.Truncated {
		t.Fatalf("truncated want true (4 allowed > max 3) raw=%s", raw)
	}
	if strings.Contains(string(raw), "secrets/") {
		t.Fatalf("denied path in payload: %s", raw)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("list must not download; hits=%d", f.artifactHits.Load())
	}
}

// Empty deny_artifact_paths → full list, no policy flags.
func TestListArtifacts_PolicyFilter_EmptyPatternsUnchanged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newArtifactFixture(fixtureArtifactsJSON)
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "art-nofilter", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.IsError {
		t.Fatalf("tool error: %#v", res)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out jenkins.ArtifactList
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Artifacts) != 4 || out.Count != 4 {
		t.Fatalf("want all 4, got count=%d arts=%d raw=%s", out.Count, len(out.Artifacts), raw)
	}
	if out.PolicyFiltered || out.PolicyOmittedCount != 0 {
		t.Fatalf("no filter flags expected: filtered=%v omitted=%d", out.PolicyFiltered, out.PolicyOmittedCount)
	}
}

// Wave 36 residual / Wave 37: get_artifact_text deny → policy_denial, zero artifact download hits.
func TestGetArtifactText_PolicyDeny_ZeroJenkinsHits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newArtifactFixture(`{"timestamp":0,"artifacts":[]}`)
	f.setArtifact("secrets/creds.txt", []byte("TOP-SECRET-TOKEN-abc123"))
	f.setArtifact("reports/out.txt", []byte("ok-content"))
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "exact/creds.txt"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "art-deny", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	// 1) Denied path → policy_denial; zero artifact download hits.
	f.artifactHits.Store(0)
	resDeny, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_artifact_text",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
			"path":         "secrets/creds.txt",
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if resDeny == nil || !resDeny.IsError {
		t.Fatalf("want policy deny, got %#v", resDeny)
	}
	text := toolErrorText(resDeny)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy_denial, got %q", text)
	}
	// Secrets must never appear in errors.
	if strings.Contains(text, "TOP-SECRET") || strings.Contains(text, "abc123") {
		t.Fatalf("secret leaked in error: %q", text)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("Jenkins artifact download must not run on policy deny (hits=%d)", f.artifactHits.Load())
	}

	// 2) Allowed path still works.
	f.artifactHits.Store(0)
	resOK, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_artifact_text",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
			"path":         "reports/out.txt",
		},
	})
	if err != nil {
		t.Fatalf("allowed transport: %v", err)
	}
	if resOK == nil || resOK.IsError {
		t.Fatalf("want success: %#v text=%q", resOK, toolErrorText(resOK))
	}
	rawOK, _ := json.Marshal(resOK.StructuredContent)
	if !strings.Contains(string(rawOK), "ok-content") {
		t.Fatalf("expected content in payload: %s", rawOK)
	}
	if f.artifactHits.Load() != 1 {
		t.Fatalf("allowed path must hit Jenkins once; hits=%d", f.artifactHits.Load())
	}

	// 3) Dot-form path exact/./creds.txt with deny exact/creds.txt → denied (binding collapse).
	f.setArtifact("exact/creds.txt", []byte("NEVER-DOWNLOAD-ME"))
	f.artifactHits.Store(0)
	resDot, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_get_artifact_text",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 7,
			"path":         "exact/./creds.txt",
		},
	})
	if err != nil {
		t.Fatalf("dot transport: %v", err)
	}
	if resDot == nil || !resDot.IsError {
		t.Fatalf("want policy deny for exact/./creds.txt, got %#v text=%q", resDot, toolErrorText(resDot))
	}
	dotText := toolErrorText(resDot)
	if !strings.Contains(strings.ToLower(dotText), "denied") &&
		!strings.Contains(dotText, string(apperr.CodePolicyDenial)) {
		t.Fatalf("expected policy_denial for dot form, got %q", dotText)
	}
	if strings.Contains(dotText, "NEVER-DOWNLOAD") {
		t.Fatalf("secret leaked in dot deny: %q", dotText)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("dot-form deny must not hit Jenkins (hits=%d)", f.artifactHits.Load())
	}
}

// inspect_artifact also binds path → same call-time deny, zero download hits.
func TestInspectArtifact_PolicyDeny_ZeroJenkinsHits(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := newArtifactFixture(`{"timestamp":0,"artifacts":[]}`)
	f.setArtifact("secrets/key.pem", []byte("PEM-SECRET"))
	defer f.close()

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	subj := policy.NewSubject("corp", "dev-user", true)

	server := mcp.NewServer(&mcp.Implementation{Name: "insp-deny", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: subj,
	})

	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	f.artifactHits.Store(0)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_inspect_artifact",
		Arguments: map[string]any{
			"job_name":     "demo",
			"build_number": 1,
			"path":         "secrets/key.pem",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want policy deny: %#v", res)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatalf("inspect deny must not download (hits=%d)", f.artifactHits.Load())
	}
	if strings.Contains(toolErrorText(res), "PEM-SECRET") {
		t.Fatal("secret in error text")
	}
}
