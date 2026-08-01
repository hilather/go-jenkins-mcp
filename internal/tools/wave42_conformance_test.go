package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 42 / POL-005 conformance:
//   - Hard-assert Wave 41 Done* APIs (must pass on main)
//   - Soft residual for Wave 42 feature tracks not yet present
//     (artifacts hard-cap resolve, nodes/views collect max pages)

// TestWave42_ListJobsCollectMaxPages_Hard re-asserts Wave 41 Done*:
// ResolveListJobsCollectMaxPages precedence + absolute fail-closed, and live
// ListJobsCollectMaxPages process cap is positive.
func TestWave42_ListJobsCollectMaxPages_Hard(t *testing.T) {
	t.Parallel()

	n, err := ResolveListJobsCollectMaxPages("", "")
	if err != nil || n != DefaultListJobsCollectMaxPages {
		t.Fatalf("default: n=%d err=%v want %d", n, err, DefaultListJobsCollectMaxPages)
	}
	n, err = ResolveListJobsCollectMaxPages("", "80")
	if err != nil || n != 80 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveListJobsCollectMaxPages("120", "80")
	if err != nil || n != 120 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	n, err = ResolveListJobsCollectMaxPages("200", "")
	if err != nil || n != AbsoluteMaxListJobsCollectMaxPages {
		t.Fatalf("absolute max accepted: n=%d err=%v", n, err)
	}
	if _, err := ResolveListJobsCollectMaxPages("201", ""); err == nil {
		t.Fatal("above absolute max must fail closed")
	}
	if _, err := ResolveListJobsCollectMaxPages("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}
	if EnvListJobsCollectMaxPages != "JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES" {
		t.Fatalf("env name drift: %q", EnvListJobsCollectMaxPages)
	}
	if ListJobsCollectMaxPages() <= 0 {
		t.Fatalf("ListJobsCollectMaxPages=%d", ListJobsCollectMaxPages())
	}
}

// TestWave42_ArtifactCacheFilter_Hard re-asserts Wave 41 Done*:
// getCachedArtifactList + listArtifactsWithPolicyFilter + ArtifactPolicyFingerprintMaterial.
func TestWave42_ArtifactCacheFilter_Hard(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const body = `{"timestamp":1,"artifacts":[
		{"fileName":"a.txt","relativePath":"secrets/a.txt"},
		{"fileName":"ok.txt","relativePath":"reports/ok.txt"}
	]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/api/json") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	client := &jenkins.Client{URL: srv.URL, Client: srv.Client()}

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**"},
	})
	st := regState{policy: ev}

	// Fingerprint material is sorted, namespaced, non-empty when denies live.
	fp := ArtifactPolicyFingerprintMaterial(st)
	if len(fp) < 2 || fp[0] != "deny_artifact_paths" || fp[1] != "secrets/**" {
		t.Fatalf("ArtifactPolicyFingerprintMaterial: %v", fp)
	}
	if ArtifactPolicyFingerprintMaterial(regState{}) != nil {
		t.Fatal("empty policy must yield nil artifact fingerprint")
	}

	// Direct hard-cap filter path still omits denied rows.
	listDirect, err := listArtifactsWithPolicyFilter(ctx, client, st, "demo", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if listDirect == nil || len(listDirect.Artifacts) != 1 || listDirect.Artifacts[0].Path != "reports/ok.txt" {
		t.Fatalf("listArtifactsWithPolicyFilter must omit secrets: %+v", listDirect)
	}

	// Cache path (compare/diagnose) uses same filter semantics.
	list, err := getCachedArtifactList(ctx, st, client, "demo", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list == nil || len(list.Artifacts) != 1 || list.Artifacts[0].Path != "reports/ok.txt" {
		t.Fatalf("getCachedArtifactList must omit secrets: %+v", list)
	}
	if !list.PolicyFiltered || list.PolicyOmittedCount < 1 {
		t.Fatalf("want policy filter metadata: %+v", list)
	}
	for _, a := range list.Artifacts {
		if strings.HasPrefix(a.Path, "secrets/") {
			t.Fatalf("denied path leaked via cache path: %q", a.Path)
		}
	}
}

// TestWave42_ArtifactsHardCapResolve_Hard asserts Wave 42 Done*:
// ResolveArtifactsHardCap precedence + absolute fail-closed (default 500, max 2000).
func TestWave42_ArtifactsHardCapResolve_Hard(t *testing.T) {
	t.Parallel()

	n, err := ResolveArtifactsHardCap("", "")
	if err != nil || n != jenkins.DefaultArtifactsHardCap {
		t.Fatalf("default: n=%d err=%v want %d", n, err, jenkins.DefaultArtifactsHardCap)
	}
	n, err = ResolveArtifactsHardCap("", "800")
	if err != nil || n != 800 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveArtifactsHardCap("900", "800")
	if err != nil || n != 900 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := ResolveArtifactsHardCap("99999", ""); err == nil {
		t.Fatal("above absolute max must fail closed")
	}
	if EnvArtifactsHardCap != "JENKINS_MCP_ARTIFACTS_HARD_CAP" {
		t.Fatalf("env name drift: %q", EnvArtifactsHardCap)
	}
	if ArtifactsHardCap() <= 0 {
		t.Fatalf("ArtifactsHardCap=%d", ArtifactsHardCap())
	}
	// Absolute ceiling remains documented (ListArtifacts clamps to AbsoluteMax).
	if jenkins.AbsoluteMaxArtifactsHardCap < jenkins.DefaultArtifactsHardCap {
		t.Fatalf("absolute %d < default %d", jenkins.AbsoluteMaxArtifactsHardCap, jenkins.DefaultArtifactsHardCap)
	}
}

// TestWave42_NodesViewsCollectMaxPages_Hard asserts Wave 42 Done*:
// nodes/views collect page caps are operator-tunable (default 50, absolute 200).
func TestWave42_NodesViewsCollectMaxPages_Hard(t *testing.T) {
	t.Parallel()

	n, err := ResolveListJobsCollectMaxPages("60", "")
	if err != nil || n != 60 {
		t.Fatalf("list_jobs resolve regression: n=%d err=%v", n, err)
	}

	nn, err := ResolveNodesCollectMaxPages("", "70")
	if err != nil || nn != 70 {
		t.Fatalf("nodes env: n=%d err=%v", nn, err)
	}
	nv, err := ResolveViewsCollectMaxPages("80", "70")
	if err != nil || nv != 80 {
		t.Fatalf("views flag wins: n=%d err=%v", nv, err)
	}
	if _, err := ResolveNodesCollectMaxPages("999", ""); err == nil {
		t.Fatal("nodes above absolute must fail closed")
	}
	if _, err := ResolveViewsCollectMaxPages("999", ""); err == nil {
		t.Fatal("views above absolute must fail closed")
	}
	if NodesCollectMaxPages() <= 0 || ViewsCollectMaxPages() <= 0 {
		t.Fatalf("live caps nodes=%d views=%d", NodesCollectMaxPages(), ViewsCollectMaxPages())
	}
}
