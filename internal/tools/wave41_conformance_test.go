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

// Wave 41 / POL-005 hard asserts for landed privacy residual tracks.

// TestWave41_ArtifactCacheFilter_Hard asserts getCachedArtifactList applies
// deny_artifact_paths (fetch via listArtifactsWithPolicyFilter + live post-filter).
func TestWave41_ArtifactCacheFilter_Hard(t *testing.T) {
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

	list, err := getCachedArtifactList(ctx, st, client, "demo", 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if list == nil || len(list.Artifacts) != 1 || list.Artifacts[0].Path != "reports/ok.txt" {
		t.Fatalf("cache path must omit secrets: %+v", list)
	}
	if !list.PolicyFiltered || list.PolicyOmittedCount < 1 {
		t.Fatalf("want policy filter metadata: %+v", list)
	}

	// Empty patterns still return full set foundation.
	arts := []jenkins.ArtifactMeta{{Path: "secrets/a.txt"}, {Path: "reports/ok.txt"}}
	kept, om := FilterDeniedArtifacts(nil, arts)
	if om != 0 || len(kept) != 2 {
		t.Fatalf("empty patterns foundation: kept=%+v om=%d", kept, om)
	}
}

// TestWave41_CollectMaxPagesResolve_Hard asserts ResolveListJobsCollectMaxPages
// precedence and absolute fail-closed cap (default 50, max 200).
func TestWave41_CollectMaxPagesResolve_Hard(t *testing.T) {
	t.Parallel()

	n, err := ResolveListJobsCollectMaxPages("", "")
	if err != nil || n != DefaultListJobsCollectMaxPages {
		t.Fatalf("default: n=%d err=%v want %d", n, err, DefaultListJobsCollectMaxPages)
	}
	n, err = ResolveListJobsCollectMaxPages("", "75")
	if err != nil || n != 75 {
		t.Fatalf("env: n=%d err=%v", n, err)
	}
	n, err = ResolveListJobsCollectMaxPages("100", "75")
	if err != nil || n != 100 {
		t.Fatalf("flag wins: n=%d err=%v", n, err)
	}
	if _, err := ResolveListJobsCollectMaxPages("9999", ""); err == nil {
		t.Fatal("above absolute max must fail closed")
	}
	if _, err := ResolveListJobsCollectMaxPages("nope", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}

	// In-process safety cap is positive (live package var).
	if ListJobsCollectMaxPages() <= 0 {
		t.Fatalf("ListJobsCollectMaxPages=%d", ListJobsCollectMaxPages())
	}
}

// TestWave41_PolicyFingerprintStillBound hard-asserts Wave 40 Done* material is
// still available for page tokens.
func TestWave41_PolicyFingerprintStillBound(t *testing.T) {
	t.Parallel()

	st := regState{policy: policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret"},
	})}
	parts := PolicyFingerprintMaterial(st)
	if len(parts) < 2 || parts[0] != "deny_job_prefixes" || parts[1] != "secret" {
		t.Fatalf("PolicyFingerprintMaterial regression: %v", parts)
	}
}
