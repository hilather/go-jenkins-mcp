package tools_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestResourceCache_ListArtifacts_MissHitServesCache proves jenkins_list_artifacts
// fills catalog cache on first CallTool and serves it on second without a second
// Jenkins ListArtifacts hit, while still applying max_artifacts on the hit path.
func TestResourceCache_ListArtifacts_MissHitServesCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	f := newArtifactFixture(fixtureArtifactsJSON)
	defer f.close()

	dir := t.TempDir()
	rc, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "rc"),
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	server := mcp.NewServer(&mcp.Implementation{Name: "rc-list", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:          policy.NewDefaultReadOnlyGate(),
		ResourceCache: rc,
		ProfileID:     "lab",
		SubjectKey:    "alice",
	})
	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	call := func(max int) jenkins.ArtifactList {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "jenkins_list_artifacts",
			Arguments: map[string]any{
				"job_name":      "demo",
				"build_number":  7,
				"max_artifacts": max,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res == nil || res.IsError {
			t.Fatalf("tool error: %s", toolErrorText(res))
		}
		raw, _ := json.Marshal(res.StructuredContent)
		var out jenkins.ArtifactList
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v raw=%s", err, raw)
		}
		return out
	}

	out1 := call(50)
	if len(out1.Artifacts) < 1 {
		t.Fatalf("empty list: %+v", out1)
	}
	hits1 := f.listHits.Load()
	if hits1 < 1 {
		t.Fatal("first call must hit Jenkins")
	}

	out2 := call(50)
	hits2 := f.listHits.Load()
	if hits2 != hits1 {
		t.Fatalf("second call re-hit Jenkins: first=%d second=%d (cache not served)", hits1, hits2)
	}
	if len(out2.Artifacts) != len(out1.Artifacts) {
		t.Fatalf("hit list mismatch %d vs %d", len(out2.Artifacts), len(out1.Artifacts))
	}

	// max_artifacts applied on hit path without origin re-fetch
	out3 := call(1)
	if f.listHits.Load() != hits1 {
		t.Fatalf("max_artifacts call re-hit Jenkins: %d", f.listHits.Load())
	}
	if len(out3.Artifacts) != 1 {
		t.Fatalf("want max 1 artifact, got %d", len(out3.Artifacts))
	}
	if !out3.Truncated {
		t.Fatal("expect Truncated when max_artifacts trims cached catalog")
	}
}

// TestResourceCache_ListArtifacts_DenyOnHit filters deny_artifact_paths without
// discarding the cache (and without re-fetching origin when catalog is warm).
func TestResourceCache_ListArtifacts_DenyOnHit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	f := newArtifactFixture(fixtureArtifactsJSON)
	defer f.close()

	dir := t.TempDir()
	rc, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "rc"),
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:              policy.ModePilot,
		DenyArtifactPaths: []string{"secrets/**", "*.pem"},
	})
	server := mcp.NewServer(&mcp.Implementation{Name: "rc-deny", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:          policy.NewDefaultReadOnlyGate(),
		Policy:        ev,
		Subject:       policy.NewSubject("corp", "dev-user", true),
		ResourceCache: rc,
		ProfileID:     "lab",
		SubjectKey:    "alice",
	})
	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	// Warm cache
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name": "demo", "build_number": 7, "max_artifacts": 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hits := f.listHits.Load()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name": "demo", "build_number": 7, "max_artifacts": 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.listHits.Load() != hits {
		t.Fatal("deny-on-hit must not re-list Jenkins")
	}
	raw, _ := json.Marshal(res.StructuredContent)
	if strings.Contains(string(raw), "secrets/") || strings.Contains(string(raw), "key.pem") {
		t.Fatalf("denied paths leaked on cache hit: %s", raw)
	}
	var out jenkins.ArtifactList
	_ = json.Unmarshal(raw, &out)
	if !out.PolicyFiltered {
		t.Fatalf("expect policy_filtered on hit: %s", raw)
	}
}

// TestResourceCache_ArtifactText_MaxBytesVariant isolates different max_bytes
// cache entries (real tool path via Register).
func TestResourceCache_ArtifactText_MaxBytesVariant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	f := newArtifactFixture(fixtureArtifactsJSON)
	// body longer than 10 bytes so truncation differs by max_bytes
	f.setArtifact("reports/out.txt", []byte("0123456789ABCDEFGHIJ"))
	defer f.close()

	dir := t.TempDir()
	rc, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "rc"),
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	server := mcp.NewServer(&mcp.Implementation{Name: "rc-text", Version: "test"}, nil)
	tools.Register(server, f.client(), &tools.RegisterOptions{
		Gate:          policy.NewDefaultReadOnlyGate(),
		ResourceCache: rc,
		ProfileID:     "lab",
		SubjectKey:    "alice",
	})
	cs, ss := connectMCP(t, ctx, server)
	defer ss.Close()
	defer cs.Close()

	call := func(maxB int) {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{
			Name: "jenkins_get_artifact_text",
			Arguments: map[string]any{
				"job_name":     "demo",
				"build_number": 7,
				"path":         "reports/out.txt",
				"max_bytes":    maxB,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res == nil || res.IsError {
			t.Fatalf("error: %s", toolErrorText(res))
		}
	}

	hits0 := f.artifactHits.Load()
	call(10)
	if f.artifactHits.Load() <= hits0 {
		t.Fatal("first max_bytes=10 must download")
	}
	hits1 := f.artifactHits.Load()
	call(10)
	if f.artifactHits.Load() != hits1 {
		t.Fatal("second max_bytes=10 must hit cache")
	}
	// Different budget must not reuse the 10-byte entry as complete 20-byte.
	call(20)
	if f.artifactHits.Load() <= hits1 {
		t.Fatal("max_bytes=20 must be a separate cache fill (origin hit)")
	}
}

// TestResourceCache_SubjectPrivate_NoCrossSubjectHit via tool SubjectKey.
func TestResourceCache_SubjectPrivate_NoCrossSubjectHit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	f := newArtifactFixture(fixtureArtifactsJSON)
	defer f.close()

	dir := t.TempDir()
	rc, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "rc"),
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	// Alice
	serverA := mcp.NewServer(&mcp.Implementation{Name: "rc-a", Version: "test"}, nil)
	tools.Register(serverA, f.client(), &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(), ResourceCache: rc,
		ProfileID: "lab", SubjectKey: "alice",
	})
	csA, ssA := connectMCP(t, ctx, serverA)
	defer ssA.Close()
	defer csA.Close()
	_, err = csA.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name": "demo", "build_number": 7, "max_artifacts": 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hitsAlice := f.listHits.Load()

	// Bob shares same Cache dir but different SubjectKey
	serverB := mcp.NewServer(&mcp.Implementation{Name: "rc-b", Version: "test"}, nil)
	tools.Register(serverB, f.client(), &tools.RegisterOptions{
		Gate: policy.NewDefaultReadOnlyGate(), ResourceCache: rc,
		ProfileID: "lab", SubjectKey: "bob",
	})
	csB, ssB := connectMCP(t, ctx, serverB)
	defer ssB.Close()
	defer csB.Close()
	_, err = csB.CallTool(ctx, &mcp.CallToolParams{
		Name: "jenkins_list_artifacts",
		Arguments: map[string]any{
			"job_name": "demo", "build_number": 7, "max_artifacts": 50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.listHits.Load() <= hitsAlice {
		t.Fatal("bob must not reuse alice subject_private catalog without origin fill")
	}
}

// TestResourceCache_SevenKinds_MissThenHit covers pure GetOrFetch key variants.
func TestResourceCache_SevenKinds_MissThenHit(t *testing.T) {
	kinds := []struct {
		kind resourcecache.ResourceKind
		sel  string
		var_ string
	}{
		{resourcecache.KindStageLog, "stage-1", "max_length=100"},
		{resourcecache.KindArtifactCatalog, "", "hardcap=500"},
		{resourcecache.KindArtifactText, "out/log.txt", "max_bytes=100"},
		{resourcecache.KindArtifactInspection, "out/bundle.zip", "max_bytes=0|max_members=50"},
		{resourcecache.KindTestReport, "", "max_failed=50"},
		{resourcecache.KindPipelineStages, "", "v1"},
		{resourcecache.KindBuildChanges, "", "baseline=0|max_commits=50|offset=0|max_files=50|max_msg=512|max_scan=20"},
	}
	dir := t.TempDir()
	rc, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "rc"),
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	var _ tools.ResourceCache = rc
	src := &sourceCounter{}
	for _, k := range kinds {
		key := resourcecache.ResourceKey{
			ProfileID: "lab", Kind: k.kind,
			JobFullName: "demo", BuildNumber: 3,
			Selector: k.sel, Variant: k.var_,
		}
		req := resourcecache.FetchRequest{
			Key: key, Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
			Source: src, ArtifactPath: k.sel, Verifier: resourcecache.AllowAllVerifier{},
		}
		n0 := src.n.Load()
		if _, _, err := rc.GetOrFetch(context.Background(), req); err != nil {
			t.Fatalf("%s first: %v", k.kind, err)
		}
		if _, lr2, err := rc.GetOrFetch(context.Background(), req); err != nil || !lr2.FromCache {
			t.Fatalf("%s second hit: err=%v fromCache=%v", k.kind, err, lr2.FromCache)
		}
		if src.n.Load() != n0+1 {
			t.Fatalf("%s origin re-fetched", k.kind)
		}
	}
}

type sourceCounter struct{ n atomic.Int32 }

func (s *sourceCounter) Fetch(ctx context.Context, key resourcecache.ResourceKey, _ *resourcecache.Entry) (resourcecache.FetchResult, error) {
	s.n.Add(1)
	return resourcecache.FetchResult{
		Structured: map[string]any{"kind": string(key.Kind), "variant": key.Variant},
		Meta:       resourcecache.SourceMetadata{Completeness: resourcecache.Complete},
	}, nil
}
