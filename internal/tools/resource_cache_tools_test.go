package tools_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/resourcecache"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// sourceCounter counts origin fetches for tool-kind keys.
type sourceCounter struct {
	n atomic.Int32
}

func (s *sourceCounter) Fetch(ctx context.Context, key resourcecache.ResourceKey, _ *resourcecache.Entry) (resourcecache.FetchResult, error) {
	s.n.Add(1)
	return resourcecache.FetchResult{
		Structured: map[string]any{
			"kind": string(key.Kind),
			"job":  key.JobFullName,
			"n":    key.BuildNumber,
			"sel":  key.Selector,
		},
		Meta: resourcecache.SourceMetadata{Completeness: resourcecache.Complete},
	}, nil
}

// TestResourceCache_SevenKinds_MissThenHit proves each approved tool kind
// populates cache on first GetOrFetch and serves disk/L0 on second without
// re-fetch (real resourcecache facade used by tools.Register ResourceCache).
func TestResourceCache_SevenKinds_MissThenHit(t *testing.T) {
	kinds := []struct {
		kind resourcecache.ResourceKind
		sel  string
	}{
		{resourcecache.KindStageLog, "stage-1"},
		{resourcecache.KindArtifactCatalog, ""},
		{resourcecache.KindArtifactText, "out/log.txt"},
		{resourcecache.KindArtifactInspection, "out/bundle.zip"},
		{resourcecache.KindTestReport, ""},
		{resourcecache.KindPipelineStages, ""},
		{resourcecache.KindBuildChanges, ""},
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

	// Ensure tools package still exports ResourceCache interface compatibility.
	var _ tools.ResourceCache = rc

	src := &sourceCounter{}
	for _, k := range kinds {
		key := resourcecache.ResourceKey{
			ProfileID: "lab", Kind: k.kind,
			JobFullName: "demo", BuildNumber: 3,
			Selector: k.sel, Variant: "v1",
		}
		req := resourcecache.FetchRequest{
			Key: key, Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
			Source: src, ArtifactPath: k.sel, Verifier: resourcecache.AllowAllVerifier{},
		}
		n0 := src.n.Load()
		_, lr1, err := rc.GetOrFetch(context.Background(), req)
		if err != nil {
			t.Fatalf("%s first: %v", k.kind, err)
		}
		if lr1.FromCache {
			t.Fatalf("%s first should be origin", k.kind)
		}
		if src.n.Load() != n0+1 {
			t.Fatalf("%s fetch count", k.kind)
		}
		_, lr2, err := rc.GetOrFetch(context.Background(), req)
		if err != nil {
			t.Fatalf("%s second: %v", k.kind, err)
		}
		if !lr2.FromCache {
			t.Fatalf("%s second should hit cache source=%s", k.kind, lr2.Source)
		}
		if src.n.Load() != n0+1 {
			t.Fatalf("%s origin re-fetched on hit", k.kind)
		}
	}
}

// TestResourceCache_PolicyDenyOnHit_UsesLiveVerifier ensures tools' policyVerifier
// path rejects hits when Evaluate would deny (Deny via custom verifier).
func TestResourceCache_PolicyDenyOnHit_UsesLiveVerifier(t *testing.T) {
	dir := t.TempDir()
	rc, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "rc"),
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.Close() })
	src := &sourceCounter{}
	key := resourcecache.ResourceKey{
		ProfileID: "lab", Kind: resourcecache.KindTestReport,
		JobFullName: "demo", BuildNumber: 1, Variant: "v1",
	}
	req := resourcecache.FetchRequest{
		Key: key, Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src, Verifier: resourcecache.AllowAllVerifier{},
	}
	if _, _, err := rc.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	deny := denyAll{}
	req.Verifier = deny
	_, _, err = rc.GetOrFetch(context.Background(), req)
	if err == nil {
		t.Fatal("expected deny on hit")
	}
}

type denyAll struct{}

func (denyAll) AuthorizeJob(context.Context, resourcecache.AccessContext, string) error {
	return errRCPolicy
}
func (denyAll) AuthorizeArtifact(context.Context, resourcecache.AccessContext, string, string) error {
	return errRCPolicy
}

var errRCPolicy = rcPolicyErr("policy denial")

type rcPolicyErr string

func (e rcPolicyErr) Error() string { return string(e) }
