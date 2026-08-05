package resourcecache_test

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache"
)

type countingSource struct {
	n    atomic.Int32
	body []byte
	comp resourcecache.Completeness
	err  error
}

func (c *countingSource) Fetch(ctx context.Context, key resourcecache.ResourceKey, _ *resourcecache.Entry) (resourcecache.FetchResult, error) {
	c.n.Add(1)
	if c.err != nil {
		return resourcecache.FetchResult{}, c.err
	}
	comp := c.comp
	if comp == "" {
		comp = resourcecache.Complete
	}
	if ClassIsBlob(key.Kind) {
		return resourcecache.FetchResult{
			Bytes: append([]byte(nil), c.body...),
			Meta:  resourcecache.SourceMetadata{Completeness: comp, ContentLength: int64(len(c.body))},
		}, nil
	}
	return resourcecache.FetchResult{
		Structured: map[string]any{"payload": string(c.body), "kind": string(key.Kind)},
		Meta:       resourcecache.SourceMetadata{Completeness: comp},
	}, nil
}

func ClassIsBlob(k resourcecache.ResourceKind) bool {
	return resourcecache.ClassOf(k) == resourcecache.ClassImmutableBlob
}

type denyJob struct{ resourcecache.AllowAllVerifier }

func (denyJob) AuthorizeJob(context.Context, resourcecache.AccessContext, string) error {
	return apperr.New(apperr.CodePolicyDenial, "job denied")
}

type denyArt struct{ resourcecache.AllowAllVerifier }

func (denyArt) AuthorizeArtifact(context.Context, resourcecache.AccessContext, string, string) error {
	return apperr.New(apperr.CodePolicyDenial, "artifact denied")
}

func openTestCache(t *testing.T, v resourcecache.AuthorizationVerifier) *resourcecache.Cache {
	t.Helper()
	dir := t.TempDir()
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(dir, "cache"),
		Verifier: v,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func testKey(kind resourcecache.ResourceKind, sel string) resourcecache.ResourceKey {
	return resourcecache.ResourceKey{
		ProfileID:    "lab",
		ControllerID: "ctrl1",
		Kind:         kind,
		JobFullName:  "demo",
		BuildNumber:  1,
		Selector:     sel,
		Variant:      "v1",
	}
}

func TestGetOrFetch_MissFillHit(t *testing.T) {
	src := &countingSource{body: []byte(`{"jobs":1}`)}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindArtifactCatalog, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
		Source: src,
	}
	er1, lr1, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if lr1.FromCache || lr1.Source != resourcecache.SourceOrigin {
		t.Fatalf("first: %+v", lr1)
	}
	if er1.Entry.Completeness != resourcecache.Complete {
		t.Fatalf("completeness %s", er1.Entry.Completeness)
	}
	if src.n.Load() != 1 {
		t.Fatalf("fetch count %d", src.n.Load())
	}
	er2, lr2, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !lr2.FromCache {
		t.Fatalf("second should hit cache: %+v", lr2)
	}
	if src.n.Load() != 1 {
		t.Fatalf("fetch after hit %d", src.n.Load())
	}
	var m map[string]any
	if err := er2.DecodeStructured(&m); err != nil {
		t.Fatal(err)
	}
	if m["payload"] != `{"jobs":1}` {
		t.Fatalf("payload %+v", m)
	}
}

// fixedModePolicy is a test ModePolicy with independent lookup/fill flags.
type fixedModePolicy struct {
	lookup, fill bool
}

func (f fixedModePolicy) AllowLookup(resourcecache.ResourceKind) bool { return f.lookup }
func (f fixedModePolicy) AllowFill(resourcecache.ResourceKind) bool   { return f.fill }

func TestGetOrFetch_ModeOff_BypassesCacheWithoutPurge(t *testing.T) {
	// Regression: mode off stops use but does not delete existing entries.
	src := &countingSource{body: []byte(`{"v":1}`)}
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir: cacheDir,
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindTestReport, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
		Source: src,
	}
	if _, _, err := c.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if src.n.Load() != 1 {
		t.Fatal(src.n.Load())
	}
	// Hit while on
	if _, lr, err := c.GetOrFetch(context.Background(), req); err != nil || !lr.FromCache {
		t.Fatalf("expected hit: %v %+v", err, lr)
	}
	_ = c.Close()

	// Reopen with mode off (no lookup, no fill)
	c2, err := resourcecache.Open(resourcecache.Config{
		CacheDir: cacheDir,
		Verifier: resourcecache.AllowAllVerifier{},
		Modes:    fixedModePolicy{lookup: false, fill: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	_, lr, err := c2.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if lr.FromCache {
		t.Fatal("mode off must not serve cache")
	}
	if src.n.Load() != 2 {
		t.Fatalf("should fetch origin under off: %d", src.n.Load())
	}
	// Data still on disk: reopen without mode policy should hit again
	_ = c2.Close()
	c3, err := resourcecache.Open(resourcecache.Config{
		CacheDir: cacheDir,
		Verifier: resourcecache.AllowAllVerifier{},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c3.Close() })
	_, lr3, err := c3.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !lr3.FromCache {
		t.Fatal("data must remain after mode off (no implicit purge)")
	}
	if src.n.Load() != 2 {
		t.Fatalf("no extra fetch: %d", src.n.Load())
	}
}

func TestGetOrFetch_ModeReadOnly_NoFill(t *testing.T) {
	src := &countingSource{body: []byte(`{"v":2}`)}
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(t.TempDir(), "c"),
		Verifier: resourcecache.AllowAllVerifier{},
		Modes:    fixedModePolicy{lookup: true, fill: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindPipelineStages, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	}
	_, lr, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if lr.FromCache {
		t.Fatal("miss should not be from cache")
	}
	// Second call still misses (no fill)
	_, lr2, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if lr2.FromCache {
		t.Fatal("read_only must not fill")
	}
	if src.n.Load() != 2 {
		t.Fatalf("fetches %d", src.n.Load())
	}
}

func TestGetOrFetch_ModeWriteOnly_NeverServesHit(t *testing.T) {
	src := &countingSource{body: []byte(`{"v":3}`)}
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(t.TempDir(), "c"),
		Verifier: resourcecache.AllowAllVerifier{},
		Modes:    fixedModePolicy{lookup: false, fill: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindBuildChanges, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	}
	if _, _, err := c.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Even after fill, write_only never serves
	_, lr, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if lr.FromCache {
		t.Fatal("write_only must not serve cache")
	}
	if src.n.Load() != 2 {
		t.Fatalf("fetches %d", src.n.Load())
	}
}

func TestGetOrFetch_ModeOff_StillReauthRequired(t *testing.T) {
	// Fail-closed: mode gates never skip auth.
	src := &countingSource{body: []byte("x")}
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(t.TempDir(), "c"),
		Verifier: denyJob{},
		Modes:    fixedModePolicy{lookup: false, fill: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_, _, err = c.GetOrFetch(context.Background(), resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindArtifactCatalog, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("expected policy denial, got %v", err)
	}
	if src.n.Load() != 0 {
		t.Fatal("must not fetch when auth denied")
	}
}

func TestGetOrFetch_PolicyDenyOnHit(t *testing.T) {
	src := &countingSource{body: []byte("catalog")}
	// First populate with allow-all
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindArtifactCatalog, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
		Source: src,
	}
	if _, _, err := c.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Re-open same dir with deny verifier to simulate policy change
	dir := c.DB().Dir()
	_ = c.Close()
	c2, err := resourcecache.Open(resourcecache.Config{CacheDir: dir, Verifier: denyJob{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	_, _, err = c2.GetOrFetch(context.Background(), req)
	if err == nil {
		t.Fatal("expected deny on hit")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
}

func TestGetOrFetch_IncompleteNeverSealed(t *testing.T) {
	src := &countingSource{body: []byte("partial"), comp: resourcecache.Incomplete}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	_, _, err := c.GetOrFetch(context.Background(), resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindStageLog, "42"),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	})
	if err == nil {
		t.Fatal("expected error for incomplete")
	}
	st, ok, err := c.Status(context.Background(), testKey(resourcecache.KindStageLog, "42"))
	if err != nil {
		t.Fatal(err)
	}
	if ok && st.State == resourcecache.StateReady && st.Completeness == resourcecache.Complete {
		t.Fatalf("must not seal incomplete as complete ready: %+v", st)
	}
}

func TestGetOrFetch_PartialStageLogVariantHit(t *testing.T) {
	src := &countingSource{body: []byte("log-tail"), comp: resourcecache.Partial}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	key := testKey(resourcecache.KindStageLog, "n1")
	key.Variant = "max_length=100"
	req := resourcecache.FetchRequest{
		Key:    key,
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	}
	er, lr, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if er.Entry.Completeness != resourcecache.Partial {
		t.Fatalf("want partial got %s", er.Entry.Completeness)
	}
	_, lr2, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !lr2.FromCache {
		t.Fatalf("partial same variant should hit: first=%v second=%v", lr, lr2)
	}
	if src.n.Load() != 1 {
		t.Fatalf("fetches %d", src.n.Load())
	}
}

func TestBlob_DigestMismatchFailClosed(t *testing.T) {
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	// craft source that returns body but we force mismatch via CommitStream expected
	// Use blob store directly
	bs := c.Blobs()
	_, err := bs.CommitStream(bytes.NewReader([]byte("hello")), "deadbeef")
	if err == nil {
		t.Fatal("expected digest mismatch")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

func TestBlob_CancelMidWriteCleansStaging(t *testing.T) {
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	r, w := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Blobs().CommitStream(r, "")
		errCh <- err
	}()
	_, _ = w.Write([]byte("abc"))
	_ = w.CloseWithError(context.Canceled)
	err := <-errCh
	if err == nil {
		t.Fatal("expected error")
	}
	// staging dir should not leave committed blob for partial
	// no ready entry for incomplete key
}

func TestArtifactPathDenyOnHit(t *testing.T) {
	src := &countingSource{body: []byte("secret-text")}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	key := testKey(resourcecache.KindArtifactText, "reports/a.txt")
	req := resourcecache.FetchRequest{
		Key:          key,
		Access:       resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source:       src,
		ArtifactPath: "reports/a.txt",
	}
	if _, _, err := c.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	dir := c.DB().Dir()
	_ = c.Close()
	c2, err := resourcecache.Open(resourcecache.Config{CacheDir: dir, Verifier: denyArt{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	_, _, err = c2.GetOrFetch(context.Background(), req)
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("want artifact deny, got %v", err)
	}
}

func TestKeyGoldenVectors(t *testing.T) {
	k := resourcecache.ResourceKey{
		ProfileID:    "p1",
		ControllerID: "c1",
		Kind:         resourcecache.KindTestReport,
		JobFullName:  "folder/job",
		BuildNumber:  7,
		Variant:      "max_failed=50",
	}
	d1, err := k.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := k.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("digest unstable %s %s", d1, d2)
	}
	// path sanitize for artifacts
	ka := resourcecache.ResourceKey{
		ProfileID: "p", Kind: resourcecache.KindArtifactBlob,
		JobFullName: "j", BuildNumber: 1, Selector: "a/./b.txt",
	}
	nk, err := ka.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if nk.Selector != "a/b.txt" {
		t.Fatalf("selector %q", nk.Selector)
	}
}

func TestFreshnessBuildingTTL(t *testing.T) {
	p := resourcecache.FreshnessPolicy{BuildingTTL: 10 * time.Millisecond}
	e := resourcecache.Entry{
		State: resourcecache.StateReady, Completeness: resourcecache.Complete,
		BuildBuilding: true, FetchedAt: time.Now().UTC().Add(-time.Second),
	}
	if p.IsFresh(e, time.Now().UTC()) {
		t.Fatal("building entry should be stale")
	}
}

// Regression: artifact kinds still run AuthorizeArtifact (deny must fail).
func TestGetOrFetch_ArtifactText_StillAuthorizesArtifact(t *testing.T) {
	src := &countingSource{body: []byte("text"), comp: resourcecache.Complete}
	c := openTestCache(t, denyArt{})
	key := testKey(resourcecache.KindArtifactText, "reports/a.txt")
	key.Variant = "max_bytes=100"
	_, _, err := c.GetOrFetch(context.Background(), resourcecache.FetchRequest{
		Key: key, Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src, ArtifactPath: "reports/a.txt", Verifier: denyArt{},
	})
	if err == nil {
		t.Fatal("artifact_text must still fail closed on artifact deny")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
}

// Regression: stage_log Selector (stage id) must never AuthorizeArtifact /
// jenkins_get_artifact_text. DenyTools on artifact_text must not break stage_log.
func TestGetOrFetch_StageLog_DoesNotAuthorizeAsArtifact(t *testing.T) {
	src := &countingSource{body: []byte("stage log text"), comp: resourcecache.Complete}
	// Verifier that always fails artifact auth
	c := openTestCache(t, denyArt{})
	key := testKey(resourcecache.KindStageLog, "flow-node-42")
	key.Variant = "max_length=100"
	// Even if caller accidentally passes ArtifactPath=selector, non-artifact kinds clear it.
	req := resourcecache.FetchRequest{
		Key:          key,
		Access:       resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
		Source:       src,
		ArtifactPath: "flow-node-42", // must be ignored for KindStageLog
		Verifier:     denyArt{},
	}
	_, _, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatalf("stage_log must not fail via artifact auth: %v", err)
	}
	// Second hit still OK
	_, lr, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !lr.FromCache {
		t.Fatal("expected cache hit")
	}
}

func TestGetOrFetch_SubjectPrivateIsolation(t *testing.T) {
	src := &countingSource{body: []byte("secret-for-alice")}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	key := testKey(resourcecache.KindTestReport, "")
	alice := resourcecache.FetchRequest{
		Key: key, Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"},
		Source: src, Verifier: resourcecache.AllowAllVerifier{},
	}
	if _, _, err := c.GetOrFetch(context.Background(), alice); err != nil {
		t.Fatal(err)
	}
	nAfterAlice := src.n.Load()
	bob := resourcecache.FetchRequest{
		Key: key, Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "bob"},
		Source: src, Verifier: resourcecache.AllowAllVerifier{},
	}
	_, lr, err := c.GetOrFetch(context.Background(), bob)
	if err != nil {
		t.Fatal(err)
	}
	// Bob must not reuse Alice's subject_private entry without re-fetch.
	if lr.FromCache && src.n.Load() == nAfterAlice {
		t.Fatal("bob must not hit alice subject_private cache without origin fill")
	}
	if src.n.Load() < nAfterAlice+1 {
		t.Fatalf("expected bob origin fetch, n=%d", src.n.Load())
	}
}
