package resourcecache_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/resourcecache"
)

type countingTel struct {
	hits   atomic.Int64
	misses atomic.Int64
	fills  atomic.Int64
	last   string
}

func (c *countingTel) OnResourceEvent(kind resourcecache.ResourceKind, layer, outcome string, bytes int64, reason string) {
	c.last = string(kind) + ":" + layer + ":" + outcome + ":" + reason
	switch outcome {
	case "hit":
		c.hits.Add(1)
	case "miss":
		c.misses.Add(1)
	case "fill_ok":
		c.fills.Add(1)
	}
}

type epochBox struct{ ep atomic.Uint64 }

func (e *epochBox) PurgeEpoch(resourcecache.ResourceKind) uint64 { return e.ep.Load() }

func TestGetOrFetch_EmitsTelemetry(t *testing.T) {
	tel := &countingTel{}
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir:  filepath.Join(t.TempDir(), "c"),
		Verifier:  resourcecache.AllowAllVerifier{},
		Telemetry: tel,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	src := &countingSource{body: []byte(`{"t":1}`)}
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindTestReport, ""),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	}
	if _, _, err := c.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if tel.misses.Load() < 1 || tel.fills.Load() < 1 {
		t.Fatalf("miss/fill telemetry: misses=%d fills=%d last=%s", tel.misses.Load(), tel.fills.Load(), tel.last)
	}
	if _, _, err := c.GetOrFetch(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if tel.hits.Load() < 1 {
		t.Fatalf("hit telemetry: hits=%d last=%s", tel.hits.Load(), tel.last)
	}
}

func TestGetOrFetch_PurgeEpochDiscardsLateFill(t *testing.T) {
	ep := &epochBox{}
	c, err := resourcecache.Open(resourcecache.Config{
		CacheDir: filepath.Join(t.TempDir(), "c"),
		Verifier: resourcecache.AllowAllVerifier{},
		Epochs:   ep,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// Source that bumps epoch mid-fetch after first call path.
	// Simpler: set epoch after first fill, then force miss by using new key —
	// and bump epoch during Source.Fetch for second key.
	src := &epochBumpSource{body: []byte(`{"x":1}`), ep: ep}
	req := resourcecache.FetchRequest{
		Key:    testKey(resourcecache.KindPipelineStages, "late"),
		Access: resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "a"},
		Source: src,
	}
	er, lr, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if lr.FromCache {
		t.Fatal("first should be origin")
	}
	// Late fill discarded → no durable ready row on second open of same key after epoch bump during fetch.
	// The first fetch already bumped epoch in Source.Fetch before commit → entry should not be sealed.
	// Re-open and try hit with epoch still high — if discarded, miss again.
	_ = er
	// If epoch advanced during fill, commit was discarded: second GetOrFetch with same source
	// (which bumps again) should still not serve from cache without a successful commit.
	src2 := &countingSource{body: []byte(`{"x":2}`)}
	req.Source = src2
	_, lr2, err := c.GetOrFetch(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// After discarded fill, disk should not have ready entry → origin again
	if lr2.FromCache {
		t.Fatal("late fill after purge epoch bump must not leave ready cache entry")
	}
	if src2.n.Load() != 1 {
		t.Fatalf("expected origin fetch, got %d", src2.n.Load())
	}
}

// epochBumpSource increments purge epoch during Fetch (simulates concurrent purge).
type epochBumpSource struct {
	body []byte
	ep   *epochBox
	n    atomic.Int32
}

func (s *epochBumpSource) Fetch(ctx context.Context, key resourcecache.ResourceKey, _ *resourcecache.Entry) (resourcecache.FetchResult, error) {
	s.n.Add(1)
	// Advance epoch mid-origin so commit sees mismatch.
	s.ep.ep.Add(1)
	return resourcecache.FetchResult{
		Structured: map[string]any{"payload": string(s.body)},
		Meta:       resourcecache.SourceMetadata{Completeness: resourcecache.Complete},
	}, nil
}
