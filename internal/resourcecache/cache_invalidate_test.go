package resourcecache_test

import (
	"context"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/resourcecache"
)

// Regression: Invalidate/Status computed the digest of the PLAIN key, but
// GetOrFetch stores subject-private entries (the default scope) under a digest
// that folds in the subject hash ("|sk=..."). Invalidate/Status therefore
// targeted a digest nothing is stored under: invalidation was a silent no-op
// (the entry kept being served) and Status reported not-found for an existing
// entry. The new InvalidateFor/StatusFor take the AccessContext and compute
// the stored digest.
func TestInvalidateFor_SubjectPrivateEntry(t *testing.T) {
	src := &countingSource{body: []byte(`{"jobs":1}`)}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	ctx := context.Background()
	key := testKey(resourcecache.KindArtifactCatalog, "")
	ac := resourcecache.AccessContext{ProfileID: "lab", SubjectKey: "alice"}

	// Fill under the subject-private digest.
	_, lr, err := c.GetOrFetch(ctx, resourcecache.FetchRequest{Key: key, Access: ac, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	if lr.FromCache {
		t.Fatal("first fetch must be an origin fill")
	}

	// Status with the request's access context finds the entry.
	e, ok, err := c.StatusFor(ctx, key, ac)
	if err != nil || !ok {
		t.Fatalf("StatusFor must find the subject-private entry: ok=%v err=%v", ok, err)
	}
	if e.KeyDigest == "" {
		t.Fatal("empty digest")
	}

	// Invalidate with the same access context actually removes it.
	if err := c.InvalidateFor(ctx, key, ac); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.StatusFor(ctx, key, ac); err != nil || ok {
		t.Fatalf("entry must be gone after InvalidateFor: ok=%v err=%v", ok, err)
	}
	// Next fetch is an origin re-fill (proves the L0/disk entry is gone).
	_, lr2, err := c.GetOrFetch(ctx, resourcecache.FetchRequest{Key: key, Access: ac, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	if lr2.FromCache {
		t.Fatal("entry served from cache after InvalidateFor")
	}
	if src.n.Load() != 2 {
		t.Fatalf("origin fetches=%d want 2", src.n.Load())
	}
}

// Control: the plain Invalidate/Status keep working for empty-subject
// (shared-shape) entries — same digest as before.
func TestInvalidate_EmptySubjectUnchanged(t *testing.T) {
	src := &countingSource{body: []byte(`{"jobs":1}`)}
	c := openTestCache(t, resourcecache.AllowAllVerifier{})
	ctx := context.Background()
	key := testKey(resourcecache.KindArtifactCatalog, "")
	ac := resourcecache.AccessContext{ProfileID: "lab"} // no subject key

	if _, _, err := c.GetOrFetch(ctx, resourcecache.FetchRequest{Key: key, Access: ac, Source: src}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.Status(ctx, key); err != nil || !ok {
		t.Fatalf("Status must find the empty-subject entry: ok=%v err=%v", ok, err)
	}
	if err := c.Invalidate(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := c.Status(ctx, key); err != nil || ok {
		t.Fatalf("entry must be gone after Invalidate: ok=%v err=%v", ok, err)
	}
}
