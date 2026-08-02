package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestSchemaV8_WireHashOnNewFrames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	meta, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	ctx := context.Background()
	ver, err := meta.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ver != store.CurrentSchemaVersion || ver < 8 {
		t.Fatalf("schema %d", ver)
	}
	key := store.LogKey{Profile: "corp", Job: "j", Build: 1}
	g := &store.LogGeneration{Profile: key.Profile, Job: key.Job, Build: key.Build, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(meta, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	payload := []byte("hello wire hash frame\n")
	if _, err := fr.Append(ctx, g.ID, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil || len(chunks) < 1 {
		t.Fatalf("chunks: %v %d", err, len(chunks))
	}
	c := chunks[0]
	if c.ZstdSize < 1 || c.ZstdSHA256 == "" {
		t.Fatalf("wire hash not persisted: size=%d sha=%q frame=%q enc=%q", c.ZstdSize, c.ZstdSHA256, c.FrameSHA256, c.EncAlg)
	}
	zstd, err := store.OpenFrameCompressed(dataDir, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(zstd)) != c.ZstdSize {
		t.Fatalf("size %d vs %d", len(zstd), c.ZstdSize)
	}
	sz, sha, err := meta.EnsureChunkWireHash(ctx, dataDir, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sz != c.ZstdSize || sha != c.ZstdSHA256 {
		t.Fatalf("ensure: %d %s", sz, sha)
	}
}

func TestSchemaV8_MigrateFromV7_LazyBackfill(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	if _, err := store.CreateMetaDBAtVersion(dataDir, 7); err != nil {
		t.Fatal(err)
	}
	m, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx := context.Background()
	ver, err := m.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ver != 8 {
		t.Fatalf("want schema 8 after migrate from 7, got %d", ver)
	}
	key := store.LogKey{Profile: "corp", Job: "legacy", Build: 2}
	g := &store.LogGeneration{Profile: key.Profile, Job: key.Job, Build: key.Build, Generation: 1, MoreData: true}
	if err := m.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(m, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Append(ctx, g.ID, []byte("legacy backfill\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	chunks, err := m.ListChunks(ctx, g.ID)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("%v %d", err, len(chunks))
	}
	if _, err := m.DB().Exec(`UPDATE chunks SET zstd_size = NULL, zstd_sha256 = NULL WHERE id = ?`, chunks[0].ID); err != nil {
		t.Fatal(err)
	}
	chunks, err = m.ListChunks(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if chunks[0].ZstdSize != 0 || chunks[0].ZstdSHA256 != "" {
		t.Fatal("expected cleared wire hash")
	}
	sz, sha, err := m.EnsureChunkWireHash(ctx, dataDir, chunks[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if sz < 1 || sha == "" {
		t.Fatalf("backfill empty: %d %q", sz, sha)
	}
	chunks2, err := m.ListChunks(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if chunks2[0].ZstdSize != sz || chunks2[0].ZstdSHA256 != sha {
		t.Fatalf("not persisted: %+v", chunks2[0])
	}
}
