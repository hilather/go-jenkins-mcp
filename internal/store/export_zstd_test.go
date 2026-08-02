package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestExportPureZstd_SuccessAndMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	meta, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	ctx := context.Background()
	g := &store.LogGeneration{Profile: "corp", Job: "export", Build: 1, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(meta, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Append(ctx, g.ID, []byte("export pure zstd payload\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil || len(chunks) != 1 {
		t.Fatalf("%v %d", err, len(chunks))
	}
	c := chunks[0]
	exp, err := store.ExportPureZstd(dataDir, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Size < 1 || exp.SHA256 == "" || len(exp.Bytes) != int(exp.Size) {
		t.Fatalf("%+v", exp)
	}
	if c.ZstdSHA256 != "" && exp.SHA256 != c.ZstdSHA256 {
		t.Fatalf("sha %s vs %s", exp.SHA256, c.ZstdSHA256)
	}
	// Mismatch: corrupt declared wire hash.
	bad := c
	bad.ZstdSHA256 = "00" + c.ZstdSHA256[2:]
	_, err = store.ExportPureZstd(dataDir, bad, nil)
	if err == nil {
		t.Fatal("expected mismatch")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("code %v", err)
	}
	// Ensured path.
	exp2, err := meta.ExportPureZstdEnsured(ctx, dataDir, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exp2.SHA256 != exp.SHA256 {
		t.Fatalf("%s vs %s", exp2.SHA256, exp.SHA256)
	}
}

func TestExportPureZstd_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "profiles", "corp")
	meta, err := store.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	ctx := context.Background()
	g := &store.LogGeneration{Profile: "corp", Job: "miss", Build: 1, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	fr, err := store.NewFrames(meta, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Append(ctx, g.ID, []byte("will delete\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil || len(chunks) != 1 {
		t.Fatal(err)
	}
	c := chunks[0]
	abs, err := store.FrameAbsPath(dataDir, c.RelPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(abs); err != nil {
		t.Fatal(err)
	}
	_, err = store.ExportPureZstd(dataDir, c, nil)
	if err == nil {
		t.Fatal("expected missing file fail")
	}
}
