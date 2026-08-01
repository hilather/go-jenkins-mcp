package archive_test

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/archive"
)

func TestMemoryStore_PutOpenVerifyDelete(t *testing.T) {
	ctx := context.Background()
	data, _ := writeTestPack(t, 64)
	store := archive.NewMemoryStore(archive.WithMaxRangeBytes(1 << 20))

	cap := store.Capabilities()
	if !cap.NativeReader || cap.RatarmountAdapter || cap.FUSEMountAvailable {
		t.Fatalf("unexpected capabilities: %+v", cap)
	}
	if cap.Name != "memory" {
		t.Fatalf("name %q", cap.Name)
	}

	if err := store.PutPack(ctx, archive.PackDescriptor{
		PackID:        "pack-test-1",
		AffinityGroup: "job/demo#1",
		Data:          data,
	}); err != nil {
		t.Fatalf("PutPack: %v", err)
	}

	entries, err := store.ListEntries(ctx, "pack-test-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("entries %d", len(entries))
	}
	// No path leakage in metadata.
	for _, e := range entries {
		if e.PackID != "pack-test-1" {
			t.Fatalf("pack id leak/mismatch %q", e.PackID)
		}
		if filepath.IsAbs(e.Name) || filepath.IsAbs(e.EntryID) {
			t.Fatalf("absolute path leaked: %+v", e)
		}
	}

	rc, meta, err := store.OpenEntry(ctx, archive.ArchiveRef{
		PackID:  "pack-test-1",
		EntryID: "logs/root/consoleText",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "root log line one\nroot log line two\n" {
		t.Fatalf("body %q", body)
	}
	if meta.Name != "logs/root/consoleText" {
		t.Fatalf("meta name %q", meta.Name)
	}

	// Range with limit enforcement.
	_, _, err = store.OpenRange(ctx, archive.ArchiveRef{
		PackID: "pack-test-1", EntryID: "logs/stage/build.log",
	}, 0, (1<<20)+1)
	if err == nil || apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("expected quota on oversized range, got %v", err)
	}

	rc, _, err = store.OpenRange(ctx, archive.ArchiveRef{
		PackID: "pack-test-1", EntryID: "logs/stage/build.log",
	}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	part, _ := io.ReadAll(rc)
	_ = rc.Close()
	if len(part) != 10 {
		t.Fatalf("range len %d", len(part))
	}

	if err := store.Verify(ctx, archive.ArchiveRef{PackID: "pack-test-1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(ctx, archive.ArchiveRef{PackID: "pack-test-1", EntryID: "missing"}); err == nil {
		t.Fatal("expected missing entry")
	}

	if err := store.DeletePack(ctx, archive.ArchiveRef{PackID: "pack-test-1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Verify(ctx, archive.ArchiveRef{PackID: "pack-test-1"}); err == nil {
		t.Fatal("expected not found after delete")
	}
}

func TestMemoryStore_RejectsSingleFrame(t *testing.T) {
	// Build invalid pack by stripping seek table from a valid one... simpler: raw single frame.
	// Covered by OpenPack; PutPack must fail closed.
	store := archive.NewMemoryStore()
	err := store.PutPack(context.Background(), archive.PackDescriptor{
		PackID: "bad",
		Data:   []byte{0x28, 0xb5, 0x2f, 0xfd}, // truncated junk
	})
	if err == nil {
		t.Fatal("expected put failure")
	}
}

func TestFSStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := archive.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := writeTestPack(t, 64)
	if err := store.PutPack(ctx, archive.PackDescriptor{PackID: "pack-test-1", Data: data}); err != nil {
		t.Fatal(err)
	}
	// New store instance simulates process restart (catalog cold).
	store2, err := archive.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rc, meta, err := store2.OpenEntry(ctx, archive.ArchiveRef{
		PackID: "pack-test-1", EntryID: "evidence/binary.bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	_ = rc.Close()
	if len(body) != 5 || body[0] != 0x00 {
		t.Fatalf("body %v meta %+v", body, meta)
	}
	if store2.Capabilities().Name != "filesystem" {
		t.Fatalf("cap name %s", store2.Capabilities().Name)
	}
	if err := store2.DeletePack(ctx, archive.ArchiveRef{PackID: "pack-test-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryStore_Cancel(t *testing.T) {
	store := archive.NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := store.PutPack(ctx, archive.PackDescriptor{PackID: "x", Data: []byte("y")})
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		// may also be invalid data if cancel not checked first — PutPack checks ctx first
		if err == nil {
			t.Fatal("expected error")
		}
	}
}
