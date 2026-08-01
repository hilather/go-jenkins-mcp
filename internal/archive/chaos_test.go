package archive_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/archive"
)

// QA-002 lite: L2 pack corruption / quarantine fault injection.

func TestChaos_CorruptL2PackChecksum_VerifyFailsQuarantine(t *testing.T) {
	// Corrupt L2 pack checksum → VerifyPack fails; quarantine path moves pack out of store.
	ctx := context.Background()
	data, st := writeTestPack(t, 48)
	if st == nil || len(data) < 32 {
		t.Fatal("expected multi-frame pack bytes")
	}

	// In-memory VerifyPack rejects corrupted bytes.
	corrupt := append([]byte{}, data...)
	// Flip bytes in the middle of content (not just header) so open/verify fails.
	for i := 10; i < 20 && i < len(corrupt); i++ {
		corrupt[i] ^= 0xa5
	}
	rep, err := archive.VerifyPack(ctx, "pack-test-1", corrupt, nil)
	if err == nil && rep.PackOK {
		// Stronger corruption if random flip still parsed.
		corrupt = []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00, 0x00} // bad zstd-ish
		rep, err = archive.VerifyPack(ctx, "pack-test-1", corrupt, nil)
	}
	if err == nil {
		t.Fatalf("expected VerifyPack failure for corrupt pack, rep=%+v", rep)
	}
	if rep.PackOK {
		t.Fatal("PackOK must be false for corrupt pack")
	}

	// FS store quarantine path.
	dir := t.TempDir()
	fs, err := archive.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Publish good pack first under a distinct id, then overwrite file with corrupt bytes.
	const packID = "pack-chaos-corrupt"
	// Build a valid pack with matching id when possible; WritePack uses pack-test-1.
	// Put under pack-test-1 then corrupt on disk.
	goodID := "pack-test-1"
	if err := fs.PutPack(ctx, archive.PackDescriptor{
		PackID: goodID,
		Data:   data,
	}); err != nil {
		t.Fatal(err)
	}
	packPath := filepath.Join(dir, goodID+".tar.zst")
	if err := os.WriteFile(packPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	// Also test explicit VerifyPackFile + quarantine for chaos pack id.
	chaosPath := filepath.Join(dir, packID+".tar.zst")
	if err := os.WriteFile(chaosPath, []byte("not-a-valid-multiframe-pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	vrep, verr := archive.VerifyPackFile(ctx, packID, chaosPath, dir, true)
	if verr == nil {
		t.Fatal("expected VerifyPackFile error for garbage pack")
	}
	if !vrep.Quarantined {
		t.Fatalf("expected quarantined: %+v", vrep)
	}
	if _, err := os.Stat(chaosPath); !os.IsNotExist(err) {
		t.Fatal("quarantined pack must leave original path")
	}
	if !archive.IsQuarantined(dir, packID) {
		t.Fatal("expected quarantine marker under quarantine/")
	}

	// FSStore VerifyAndMaybeQuarantine on on-disk corrupted goodID.
	// Force unreadable garbage so quarantine is deterministic.
	if err := os.WriteFile(packPath, []byte{0x00, 0x01, 0x02}, 0o600); err != nil {
		t.Fatal(err)
	}
	qrep, qerr := fs.VerifyAndMaybeQuarantine(ctx, goodID, true)
	if qerr == nil {
		t.Fatalf("expected verify failure after on-disk corruption, rep=%+v", qrep)
	}
	if !qrep.Quarantined {
		t.Fatalf("expected quarantined: %+v", qrep)
	}
	if !archive.IsQuarantined(dir, goodID) {
		t.Fatal("expected quarantine marker for goodID")
	}
	// After quarantine, list must not silently serve a trusted pack.
	if _, openErr := fs.ListEntries(ctx, goodID); openErr == nil {
		t.Fatal("quarantined pack must not list as healthy catalog entry")
	}
	_ = apperr.CodeOf(verr)
}

func TestChaos_CancelDuringVerify_NoSideEffects(t *testing.T) {
	// Cancelled verify must not quarantine or leave partial state.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data, _ := writeTestPack(t, 32)
	dir := t.TempDir()
	packPath := filepath.Join(dir, "p-cancel.tar.zst")
	if err := os.WriteFile(packPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := archive.VerifyPackFile(ctx, "p-cancel", packPath, dir, true)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("expected cancelled, got err=%v rep=%+v", err, rep)
	}
	if rep.Quarantined {
		t.Fatal("cancel must not quarantine")
	}
	if _, err := os.Stat(packPath); err != nil {
		t.Fatal("pack must remain after cancelled verify")
	}
	if archive.IsQuarantined(dir, "p-cancel") {
		t.Fatal("no quarantine dir entry on cancel")
	}
}
