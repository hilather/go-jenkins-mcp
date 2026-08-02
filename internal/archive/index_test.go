package archive_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/archive"
)

func TestIndex_BindRejectsWrongChecksum(t *testing.T) {
	// Regression: wrong index is never trusted.
	data, _ := writeTestPack(t, 32)
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	st := p.SeekTable()
	idx, err := archive.BuildIndexFromPack("pack-test-1", "aff-a", data, st)
	p.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Tamper checksum binding.
	idx.PackSHA256 = "deadbeef"
	if err := idx.BindMatches("pack-test-1", int64(len(data)), st.PackSHA256, archive.Sha256Hex(data), archive.FormatVersion); err == nil {
		t.Fatal("expected bind failure for wrong pack_sha256 on index")
	}
	// Correct index vs wrong size.
	idx2, err := archive.BuildIndexFromPack("pack-test-1", "aff-a", data, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := idx2.BindMatches("pack-test-1", int64(len(data))+1, st.PackSHA256, archive.Sha256Hex(data), archive.FormatVersion); err == nil {
		t.Fatal("expected size mismatch")
	}
	// Wrong schema.
	if err := idx2.BindMatches("pack-test-1", int64(len(data)), st.PackSHA256, archive.Sha256Hex(data), archive.FormatVersion+9); err == nil {
		t.Fatal("expected schema mismatch")
	}
}

func TestRebuildIndex_MatchesAndCancel(t *testing.T) {
	data, _ := writeTestPack(t, 48)
	ctx := context.Background()
	idx, err := archive.RebuildIndex(ctx, "pack-test-1", "g1", data)
	if err != nil {
		t.Fatalf("RebuildIndex: %v", err)
	}
	if idx.PackID != "pack-test-1" || idx.MemberCount < 1 {
		t.Fatalf("bad index: %+v", idx)
	}
	if err := idx.BindMatches("pack-test-1", int64(len(data)), idx.PackSHA256, idx.FileSHA256, archive.FormatVersion); err != nil {
		t.Fatalf("bind self: %v", err)
	}

	// Cancel during rebuild is safe.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = archive.RebuildIndex(cctx, "pack-test-1", "g1", data)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("expected cancelled, got %v", err)
	}
}

func TestFSStore_IndexLifecycleAndQuarantine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := archive.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// writeTestPack embeds pack_id "pack-test-1" in the seek table.
	data, _ := writeTestPack(t, 64)
	const packID = "pack-test-1"
	if err := store.PutPack(ctx, archive.PackDescriptor{
		PackID:        packID,
		AffinityGroup: "job/demo",
		Data:          data,
	}); err != nil {
		t.Fatal(err)
	}
	info, ok := store.PackInfo(packID)
	if !ok {
		t.Fatal("missing pack info")
	}
	if !info.IndexTrusted || info.RebuildNeeded {
		t.Fatalf("expected trusted index after PutPack: %+v", info)
	}
	idxPath := archive.IndexPath(filepath.Join(dir, packID+".tar.zst"))
	if _, err := os.Stat(idxPath); err != nil {
		t.Fatalf("index file missing: %v", err)
	}

	// Stale index: corrupt sidecar, reopen cold store → native open, never trust.
	if err := os.WriteFile(idxPath, []byte(`{"magic":"JMCP-IDX-V1","index_schema_version":1,"pack_id":"pack-test-1","pack_format_version":1,"pack_size_bytes":1,"pack_sha256":"00","file_sha256":"00","member_count":0,"frame_count":2,"built_at":"x","members":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store2, err := archive.NewFSStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Read path uses native seek table; must succeed.
	entries, err := store2.ListEntries(ctx, packID)
	if err != nil {
		t.Fatalf("ListEntries with stale index: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected members via native open")
	}
	info2, ok := store2.PackInfo(packID)
	if !ok {
		t.Fatal("missing info after load")
	}
	if info2.IndexTrusted {
		t.Fatal("stale index must not be trusted")
	}
	if !info2.RebuildNeeded {
		t.Fatal("expected RebuildNeeded")
	}

	// Explicit rebuild produces matching trusted index.
	idx, err := store2.RebuildIndex(ctx, packID)
	if err != nil {
		t.Fatalf("RebuildIndex: %v", err)
	}
	if idx.PackID != packID {
		t.Fatalf("pack id %q", idx.PackID)
	}
	info3, _ := store2.PackInfo(packID)
	if !info3.IndexTrusted || info3.RebuildNeeded {
		t.Fatalf("after rebuild: %+v", info3)
	}

	// Corrupt pack → quarantine.
	packPath := filepath.Join(dir, "pack-bad.tar.zst")
	if err := os.WriteFile(packPath, []byte("not-a-pack"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Place under store naming convention.
	_ = os.Remove(packPath)
	badID := "pack-corrupt"
	badPath := filepath.Join(dir, badID+".tar.zst")
	// Mutate a valid pack's bytes so OpenPack or Verify fails.
	corrupt := append([]byte{}, data...)
	if len(corrupt) > 20 {
		corrupt[10] ^= 0xff
		corrupt[11] ^= 0xff
	}
	if err := os.WriteFile(badPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := store2.VerifyAndMaybeQuarantine(ctx, badID, true)
	if err == nil {
		// Some mutations might still parse; force stronger corruption.
		t.Logf("verify err=nil rep=%+v; rewriting unreadable pack", rep)
		if err := os.WriteFile(badPath, []byte{0x00, 0x01, 0x02}, 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err = store2.VerifyAndMaybeQuarantine(ctx, badID, true)
	}
	if err == nil {
		t.Fatal("expected verify failure for corrupt pack")
	}
	if !rep.Quarantined {
		t.Fatalf("expected quarantined: %+v", rep)
	}
	if _, statErr := os.Stat(badPath); !os.IsNotExist(statErr) {
		t.Fatal("corrupt pack should be moved out of store root")
	}
	if !archive.IsQuarantined(dir, badID) {
		t.Fatal("expected quarantine marker")
	}
}

func TestRepairIndex_CancelSafe(t *testing.T) {
	dir := t.TempDir()
	data, _ := writeTestPack(t, 40)
	packPath := filepath.Join(dir, "p1.tar.zst")
	if err := os.WriteFile(packPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := archive.RepairIndex(ctx, "p1", "", packPath, data)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("expected cancel, got %v", err)
	}
	// No partial publish required; .tmp should not linger as final.
	if _, err := os.Stat(archive.IndexPath(packPath)); err == nil {
		t.Fatal("index should not exist after cancelled repair")
	}
}

func TestVerifyPack_WrongIndexNotTrusted(t *testing.T) {
	data, _ := writeTestPack(t, 32)
	p, _ := archive.OpenPack(data)
	idx, err := archive.BuildIndexFromPack("pack-test-1", "", data, p.SeekTable())
	p.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Wrong file hash in index.
	idx.FileSHA256 = "ff"
	rep, err := archive.VerifyPack(context.Background(), "pack-test-1", data, idx)
	if err != nil {
		t.Fatalf("pack should still verify: %v", err)
	}
	if !rep.PackOK {
		t.Fatal("pack ok")
	}
	if rep.IndexTrusted {
		t.Fatal("wrong index must not be trusted")
	}
	if !rep.RebuildNeeded {
		t.Fatal("rebuild needed")
	}
}

// QA-004: index_schema_version is independent of pack bytes.
// Future / unknown index schema fails closed (never trusted); pack content needs no rewrite.
// Stale index after pack rewrite still fails bind (ARC-006) — derived index, lazy rebuild only.
func TestIndex_FutureSchemaVersionFailsClosed(t *testing.T) {
	data, _ := writeTestPack(t, 32)
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	st := p.SeekTable()
	idx, err := archive.BuildIndexFromPack("pack-test-1", "aff", data, st)
	p.Close()
	if err != nil {
		t.Fatal(err)
	}
	if idx.IndexSchemaVersion != archive.IndexSchemaVersion {
		t.Fatalf("fixture schema %d", idx.IndexSchemaVersion)
	}

	// Future sidecar schema: Validate rejects; BindMatches must not trust.
	idx.IndexSchemaVersion = archive.IndexSchemaVersion + 5
	err = idx.Validate()
	if err == nil {
		t.Fatal("expected reject future index_schema_version")
	}
	if !apperr.IsCode(err, apperr.CodeCorruptCache) {
		t.Fatalf("code: %s (%v)", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "unsupported index_schema_version") {
		t.Fatalf("message: %q", err.Error())
	}
	if err := idx.BindMatches("pack-test-1", int64(len(data)), st.PackSHA256, archive.Sha256Hex(data), archive.FormatVersion); err == nil {
		t.Fatal("BindMatches must fail for future index schema")
	}

	// On-disk: OpenIndexForPack sets RebuildNeeded, never mutates pack.
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack-test-1.tar.zst")
	if err := os.WriteFile(packPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bypass MarshalIndex validation by writing raw JSON with a future schema.
	raw := []byte(`{
  "magic": "JMCP-IDX-V1",
  "index_schema_version": 99,
  "pack_id": "pack-test-1",
  "pack_format_version": 1,
  "pack_size_bytes": ` + strconv.FormatInt(int64(len(data)), 10) + `,
  "pack_sha256": "` + st.PackSHA256 + `",
  "file_sha256": "` + archive.Sha256Hex(data) + `",
  "member_count": 1,
  "frame_count": 2,
  "built_at": "2020-01-01T00:00:00Z",
  "members": []
}`)
	if err := os.WriteFile(archive.IndexPath(packPath), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(packPath)
	res := archive.OpenIndexForPack("pack-test-1", packPath, data)
	if res.Trusted {
		t.Fatal("future index schema must not be trusted")
	}
	if !res.RebuildNeeded {
		t.Fatal("expected RebuildNeeded for future index schema")
	}
	after, _ := os.ReadFile(packPath)
	if string(before) != string(after) {
		t.Fatal("pack bytes must not change when index schema is unsupported")
	}
}
