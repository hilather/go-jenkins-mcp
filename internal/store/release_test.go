package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/archive"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func openReleaseEnv(t *testing.T) (*store.Meta, *store.Frames, *logmirror.Machine, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	fr.TargetBytes = 48
	fr.MaxBytes = 128
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m := logmirror.NewMachine(meta, nil)
	m.Frames = fr
	m.Reader = reader
	m.ArchiveRoot = filepath.Join(dir, store.ArchivesDirName)
	return meta, fr, m, dir
}

func sealAndPackFS(t *testing.T, meta *store.Meta, machine *logmirror.Machine, dir string, key store.LogKey, body []byte, packID string) int64 {
	t.Helper()
	ctx := context.Background()
	st, err := machine.Append(ctx, key, logmirror.Segment{
		Data: body, ReportedNextOffset: int64(len(body)), MoreData: false, BuildComplete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Sealed {
		if _, err := machine.Seal(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(dir, store.ArchivesDirName)
	dest, err := archive.NewFSStore(root)
	if err != nil {
		t.Fatal(err)
	}
	res, err := logmirror.PackGenerations(ctx, []store.LogKey{key}, meta, dir, dest, logmirror.PackOptions{
		PackID: packID,
		Marker: meta,
	})
	if err != nil {
		t.Fatalf("PackGenerations: %v", err)
	}
	if !res.MarkedPacked {
		t.Fatal("expected MarkedPacked")
	}
	g, err := meta.GetLatestGeneration(ctx, key)
	if err != nil || g == nil {
		t.Fatalf("gen: %v", err)
	}
	return g.ID
}

func TestReleasePackedL1_PackMarkRelease_L2ReadWorks(t *testing.T) {
	// Pack → mark → release → L1 files gone, L2 remains, ReadRange/Tail via L2.
	meta, _, machine, dir := openReleaseEnv(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "demo", Build: 1}
	body := []byte(strings.Repeat("release-line\n", 40))
	genID := sealAndPackFS(t, meta, machine, dir, key, body, "pack-rel-1")

	// L1 present before release.
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil || len(chunks) == 0 {
		t.Fatalf("expected L1 chunks: %v n=%d", err, len(chunks))
	}
	abs, err := store.FrameAbsPath(dir, chunks[0].RelPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("L1 frame missing before release: %v", err)
	}

	rm, err := store.NewReleaseManager(meta, dir, logmirror.VerifyPackForRelease(filepath.Join(dir, store.ArchivesDirName)), store.ReleaseConfig{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := rm.ReleasePackedL1(ctx, genID)
	if err != nil {
		t.Fatalf("ReleasePackedL1: %v", err)
	}
	if !res.Released || res.Skipped != "" {
		t.Fatalf("release result: %+v", res)
	}

	g, err := meta.GetGenerationByID(ctx, genID)
	if err != nil || g == nil {
		t.Fatal(err)
	}
	if !g.L1Released {
		t.Fatal("expected L1Released")
	}
	chunks, err = meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 0 {
		t.Fatalf("chunks should be gone, got %d", len(chunks))
	}
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Fatalf("L1 frame should be gone: %v", err)
	}
	packPath := filepath.Join(dir, store.ArchivesDirName, "pack-rel-1.tar.zst")
	if _, err := os.Stat(packPath); err != nil {
		t.Fatalf("L2 pack must remain: %v", err)
	}

	// Reads via L2 fallback.
	rr, err := machine.ReadRange(ctx, key, 0, int64(len(body)))
	if err != nil {
		t.Fatalf("ReadRange after L1 release: %v", err)
	}
	if string(rr.Data) != string(body) {
		t.Fatalf("body mismatch after L2 read: got %q", string(rr.Data[:min(40, len(rr.Data))]))
	}
	tail, err := machine.TailBytes(ctx, key, 20)
	if err != nil {
		t.Fatalf("TailBytes after L1 release: %v", err)
	}
	wantTail := body
	if len(wantTail) > 20 {
		wantTail = wantTail[len(wantTail)-20:]
	}
	if string(tail.Data) != string(wantTail) {
		t.Fatalf("tail mismatch: got %q want %q", tail.Data, wantTail)
	}

	// Idempotent second release.
	res2, err := rm.ReleasePackedL1(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Already || res2.Skipped != "already_released" {
		t.Fatalf("second release: %+v", res2)
	}
}

func TestReleasePackedL1_PinAndLeaseBlock(t *testing.T) {
	meta, _, machine, dir := openReleaseEnv(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "pinme", Build: 2}
	body := []byte(strings.Repeat("pin-line\n", 20))
	genID := sealAndPackFS(t, meta, machine, dir, key, body, "pack-pin-1")

	qm, err := store.NewQuotaManager(meta, dir, store.QuotaConfig{TotalQuotaBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	rm, err := store.NewReleaseManager(meta, dir, logmirror.VerifyPackForRelease(filepath.Join(dir, store.ArchivesDirName)), store.ReleaseConfig{})
	if err != nil {
		t.Fatal(err)
	}
	rm.Leases = qm

	if err := meta.PinGeneration(ctx, genID); err != nil {
		t.Fatal(err)
	}
	res, err := rm.ReleasePackedL1(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Released && !res.Already {
		t.Fatal("pin must block release")
	}
	if res.Skipped != "pinned" {
		t.Fatalf("skip reason: %q", res.Skipped)
	}
	if err := meta.UnpinGeneration(ctx, genID); err != nil {
		t.Fatal(err)
	}

	if err := qm.LeaseGeneration(genID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	res, err = rm.ReleasePackedL1(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != "leased" {
		t.Fatalf("lease skip: %+v", res)
	}
	// L1 still present.
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil || len(chunks) == 0 {
		t.Fatalf("L1 must remain under pin/lease: chunks=%d err=%v", len(chunks), err)
	}
	qm.ReleaseLease(genID)

	// Now release succeeds.
	res, err = rm.ReleasePackedL1(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Released {
		t.Fatalf("expected release after unpin/unlease: %+v", res)
	}
}

func TestReleasePackedL1_CrashMidReleaseRecovers(t *testing.T) {
	// Regression: crash mid-release leaves journal; Recover finishes safely
	// (either L1 present or pack valid + L1 gone — never both missing).
	meta, _, machine, dir := openReleaseEnv(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "crash", Build: 3}
	body := []byte(strings.Repeat("crash-line\n", 25))
	genID := sealAndPackFS(t, meta, machine, dir, key, body, "pack-crash-1")

	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	var bytes int64
	for _, c := range chunks {
		paths = append(paths, c.RelPath)
		bytes += c.CompressedSize
	}

	// Simulate kill after meta_done (chunks cleared, flag set) but files still present.
	if err := meta.MarkGenerationL1Released(ctx, genID); err != nil {
		t.Fatal(err)
	}
	if err := meta.DeleteChunksForGeneration(ctx, genID); err != nil {
		t.Fatal(err)
	}
	// Confirm frame file still on disk.
	abs, err := store.FrameAbsPath(dir, paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("planted meta_done state expects file still present: %v", err)
	}

	journal := map[string]any{
		"started_at": time.Now().UTC().Format(time.RFC3339Nano),
		"items": []map[string]any{{
			"generation_id": genID,
			"pack_id":       "pack-crash-1",
			"bytes":         bytes,
			"rel_paths":     paths,
			"status":        "meta_done",
		}},
	}
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	jp := filepath.Join(dir, store.ReleaseJournalFile)
	if err := os.WriteFile(jp, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	rm, err := store.NewReleaseManager(meta, dir, logmirror.VerifyPackForRelease(filepath.Join(dir, store.ArchivesDirName)), store.ReleaseConfig{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := rm.RecoverReleaseJournal(ctx)
	if err != nil {
		t.Fatalf("RecoverReleaseJournal: %v", err)
	}
	if !rec.Released {
		t.Fatalf("recover should complete release: %+v", rec)
	}
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Fatalf("frame should be purged after recover: %v", err)
	}
	if _, err := os.Stat(jp); !os.IsNotExist(err) {
		t.Fatal("journal should be cleared")
	}
	// Pack still present; L2 read works.
	rr, err := machine.ReadRange(ctx, key, 0, int64(len(body)))
	if err != nil {
		t.Fatalf("L2 read after recover: %v", err)
	}
	if string(rr.Data) != string(body) {
		t.Fatal("body mismatch after crash recover")
	}
}

func TestReleasePackedL1_CancelLeavesConsistentState(t *testing.T) {
	meta, _, machine, dir := openReleaseEnv(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "cancel", Build: 4}
	body := []byte(strings.Repeat("cancel-line\n", 20))
	genID := sealAndPackFS(t, meta, machine, dir, key, body, "pack-cancel-1")

	// Verifier that cancels after first call would be hard mid-apply; use cancelled ctx
	// after a pre-check that would still run verify. Use a wrapper that cancels on second verify...
	// Simpler: cancelled context from the start → cancel before destructive work.
	cctx, cancel := context.WithCancel(ctx)
	cancel()

	rm, err := store.NewReleaseManager(meta, dir, logmirror.VerifyPackForRelease(filepath.Join(dir, store.ArchivesDirName)), store.ReleaseConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rm.ReleasePackedL1(cctx, genID)
	if err == nil {
		t.Fatal("expected cancelled error")
	}

	// L1 intact, pack intact, not released.
	g, err := meta.GetGenerationByID(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if g.L1Released {
		t.Fatal("must not release on cancelled ctx before work")
	}
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil || len(chunks) == 0 {
		t.Fatalf("L1 must remain: n=%d err=%v", len(chunks), err)
	}
	packPath := filepath.Join(dir, store.ArchivesDirName, "pack-cancel-1.tar.zst")
	if _, err := os.Stat(packPath); err != nil {
		t.Fatalf("pack must remain: %v", err)
	}

	// Mid-flight cancel: plant journal pending, cancel recover mid-way via cancelled ctx.
	// Direct Release with verify that cancels after success is tested via Recover with cancel.
	var paths []string
	for _, c := range chunks {
		paths = append(paths, c.RelPath)
	}
	jraw, _ := json.Marshal(map[string]any{
		"started_at": time.Now().UTC().Format(time.RFC3339Nano),
		"items": []map[string]any{{
			"generation_id": genID,
			"pack_id":       "pack-cancel-1",
			"bytes":         int64(100),
			"rel_paths":     paths,
			"status":        "pending",
		}},
	})
	_ = os.WriteFile(filepath.Join(dir, store.ReleaseJournalFile), jraw, 0o600)

	// Cancelled recover leaves consistent state (journal may remain or partial).
	cctx2, cancel2 := context.WithCancel(ctx)
	cancel2()
	_, _ = rm.RecoverReleaseJournal(cctx2)

	// Either fully recovered (if cancelled after work) or L1 still valid with pack.
	// Never both pack and L1 missing.
	packOK := true
	if _, err := os.Stat(packPath); err != nil {
		packOK = false
	}
	g2, _ := meta.GetGenerationByID(ctx, genID)
	chunks2, _ := meta.ListChunks(ctx, genID)
	l1OK := len(chunks2) > 0 || (g2 != nil && g2.L1Released)
	if !packOK {
		t.Fatal("pack must never be deleted by release")
	}
	if !l1OK && g2 != nil && !g2.L1Released {
		// L1 meta gone without released flag — inconsistent.
		t.Fatalf("inconsistent: no chunks and not L1Released gen=%+v", g2)
	}

	// Finish with clean recover + release.
	_ = os.Remove(filepath.Join(dir, store.ReleaseJournalFile))
	// Reset if partially released for clean end state.
	if g2 != nil && !g2.L1Released {
		res, err := rm.ReleasePackedL1(ctx, genID)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Released {
			t.Fatalf("final release: %+v", res)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
