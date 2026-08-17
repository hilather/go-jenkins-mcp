package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// Regression: RecoverReleaseJournal could never finish a meta_done item for a
// pinned/leased generation. The recovery loop deliberately skips the pin/lease
// abort for meta_done items ("L1 already logically released — finish file
// purge despite pin"), but applyReleaseItem re-checked pin/lease
// unconditionally and returned policy_denial — so the journal was stuck and
// every maintenance releaseTick failed until the pin was manually removed.
// The pin/lease re-check now applies only to the destructive metadata step
// (pending → meta_done); the leftover-file purge (meta_done → done) proceeds.
func TestRecoverReleaseJournal_MetaDonePinnedStillFinishes(t *testing.T) {
	meta, _, machine, dir := openReleaseEnv(t)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "crash", Build: 9}
	body := []byte(strings.Repeat("crash-line\n", 25))
	genID := sealAndPackFS(t, meta, machine, dir, key, body, "pack-crash-pinned")

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

	// Simulate kill after meta_done (chunks cleared, flag set) but files present.
	if err := meta.MarkGenerationL1Released(ctx, genID); err != nil {
		t.Fatal(err)
	}
	if err := meta.DeleteChunksForGeneration(ctx, genID); err != nil {
		t.Fatal(err)
	}
	abs, err := store.FrameAbsPath(dir, paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("planted meta_done state expects file present: %v", err)
	}

	journal := map[string]any{
		"started_at": time.Now().UTC().Format(time.RFC3339Nano),
		"items": []map[string]any{{
			"generation_id": genID,
			"pack_id":       "pack-crash-pinned",
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

	// Pin AFTER the crash — the leftover-file purge must still finish.
	if err := meta.PinGeneration(ctx, genID); err != nil {
		t.Fatal(err)
	}

	rm, err := store.NewReleaseManager(meta, dir, logmirror.VerifyPackForRelease(filepath.Join(dir, store.ArchivesDirName)), store.ReleaseConfig{})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := rm.RecoverReleaseJournal(ctx)
	if err != nil {
		t.Fatalf("RecoverReleaseJournal must finish meta_done despite pin: %v", err)
	}
	if !rec.Released {
		t.Fatalf("recover should complete release: %+v", rec)
	}
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		t.Fatalf("leftover frame should be purged after recover: %v", err)
	}
	if _, err := os.Stat(jp); !os.IsNotExist(err) {
		t.Fatal("journal should be cleared")
	}
	// Pack still present; L2 read works even though the generation is pinned.
	rr, err := machine.ReadRange(ctx, key, 0, int64(len(body)))
	if err != nil {
		t.Fatalf("L2 read after recover: %v", err)
	}
	if string(rr.Data) != string(body) {
		t.Fatal("body mismatch after crash recover")
	}
}
