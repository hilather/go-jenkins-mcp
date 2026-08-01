package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// QA-002 lite: deterministic fault-injection for L1 frames + eviction journal.

func TestChaos_CorruptL1Frame_NoSilentAccept(t *testing.T) {
	// Corrupt L1 frame / bad zstd → clear CodeCorruptCache; no silent accept of bad bytes.
	meta, fr, dir := openFrames(t, 48)
	ctx := context.Background()
	genID := insertGen(t, meta)

	var log bytes.Buffer
	for i := 0; i < 20; i++ {
		log.Write(bytes.Repeat([]byte("x"), 30))
		log.WriteByte('\n')
	}
	raw := log.Bytes()
	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("need multi-frame for corrupt isolation, got %d", len(chunks))
	}

	// Corrupt the second committed frame file.
	bad := chunks[1]
	abs, err := store.FrameAbsPath(dir, bad.RelPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte{0x00, 0x01, 0x02, 0xff, 'n', 'o', 't', 'z', 's', 't'}, 0o600); err != nil {
		t.Fatal(err)
	}

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	// Range that only needs frame 0 still works (independent frames).
	ok, err := reader.ReadRange(ctx, genID, chunks[0].RawStart, chunks[0].RawEnd-chunks[0].RawStart)
	if err != nil {
		t.Fatalf("good frame must still read: %v", err)
	}
	if !bytes.Equal(ok.Data, raw[chunks[0].RawStart:chunks[0].RawEnd]) {
		t.Fatal("good frame content mismatch after sibling corruption")
	}

	// Range intersecting corrupt frame fails closed (checksum or zstd).
	_, err = reader.ReadRange(ctx, genID, chunks[1].RawStart, 8)
	if err == nil {
		t.Fatal("expected corrupt frame read to fail; silent accept is a bug")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("want CodeCorruptCache, got %s (%v)", apperr.CodeOf(err), err)
	}
}

func TestChaos_DiskFullMidFrameCommit_PriorFramesIntact(t *testing.T) {
	// Disk-full (injected) on a later frame commit leaves earlier durable frames intact.
	meta, fr, _ := openFrames(t, 40)
	ctx := context.Background()
	genID := insertGen(t, meta)

	// First payload commits at least one frame with small target.
	part1 := bytes.Repeat([]byte("line-one-aaaaaaaa\n"), 6)
	if _, err := fr.Append(ctx, genID, part1); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 1 {
		t.Fatal("expected at least one durable frame before disk-full")
	}
	durableBefore, err := meta.DurableRawEnd(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if durableBefore <= 0 {
		t.Fatal("expected positive durable end")
	}

	// Inject ENOSPC-style failure on next commit.
	fr.Hook = func(stage store.CommitStage) error {
		if stage == store.StageAfterTmpWrite {
			return apperr.New(apperr.CodeInternal, "no space left on device")
		}
		return nil
	}
	part2 := bytes.Repeat([]byte("line-two-bbbbbbbb\n"), 8)
	_, err = fr.Append(ctx, genID, part2)
	if err == nil {
		_, err = fr.Flush(ctx, genID)
	}
	if err == nil {
		t.Fatal("expected disk-full injection to fail commit")
	}

	fr.Hook = nil
	fr.Forget(genID)
	if _, err := fr.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	// Prior durable frames still listed and readable.
	chunks2, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks2) != len(chunks) {
		t.Fatalf("L1 frame count changed after failed commit: before=%d after=%d", len(chunks), len(chunks2))
	}
	end, err := meta.DurableRawEnd(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if end != durableBefore {
		t.Fatalf("durable end moved after disk-full: %d want %d", end, durableBefore)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(ctx, genID, 0, durableBefore)
	if err != nil {
		t.Fatalf("prior frames must remain readable: %v", err)
	}
	if int64(len(rr.Data)) != durableBefore {
		t.Fatalf("read len %d want %d", len(rr.Data), durableBefore)
	}
	// Content must match the durable prefix of part1 (full flush before disk-full).
	if int64(len(part1)) >= durableBefore && !bytes.Equal(rr.Data, part1[:durableBefore]) {
		t.Fatal("prior durable content mismatch after disk-full inject")
	}
}

func TestChaos_ProcessKillMidEvict_RecoverJournal(t *testing.T) {
	// Process kill mid-evict: half-applied journal; RecoverEvictJournal completes safely.
	m, qm, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	g1 := insertSealedGen(t, m, "job-a", 1, 200)
	g2 := insertSealedGen(t, m, "job-b", 2, 200)
	g3 := insertSealedGen(t, m, "job-c", 3, 200)

	// Apply first eviction only (simulates progress before kill).
	partial := store.EvictPlan{
		Candidates: []store.EvictCandidate{
			{Tier: "l1", ID: strconv.FormatInt(g1.ID, 10), ReclaimBytes: 200, Reason: "quota"},
		},
	}
	res, err := qm.Evict(ctx, partial)
	if err != nil {
		t.Fatal(err)
	}
	if res.Evicted != 1 {
		t.Fatalf("partial evict: %+v", res)
	}
	// Plant leftover journal as if kill left second/third pending after first done.
	journal := map[string]any{
		"started_at": time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
		"items": []map[string]any{
			{"tier": "l1", "id": strconv.FormatInt(g1.ID, 10), "bytes": 200, "status": "done"},
			{"tier": "l1", "id": strconv.FormatInt(g2.ID, 10), "bytes": 200, "status": "pending"},
			{"tier": "l1", "id": strconv.FormatInt(g3.ID, 10), "bytes": 200, "status": "pending"},
		},
	}
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	jp := filepath.Join(dataDir, store.EvictJournalFile)
	if err := os.WriteFile(jp, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Recover completes remaining pending items safely.
	rec, err := qm.RecoverEvictJournal(ctx)
	if err != nil {
		t.Fatalf("RecoverEvictJournal: %v", err)
	}
	if !rec.JournalConsistent {
		t.Fatalf("journal not consistent: %+v", rec)
	}
	if rec.Failed > 0 {
		t.Fatalf("recover failures: %+v", rec)
	}
	// g1 already gone; g2/g3 should be gone after recover.
	for _, id := range []int64{g1.ID, g2.ID, g3.ID} {
		got, err := m.GetGenerationByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("generation %d should be evicted after journal recover", id)
		}
	}
	if _, err := os.Stat(jp); !os.IsNotExist(err) {
		t.Fatalf("journal should be cleared after full recover: %v", err)
	}
	// Schema / store still healthy.
	st, err := m.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != store.CurrentSchemaVersion {
		t.Fatalf("schema %d", st.SchemaVersion)
	}
}

func TestChaos_CorruptEvictJournal_ClearedSafely(t *testing.T) {
	// Corrupt journal bytes must not panic; recover clears and leaves store usable.
	m, qm, dataDir := openQuotaEnv(t)
	ctx := context.Background()
	g := insertSealedGen(t, m, "job-x", 9, 100)
	jp := filepath.Join(dataDir, store.EvictJournalFile)
	if err := os.WriteFile(jp, []byte("{not-json!!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := qm.RecoverEvictJournal(ctx)
	if err != nil {
		t.Fatalf("RecoverEvictJournal corrupt journal: %v", err)
	}
	if !rec.JournalConsistent {
		t.Fatalf("%+v", rec)
	}
	// Generation still present (corrupt journal had no valid pending work).
	got, err := m.GetGenerationByID(ctx, g.ID)
	if err != nil || got == nil {
		t.Fatalf("generation should remain: %v %+v", err, got)
	}
	if _, err := os.Stat(jp); !os.IsNotExist(err) {
		t.Fatal("corrupt journal should be removed")
	}
}
