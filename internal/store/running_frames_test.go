package store_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
)

// FLC-080: replicate committed immutable frames for running logs.
// Store + pure fleetcache helpers: progressive append, offset regression,
// partial peer import invisible, seal reuses ExportPureZstd wire identity.

func openRunningFrames(t *testing.T, target int) (*store.Meta, *store.Frames, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "running")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	if target > 0 {
		fr.TargetBytes = target
		fr.MaxBytes = target * 4
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	return meta, fr, dir
}

func chunksToProgressive(chunks []store.Chunk) []fleetcache.WireFrame {
	pc := make([]fleetcache.ProgressiveChunk, len(chunks))
	for i, c := range chunks {
		pc[i] = fleetcache.ProgressiveChunk{
			Seq: c.Seq, RawStart: c.RawStart, RawEnd: c.RawEnd,
			LineStart: c.LineStart, LineEnd: c.LineEnd,
			DecodedSize: c.UncompressedSize, DecodedSHA256: c.ContentSHA256,
			ZstdSize: c.ZstdSize, ZstdSHA256: c.ZstdSHA256,
		}
	}
	return fleetcache.ProgressiveWireFrames(pc)
}

// AC1: Progressive append while MoreData=true → contiguous seq/ranges, no gap/overlap.
func TestRunning_ProgressiveAppendContiguousRanges(t *testing.T) {
	t.Parallel()
	meta, fr, _ := openRunningFrames(t, 32)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "run-prog", Build: 1, Generation: 1, MoreData: true,
	}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Append progressive chunks (small target forces multi-frame).
	var full bytes.Buffer
	for i := 0; i < 12; i++ {
		line := strings.Repeat("p", 20) + "\n"
		full.WriteString(line)
		res, err := fr.Append(ctx, g.ID, []byte(line))
		if err != nil {
			t.Fatal(err)
		}
		// Keep generation open (MoreData=true); advance offset only to DurableEnd.
		if err := meta.UpdateGenerationOffset(ctx, g.ID, res.DurableEnd, true, false, false); err != nil {
			t.Fatal(err)
		}
	}
	// Do not Flush the entire tail yet — still running. Force at least one durable frame.
	dur, err := fr.DurableEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dur == 0 {
		// If buffer never cut, flush one mid-run durable frame intentionally for multi-frame.
		if _, err := fr.Flush(ctx, g.ID); err != nil {
			t.Fatal(err)
		}
		// Re-open buffer with more progressive data after flush.
		extra := []byte("more-running-data-\n")
		full.Write(extra)
		if _, err := fr.Append(ctx, g.ID, extra); err != nil {
			t.Fatal(err)
		}
	}

	// Append more without flushing residual buffer so AcceptedEnd > DurableEnd.
	tail := []byte("buffered-not-durable-yet")
	if _, err := fr.Append(ctx, g.ID, tail); err != nil {
		t.Fatal(err)
	}
	// Keep MoreData true; jenkins_offset tracks durable only (never buffered).
	dKeep, err := fr.DurableEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.UpdateGenerationOffset(ctx, g.ID, dKeep, true, false, false); err != nil {
		t.Fatal(err)
	}

	gg, err := meta.GetGenerationByID(ctx, g.ID)
	if err != nil || gg == nil {
		t.Fatalf("%v", err)
	}
	if !gg.MoreData || gg.Sealed {
		t.Fatalf("must remain running: more=%v sealed=%v", gg.MoreData, gg.Sealed)
	}

	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 1 {
		t.Fatal("expected at least one durable frame")
	}
	// Seq 0..n contiguous.
	for i, c := range chunks {
		if c.Seq != i {
			t.Fatalf("seq hole at %d: got %d", i, c.Seq)
		}
	}
	wf := chunksToProgressive(chunks)
	if err := fleetcache.ValidateProgressiveRanges(wf); err != nil {
		t.Fatalf("ValidateProgressiveRanges: %v", err)
	}
	// No gap/overlap: raw ranges abut.
	for i := 1; i < len(chunks); i++ {
		if chunks[i].RawStart != chunks[i-1].RawEnd {
			t.Fatalf("gap/overlap at seq %d: %d vs prev end %d", i, chunks[i].RawStart, chunks[i-1].RawEnd)
		}
	}
	// Accepted may exceed durable (buffered not in ListChunks).
	acc, err := fr.AcceptedEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	dEnd, err := fr.DurableEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if acc < dEnd {
		t.Fatalf("accepted %d < durable %d", acc, dEnd)
	}
	// ListChunks only reflects durable — not buffered tail.
	if chunks[len(chunks)-1].RawEnd != dEnd {
		t.Fatalf("last chunk end %d != durable %d", chunks[len(chunks)-1].RawEnd, dEnd)
	}
}

// AC2: Offset regression creates a new logical generation (InsertGeneration bump).
func TestRunning_OffsetRegressionNewGeneration(t *testing.T) {
	t.Parallel()
	meta, fr, _ := openRunningFrames(t, 64)
	ctx := context.Background()
	key := store.LogKey{Profile: "corp", Job: "run-regress", Build: 9}

	g1 := &store.LogGeneration{
		Profile: key.Profile, Job: key.Job, Build: key.Build,
		Generation: 1, JenkinsOffset: 0, MoreData: true,
	}
	if err := meta.InsertGeneration(ctx, g1); err != nil {
		t.Fatal(err)
	}
	body := []byte(strings.Repeat("abcdefgh\n", 8)) // 72 bytes
	res, err := fr.Append(ctx, g1.ID, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, g1.ID); err != nil {
		t.Fatal(err)
	}
	d, _ := fr.DurableEnd(ctx, g1.ID)
	if d == 0 {
		d = res.DurableEnd
	}
	if err := meta.UpdateGenerationOffset(ctx, g1.ID, d, true, false, false); err != nil {
		t.Fatal(err)
	}
	priorOff := d
	if !fleetcache.OffsetRegressionNeedsNewGeneration(priorOff, priorOff/2) {
		t.Fatal("helper must detect regression")
	}
	// Within-generation offset must not regress (Meta enforces).
	if err := meta.UpdateGenerationOffset(ctx, g1.ID, priorOff/2, true, false, false); err == nil {
		t.Fatal("expected within-generation offset regression reject")
	}

	// New logical generation (logmirror startNewGeneration pattern).
	// Abandon prior open gen as sealed-at-durable; insert gen+1 at offset 0.
	if err := meta.UpdateGenerationOffset(ctx, g1.ID, priorOff, false, true, true); err != nil {
		_ = meta.SealGeneration(ctx, g1.ID)
	}
	fr.Forget(g1.ID)

	g2 := &store.LogGeneration{
		Profile: key.Profile, Job: key.Job, Build: key.Build,
		Generation: g1.Generation + 1, JenkinsOffset: 0, MoreData: true,
	}
	if err := meta.InsertGeneration(ctx, g2); err != nil {
		t.Fatal(err)
	}
	latest, err := meta.GetLatestGeneration(ctx, key)
	if err != nil || latest == nil {
		t.Fatalf("%v", err)
	}
	if latest.Generation != 2 {
		t.Fatalf("generation number: got %d want 2", latest.Generation)
	}
	if latest.JenkinsOffset != 0 {
		t.Fatalf("new gen offset: %d", latest.JenkinsOffset)
	}
	if latest.ID == g1.ID {
		t.Fatal("new generation must have distinct row id")
	}
	// Prior gen remains sealed; new is open.
	prev, err := meta.GetGeneration(ctx, key, 1)
	if err != nil || prev == nil || !prev.Sealed {
		t.Fatalf("prev sealed: %+v %v", prev, err)
	}
}

// AC3: Running peer loss / interrupt does not leave lookup-visible corrupt partial.
func TestRunning_PartialImportInvisible(t *testing.T) {
	t.Parallel()
	parts := [][]byte{[]byte("run-partial-0\n"), []byte("run-partial-1\n")}
	wm, frames, _ := buildImportFixture(t, parts)

	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)

	// Manual partial: Begin + one frame + Abort (peer loss mid-running transfer).
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	if err := sink.Abort(context.Background(), importID); err != nil {
		t.Fatal(err)
	}
	// Lookup-visible GetCommitted must be false (no corrupt partial sealed fleet object).
	if _, ok, err := sink.GetCommitted(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("partial must not be GetCommitted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("mapping partial: ok=%v err=%v", ok, err)
	}
}

// AC4: Completed seal reuses existing pure-zstd frames (ExportPureZstd identity stable).
func TestRunning_SealReusesWireFramesNoRecompress(t *testing.T) {
	t.Parallel()
	meta, fr, dir := openRunningFrames(t, 40)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "run-seal", Build: 3, Generation: 1, MoreData: true,
	}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Progressive multi-frame while running.
	parts := [][]byte{
		[]byte(strings.Repeat("aaa-\n", 10)),
		[]byte(strings.Repeat("bbb-\n", 10)),
		[]byte(strings.Repeat("ccc-\n", 10)),
	}
	var full bytes.Buffer
	for _, p := range parts {
		full.Write(p)
		if _, err := fr.Append(ctx, g.ID, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	d, err := fr.DurableEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.UpdateGenerationOffset(ctx, g.ID, d, false, true, false); err != nil {
		t.Fatal(err)
	}
	if err := meta.SealGeneration(ctx, g.ID); err != nil {
		t.Fatal(err)
	}

	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil || len(chunks) < 2 {
		t.Fatalf("multi-frame seal: n=%d err=%v", len(chunks), err)
	}
	// Ensure wire hashes; ExportPureZstd identity must be stable across calls.
	firstExport := make([][]byte, len(chunks))
	for i, c := range chunks {
		exp, err := meta.ExportPureZstdEnsured(ctx, dir, c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(exp.Bytes) >= 4 && string(exp.Bytes[:4]) == "JME1" {
			t.Fatal("export must not be AEAD envelope")
		}
		firstExport[i] = append([]byte(nil), exp.Bytes...)
		// Re-export: same pure zstd bytes (no full recompress of prior frames).
		exp2, err := store.ExportPureZstd(dir, c, nil)
		if err != nil {
			// Ensure wire hash may have updated c; reload chunk.
			chunks2, _ := meta.ListChunks(ctx, g.ID)
			exp2, err = store.ExportPureZstd(dir, chunks2[i], nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(firstExport[i], exp2.Bytes) {
			t.Fatalf("ExportPureZstd identity unstable seq %d (recompress?)", i)
		}
	}

	// Dual-dir ReplicateSealed LogReader parity without recompress of wire bytes.
	// Build wire frames from progressive sealed generation.
	fds := make([]fleetcache.FrameDescriptor, len(chunks))
	importFrames := make([]fleetcache.ImportFrameBytes, len(chunks))
	for i, c := range chunks {
		exp, err := meta.ExportPureZstdEnsured(ctx, dir, c, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Use refreshed wire meta from Ensure.
		chunks2, _ := meta.ListChunks(ctx, g.ID)
		c = chunks2[i]
		fds[i] = fleetcache.FrameDescriptor{
			Seq: c.Seq, RawStart: c.RawStart, RawEnd: c.RawEnd,
			LineStart: c.LineStart, LineEnd: c.LineEnd,
			DecodedSize: c.UncompressedSize, DecodedSHA256: c.ContentSHA256,
			ZstdSize: exp.Size, ZstdSHA256: exp.SHA256,
		}
		importFrames[i] = fleetcache.ImportFrameBytes{Seq: c.Seq, PureZstd: exp.Bytes}
		// Guard: re-export equals the bytes we put on the wire.
		if !bytes.Equal(exp.Bytes, firstExport[i]) {
			t.Fatalf("wire bytes changed before replicate seq %d", i)
		}
	}
	wm, err := fleetcache.PublishSealed(fleetcache.SealedPublishInput{
		FleetID: "fleet", CachePool: "pool", ControllerID: "ctrl",
		JobFullName: "folder/run-seal", BuildNumber: 3, Sealed: true, Frames: fds,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Peer B: different AEAD key; RF2 import pure zstd as-is.
	dirB := filepath.Join(t.TempDir(), "profiles", "member-b")
	metaB, err := store.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metaB.Close() })
	frB, err := store.NewFrames(metaB, dirB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frB.Close() })
	fcB, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 9)})
	if err != nil {
		t.Fatal(err)
	}
	frB.SetCrypto(fcB)
	sinkB := store.NewPeerImportSink(metaB, frB)
	resB, err := fleetcache.ReplicateSealed(context.Background(), sinkB, wm, importFrames)
	if err != nil || resB.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", resB, err)
	}
	// Wire identity on B matches source pure zstd (no recompress).
	wireB := exportAllPure(t, metaB, frB, resB.GenerationID, fcB)
	for i := range importFrames {
		if !bytes.Equal(wireB[i].PureZstd, importFrames[i].PureZstd) {
			t.Fatalf("peer re-export mismatch seq %d (recompress on import?)", i)
		}
	}
	readerB, err := frB.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := readerB.ReadRange(context.Background(), resB.GenerationID, 0, int64(full.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, full.Bytes()) {
		t.Fatalf("LogReader parity: got %d want %d", len(rr.Data), full.Len())
	}
}

// AC5: Running prefix plan lists only committed durable frames (not buffered).
func TestRunning_PrefixPlanOnlyDurableNotBuffered(t *testing.T) {
	t.Parallel()
	meta, fr, _ := openRunningFrames(t, 24)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "run-plan", Build: 5, Generation: 1, MoreData: true,
	}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}

	// Fill enough to cut durable frames.
	for i := 0; i < 8; i++ {
		line := strings.Repeat("d", 16) + "\n"
		if _, err := fr.Append(ctx, g.ID, []byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	// Mid-run flush creates durable prefix; leave more in buffer.
	if _, err := fr.Flush(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	// Buffered-only tail (under target, no cut) — must not enter plan.
	bufOnly := []byte("ONLY_BUFFERED_NO_COMMIT")
	if _, err := fr.Append(ctx, g.ID, bufOnly); err != nil {
		t.Fatal(err)
	}
	dEnd, err := fr.DurableEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	acc, err := fr.AcceptedEnd(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if acc <= dEnd {
		t.Fatalf("need buffered tail: acc=%d durable=%d", acc, dEnd)
	}
	if err := meta.UpdateGenerationOffset(ctx, g.ID, dEnd, true, false, false); err != nil {
		t.Fatal(err)
	}

	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 1 {
		t.Fatal("expected durable frames")
	}
	wf := chunksToProgressive(chunks)
	plan, err := fleetcache.PlanRunningDurablePrefix(g.ID, wf)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SealedSeqEnd != len(chunks)-1 {
		t.Fatalf("SealedSeqEnd %d want %d", plan.SealedSeqEnd, len(chunks)-1)
	}
	if plan.FrameCount != len(chunks) {
		t.Fatalf("FrameCount %d", plan.FrameCount)
	}
	// Export list equals durable only — never includes buffered length.
	exportFrames := fleetcache.SelectRunningExportFrames(wf, plan)
	if len(exportFrames) != len(chunks) {
		t.Fatalf("export frames %d", len(exportFrames))
	}
	lastEnd := exportFrames[len(exportFrames)-1].RawEnd
	if lastEnd != dEnd {
		t.Fatalf("export raw end %d != durable %d (buffered leaked?)", lastEnd, dEnd)
	}
	if lastEnd >= acc {
		t.Fatalf("export must stop before accepted buffered end: end=%d acc=%d", lastEnd, acc)
	}
	// Residual secret-free.
	if plan.Residual != "durable_prefix_only" {
		t.Fatalf("residual %q", plan.Residual)
	}
	if strings.Contains(strings.ToLower(plan.Residual), "token") {
		t.Fatal("residual secret leak")
	}
}
