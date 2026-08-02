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

// FLC-081: finalize running generations into sealed fleet objects without recompression.
// Progressive Append+Flush+SealGeneration → ExportPureZstd → PlanFinalizeFromDurable →
// FinalizeSealed / ReplicateSealed to second dir; pure zstd identity stable; EncKeyVersion may differ.

// TestFinalize_NoRecompressDualDir proves wire pure-zstd bytes equal before/after
// finalize plan and across peer import (AC1 + wire identity).
func TestFinalize_NoRecompressDualDir(t *testing.T) {
	t.Parallel()
	meta, fr, dir := openRunningFrames(t, 40)
	ctx := context.Background()
	g := &store.LogGeneration{
		Profile: "corp", Job: "fin-seal", Build: 11, Generation: 1, MoreData: true,
	}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}

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

	// Export pure zstd BEFORE finalize plan (baseline wire identity).
	beforeExport := make([][]byte, len(chunks))
	wireFrames := make([]fleetcache.WireFrame, len(chunks))
	importFrames := make([]fleetcache.ImportFrameBytes, len(chunks))
	for i, c := range chunks {
		exp, err := meta.ExportPureZstdEnsured(ctx, dir, c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(exp.Bytes) >= 4 && string(exp.Bytes[:4]) == "JME1" {
			t.Fatal("export must not be AEAD envelope")
		}
		beforeExport[i] = append([]byte(nil), exp.Bytes...)
		chunks2, _ := meta.ListChunks(ctx, g.ID)
		c = chunks2[i]
		wireFrames[i] = fleetcache.WireFrame{
			Seq: c.Seq, RawStart: c.RawStart, RawEnd: c.RawEnd,
			LineStart: c.LineStart, LineEnd: c.LineEnd,
			DecodedSize: c.UncompressedSize, DecodedSHA256: c.ContentSHA256,
			ZstdSize: exp.Size, ZstdSHA256: exp.SHA256,
		}
		importFrames[i] = fleetcache.ImportFrameBytes{Seq: c.Seq, PureZstd: exp.Bytes}
	}
	if err := fleetcache.ValidateProgressiveRanges(wireFrames); err != nil {
		t.Fatal(err)
	}

	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "folder/fin-seal", 11)
	if err != nil {
		t.Fatal(err)
	}
	plan, wm, err := fleetcache.PlanFinalizeFromDurable(loc, wireFrames, importFrames)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Residual != fleetcache.ResidualFinalizeFramesReused {
		t.Fatalf("plan residual %q", plan.Residual)
	}
	if len(plan.FrameSeqs) != len(chunks) {
		t.Fatalf("FrameSeqs %d", len(plan.FrameSeqs))
	}

	// AC1: ExportPureZstd AFTER plan equals export BEFORE (same sha256; no recompress).
	for i, c := range chunks {
		chunks2, _ := meta.ListChunks(ctx, g.ID)
		exp, err := store.ExportPureZstd(dir, chunks2[i], nil)
		if err != nil {
			// Reload if wire hash was backfilled.
			exp, err = meta.ExportPureZstdEnsured(ctx, dir, chunks2[i], nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(beforeExport[i], exp.Bytes) {
			t.Fatalf("ExportPureZstd after finalize plan changed seq %d (recompress?)", i)
		}
		if exp.SHA256 != wireFrames[i].ZstdSHA256 && !strings.EqualFold(exp.SHA256, wireFrames[i].ZstdSHA256) {
			t.Fatalf("sha256 drift seq %d: %s vs %s", i, exp.SHA256, wireFrames[i].ZstdSHA256)
		}
		_ = c
	}

	// Dual-dir: FinalizeSealed / ReplicateSealed to peer B with different EncKeyVersion.
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
	fcB, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 11)})
	if err != nil {
		t.Fatal(err)
	}
	frB.SetCrypto(fcB)
	sinkB := store.NewPeerImportSink(metaB, frB)

	resB, err := fleetcache.FinalizeSealed(context.Background(), sinkB, wm, importFrames)
	if err != nil || resB.Status != fleetcache.FinalizeStatusCommitted {
		t.Fatalf("%+v %v", resB, err)
	}
	if resB.FramesReused != len(importFrames) {
		t.Fatalf("FramesReused %d want %d", resB.FramesReused, len(importFrames))
	}

	// Wire pure zstd on B equals source (no recompress on import re-wrap).
	wireB := exportAllPure(t, metaB, frB, resB.GenerationID, fcB)
	for i := range importFrames {
		if !bytes.Equal(wireB[i].PureZstd, importFrames[i].PureZstd) {
			t.Fatalf("peer re-export mismatch seq %d (recompress on import?)", i)
		}
	}
	chunksB, _ := metaB.ListChunks(context.Background(), resB.GenerationID)
	if len(chunksB) == 0 || chunksB[0].EncKeyVersion != 11 {
		t.Fatalf("receiver re-wrap key ver: %+v", chunksB)
	}

	// LogReader body equal.
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

	// Exactly one sealed preferred version: second FinalizeSealed idempotent.
	res2, err := fleetcache.FinalizeSealed(context.Background(), sinkB, wm, importFrames)
	if err != nil || res2.Status != fleetcache.FinalizeStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	if res2.FramesReused != len(importFrames) {
		t.Fatalf("idempotent FramesReused %d", res2.FramesReused)
	}
	if res2.ManifestDigest != resB.ManifestDigest {
		t.Fatal("digest drift")
	}
}

// TestFinalize_CrashMidFinalizeInvisibleThenResume covers AC3: partial Abort
// leaves no lookup-visible preferred mapping; resume/complete is idempotent.
func TestFinalize_CrashMidFinalizeInvisibleThenResume(t *testing.T) {
	t.Parallel()
	parts := [][]byte{[]byte("fin-crash-0\n"), []byte("fin-crash-1\n")}
	wm, frames, full := buildImportFixture(t, parts)

	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)

	// Crash mid-finalize: Begin + one frame + Abort.
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
	if _, ok, err := sink.GetCommitted(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("partial must not be GetCommitted: ok=%v err=%v", ok, err)
	}
	if _, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("mapping partial: ok=%v err=%v", ok, err)
	}

	// Complete finalize.
	res, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.FinalizeStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res.FramesReused != len(frames) {
		t.Fatalf("FramesReused %d", res.FramesReused)
	}
	// LogReader parity after resume.
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, full) {
		t.Fatalf("body mismatch after resume finalize")
	}
	// Second finalize idempotent.
	res2, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.FinalizeStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	if res2.FramesReused != len(frames) {
		t.Fatalf("idempotent FramesReused %d", res2.FramesReused)
	}
}

// TestFinalize_SecretFreeResidualCanary: finalize residuals never carry secrets.
func TestFinalize_SecretFreeResidualCanary(t *testing.T) {
	t.Parallel()
	parts := [][]byte{[]byte("secret-free-fin\n")}
	wm, frames, _ := buildImportFixture(t, parts)
	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.FinalizeSealed(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"token", "password", "authorization", "/home/", "bearer ", "api_key"}
	for _, s := range []string{res.Residual, fleetcache.FinalizeHonestyResidual, res.LocatorHash} {
		// LocatorHash is hex only — still scan residual strings.
		_ = s
	}
	low := strings.ToLower(res.Residual + " " + fleetcache.FinalizeHonestyResidual)
	for _, b := range banned {
		if strings.Contains(low, b) {
			t.Fatalf("secret-shaped residual: %q", res.Residual)
		}
	}
	// Locator hash is 64 hex (not a path).
	if len(res.LocatorHash) != 64 {
		t.Fatalf("locator_hash shape: %q", res.LocatorHash)
	}
}
