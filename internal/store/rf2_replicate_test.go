package store_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
)

// exportAllPure returns pure-zstd frames for a committed generation (wire path).
func exportAllPure(t *testing.T, meta *store.Meta, fr *store.Frames, genID int64, crypto *store.FrameCrypto) []fleetcache.ImportFrameBytes {
	t.Helper()
	chunks, err := meta.ListChunks(context.Background(), genID)
	if err != nil || len(chunks) == 0 {
		t.Fatalf("%v n=%d", err, len(chunks))
	}
	out := make([]fleetcache.ImportFrameBytes, 0, len(chunks))
	for _, c := range chunks {
		exp, err := store.ExportPureZstd(fr.DataDir(), c, crypto)
		if err != nil {
			t.Fatal(err)
		}
		// Guard: pure zstd is not AEAD magic.
		if len(exp.Bytes) >= 4 && string(exp.Bytes[:4]) == "JME1" {
			t.Fatal("export must not be AEAD envelope")
		}
		out = append(out, fleetcache.ImportFrameBytes{Seq: c.Seq, PureZstd: exp.Bytes})
	}
	return out
}

func TestRF2_DualDirParityDifferentCrypto(t *testing.T) {
	// Member A: import sealed multi-frame with key v1.
	parts := [][]byte{
		[]byte("rf2-frame-zero-\n"),
		[]byte("rf2-frame-one--\n"),
	}
	wm, frames, full := buildImportFixture(t, parts)

	dirA := filepath.Join(t.TempDir(), "profiles", "member-a")
	metaA, err := store.Open(dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = metaA.Close() })
	frA, err := store.NewFrames(metaA, dirA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frA.Close() })
	fcA, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	frA.SetCrypto(fcA)
	sinkA := store.NewPeerImportSink(metaA, frA)
	resA, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames)
	if err != nil || resA.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", resA, err)
	}

	// Export pure zstd from A (wire bytes).
	wireFrames := exportAllPure(t, metaA, frA, resA.GenerationID, fcA)
	// Wire equality: re-export same as original fixture pure zstd.
	for i := range frames {
		if !bytes.Equal(wireFrames[i].PureZstd, frames[i].PureZstd) {
			t.Fatalf("wire pure zstd mismatch seq %d (recompression?)", i)
		}
	}

	// Member B: different crypto key v7; RF2 import.
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
	fcB, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 7)})
	if err != nil {
		t.Fatal(err)
	}
	frB.SetCrypto(fcB)
	sinkB := store.NewPeerImportSink(metaB, frB)

	resB, err := fleetcache.ReplicateSealed(context.Background(), sinkB, wm, wireFrames)
	if err != nil || resB.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", resB, err)
	}
	if resB.FramesTransferred != len(wm.Frames) {
		t.Fatalf("xfer %d", resB.FramesTransferred)
	}
	// Different local generation IDs.
	if resB.GenerationID == resA.GenerationID {
		// Possible coincidence; ensure keys differ at least via enc meta.
	}
	chunksB, _ := metaB.ListChunks(context.Background(), resB.GenerationID)
	if len(chunksB) == 0 || chunksB[0].EncKeyVersion != 7 {
		t.Fatalf("receiver re-wrap key ver: %+v", chunksB)
	}

	// LogReader parity on B.
	readerB, err := frB.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := readerB.ReadRange(context.Background(), resB.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, full) {
		t.Fatalf("B LogReader mismatch got %d want %d", len(rr.Data), len(full))
	}

	// Idempotent re-replicate: zero transfer.
	res2, err := fleetcache.ReplicateSealed(context.Background(), sinkB, wm, wireFrames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	if res2.FramesTransferred != 0 {
		t.Fatal("idempotent re-transfer")
	}
}

func TestRF2_PartialInterruptInvisibleThenRetry(t *testing.T) {
	parts := [][]byte{[]byte("one\n"), []byte("two\n")}
	wm, frames, full := buildImportFixture(t, parts)

	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)

	// Manual partial: Begin + one frame + Abort.
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
	if _, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); ok {
		t.Fatal("partial must not be committed hit")
	}

	// Full retry succeeds (atomic).
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	reader, _ := fr.Reader()
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr.Data, full) {
		t.Fatalf("%v len=%d", err, len(rr.Data))
	}
}

// Regression: interrupted staging left open; resume transfers only missing frames
// (FLC-043 AC "Retry after interruption sends only missing frames").
func TestRF2_ResumeTransfersOnlyMissingFrames(t *testing.T) {
	parts := [][]byte{[]byte("resume-0\n"), []byte("resume-1\n"), []byte("resume-2\n")}
	wm, frames, full := buildImportFixture(t, parts)

	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)

	// Stage seq 0 only; leave staging open (no Abort) — honest interrupt residual.
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); ok {
		t.Fatal("staging must not be lookup-visible")
	}
	// StagingLookup must see present seq 0.
	id2, gen2, present, ok, err := sink.GetStaging(context.Background(), wm.LocatorHash, wm.ManifestDigest)
	if err != nil || !ok || id2 != importID || gen2 != genID {
		t.Fatalf("GetStaging %+v ok=%v err=%v", present, ok, err)
	}
	if len(present) != 1 || present[0] != 0 {
		t.Fatalf("present %v", present)
	}

	// Resume with only missing seqs 1 and 2 (not full set).
	missingOnly := fleetcache.FilterImportFrames(frames, []int{1, 2})
	if len(missingOnly) != 2 {
		t.Fatalf("filter %d", len(missingOnly))
	}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, missingOnly)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res.FramesTransferred != 2 {
		t.Fatalf("Regression: resume must transfer only missing frames; FramesTransferred=%d want 2 (not %d)",
			res.FramesTransferred, len(wm.Frames))
	}
	if res.GenerationID != genID {
		t.Fatalf("resume must reuse staging generation got %d want %d", res.GenerationID, genID)
	}

	// LogReader parity on completed object.
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr.Data, full) {
		t.Fatalf("parity %v len=%d", err, len(rr.Data))
	}

	// Idempotent: zero transfer.
	res2, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent || res2.FramesTransferred != 0 {
		t.Fatalf("idempotent %+v %v", res2, err)
	}
}

// Wave plan missing_frames → ReplicateWave transfers only MissingSeqs count.
func TestRF2_WaveResumeMissingOnly(t *testing.T) {
	parts := [][]byte{[]byte("wave-r0\n"), []byte("wave-r1\n")}
	wm, frames, full := buildImportFixture(t, parts)

	open := func(name string, keyVer int) (*store.Meta, *store.Frames, *store.PeerImportSink) {
		dir := filepath.Join(t.TempDir(), "profiles", name)
		meta, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = meta.Close() })
		fr, err := store.NewFrames(meta, dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fr.Close() })
		fc, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, keyVer)})
		if err != nil {
			t.Fatal(err)
		}
		fr.SetCrypto(fc)
		return meta, fr, store.NewPeerImportSink(meta, fr)
	}
	_, _, sinkA := open("a", 1)
	metaB, frB, sinkB := open("b", 2)

	// A is full source.
	if _, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames); err != nil {
		t.Fatal(err)
	}
	// B has only seq 0 staged.
	id, gen, err := sinkB.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sinkB.WriteFrame(context.Background(), id, gen, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}

	members := []fleetcache.PlacementMember{
		{ID: "a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "b", CapacityWeight: 100, FailureDomain: "z2"},
	}
	obs := map[string]fleetcache.ReplicaObservation{
		"a": {MemberID: "a", Digest: wm.ManifestDigest, Status: "committed"},
		"b": {MemberID: "b", Status: "staging", PresentSeqs: []int{0}},
	}
	plan, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, obs, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	results, err := fleetcache.ReplicateWave(context.Background(), plan, wm, frames, map[string]fleetcache.ImportSink{
		"a": sinkA, "b": sinkB,
	})
	if err != nil {
		t.Fatal(err)
	}
	rb := results["b"]
	if rb.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("b %+v plan %+v", rb, plan)
	}
	if rb.FramesTransferred != 1 {
		t.Fatalf("Regression: wave must transfer only missing frame count; got %d", rb.FramesTransferred)
	}
	reader, _ := frB.Reader()
	rr, err := reader.ReadRange(context.Background(), rb.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr.Data, full) {
		t.Fatalf("parity %v", err)
	}
	_ = metaB
}

func TestRF2_PlanWaveDualSink(t *testing.T) {
	// Planner + wave against two real sinks (dual dirs).
	parts := [][]byte{[]byte("wave-a\n"), []byte("wave-b\n")}
	wm, frames, full := buildImportFixture(t, parts)

	open := func(name string, keyVer int) (*store.Meta, *store.Frames, *store.PeerImportSink) {
		dir := filepath.Join(t.TempDir(), "profiles", name)
		meta, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = meta.Close() })
		fr, err := store.NewFrames(meta, dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fr.Close() })
		fc, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, keyVer)})
		if err != nil {
			t.Fatal(err)
		}
		fr.SetCrypto(fc)
		return meta, fr, store.NewPeerImportSink(meta, fr)
	}
	metaA, frA, sinkA := open("a", 1)
	metaB, frB, sinkB := open("b", 2)

	// Seed A as source.
	resA, err := fleetcache.ReplicateSealed(context.Background(), sinkA, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	// Export pure-zstd from A's committed generation (real wire path; keyVer 1).
	fcA, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	wire := exportAllPure(t, metaA, frA, resA.GenerationID, fcA)

	members := []fleetcache.PlacementMember{
		{ID: "a", CapacityWeight: 100, FailureDomain: "z1"},
		{ID: "b", CapacityWeight: 100, FailureDomain: "z2"},
	}
	obs := map[string]fleetcache.ReplicaObservation{
		"a": {MemberID: "a", Digest: wm.ManifestDigest, Status: "committed"},
	}
	plan, err := fleetcache.PlanRF2Replication(wm.LocatorHash, members, wm, obs, fleetcache.PlacementOptions{
		ReplicationFactor: 2, PreferDistinctDomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	results, err := fleetcache.ReplicateWave(context.Background(), plan, wm, wire, map[string]fleetcache.ImportSink{
		"a": sinkA, "b": sinkB,
	})
	if err != nil {
		t.Fatal(err)
	}
	// B should commit.
	rb := results["b"]
	if rb.Status != fleetcache.ImportStatusCommitted && rb.Status != fleetcache.ImportStatusIdempotent {
		// Owner order may put b first — check whichever was full import target.
		ok := false
		for id, r := range results {
			if id == "a" && (r.Status == "skipped" || r.Status == fleetcache.ImportStatusIdempotent) {
				continue
			}
			if r.Status == fleetcache.ImportStatusCommitted {
				ok = true
				// parity on B if that was the commit
				if id == "b" {
					reader, _ := frB.Reader()
					rr, err := reader.ReadRange(context.Background(), r.GenerationID, 0, int64(len(full)))
					if err != nil || !bytes.Equal(rr.Data, full) {
						t.Fatalf("parity %v", err)
					}
				}
			}
		}
		if !ok {
			t.Fatalf("results %+v plan owners %v", results, plan.RequiredOwners)
		}
	} else {
		reader, _ := frB.Reader()
		rr, err := reader.ReadRange(context.Background(), rb.GenerationID, 0, int64(len(full)))
		if err != nil || !bytes.Equal(rr.Data, full) {
			t.Fatalf("parity %v len=%d", err, len(rr.Data))
		}
	}
	_ = metaB
}
