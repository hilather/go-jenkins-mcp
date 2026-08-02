package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
	"github.com/klauspost/compress/zstd"
)

func zstdBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(raw, nil)
}

func hexSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func buildImportFixture(t *testing.T, parts [][]byte) (fleetcache.WireManifest, []fleetcache.ImportFrameBytes, []byte) {
	t.Helper()
	var full bytes.Buffer
	var frames []fleetcache.FrameDescriptor
	var importFrames []fleetcache.ImportFrameBytes
	var rawOff, lineOff int64
	for i, raw := range parts {
		full.Write(raw)
		z := zstdBytes(t, raw)
		lines := int64(0)
		for _, c := range raw {
			if c == '\n' {
				lines++
			}
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			lines++
		}
		frames = append(frames, fleetcache.FrameDescriptor{
			Seq: i, RawStart: rawOff, RawEnd: rawOff + int64(len(raw)),
			LineStart: lineOff, LineEnd: lineOff + lines,
			DecodedSize: int64(len(raw)), DecodedSHA256: hexSHA(raw),
			ZstdSize: int64(len(z)), ZstdSHA256: hexSHA(z),
		})
		importFrames = append(importFrames, fleetcache.ImportFrameBytes{Seq: i, PureZstd: z})
		rawOff += int64(len(raw))
		lineOff += lines
	}
	wm, err := fleetcache.PublishSealed(fleetcache.SealedPublishInput{
		FleetID: "fleet", CachePool: "pool", ControllerID: "ctrl",
		JobFullName: "folder/job", BuildNumber: 42, Sealed: true, Frames: frames,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wm, importFrames, full.Bytes()
}

func openImportStore(t *testing.T) (*store.Meta, *store.Frames, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "recv")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	// Schema v9 required for fleet mapping.
	ver, err := meta.SchemaVersion(context.Background())
	if err != nil || ver < 9 {
		t.Fatalf("schema ver=%d err=%v", ver, err)
	}
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fr.Close() })
	return meta, fr, dir
}

func testKey(t *testing.T, ver int) storecrypto.Key {
	t.Helper()
	out := make([]byte, storecrypto.KeySize)
	for i := range out {
		out[i] = byte(ver*13 + i)
	}
	return storecrypto.Key{Version: ver, Material: out}
}

func TestPeerImport_LogReaderParityAndReencrypt(t *testing.T) {
	// Multi-frame import on receiver with different AEAD keys than "sender" pure zstd path.
	parts := [][]byte{
		[]byte(strings.Repeat("frame-zero-line\n", 5)),
		[]byte(strings.Repeat("frame-one-content-\n", 8)),
	}
	wm, frames, full := buildImportFixture(t, parts)

	meta, fr, _ := openImportStore(t)
	// Receiver encryption enabled with key v2.
	env := &storecrypto.Envelope{Enabled: true, Write: testKey(t, 2)}
	fc, err := store.NewFrameCrypto(env)
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)

	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	if res.GenerationID <= 0 {
		t.Fatal("expected local generation")
	}

	// Mapping visible.
	m, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash)
	if err != nil || !ok || m.GenerationID != res.GenerationID {
		t.Fatalf("%+v ok=%v err=%v", m, ok, err)
	}
	if m.ManifestDigest != wm.ManifestDigest {
		t.Fatal("digest")
	}

	// LogReader parity (full range).
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, full) {
		t.Fatalf("LogReader mismatch: got %d want %d", len(rr.Data), len(full))
	}
	// Subrange
	rr2, err := reader.ReadRange(context.Background(), res.GenerationID, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr2.Data, full[10:30]) {
		t.Fatal("subrange mismatch")
	}

	// On-disk frames are AEAD; ExportPureZstd recovers pure wire bytes.
	chunks, err := meta.ListChunks(context.Background(), res.GenerationID)
	if err != nil || len(chunks) != 2 {
		t.Fatalf("%v n=%d", err, len(chunks))
	}
	dataDir := fr.DataDir()
	for i, c := range chunks {
		if c.EncAlg == "" {
			t.Fatal("expected local AEAD enc metadata")
		}
		exp, err := store.ExportPureZstd(dataDir, c, fc)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(exp.Bytes, frames[i].PureZstd) {
			t.Fatalf("wire pure zstd preserved for seq %d", i)
		}
		if exp.SHA256 != hexSHA(frames[i].PureZstd) {
			t.Fatalf("sha seq %d", i)
		}
	}

	// Idempotent re-import.
	res2, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
}

func TestPeerImport_PartialInvisibleConflict(t *testing.T) {
	parts := [][]byte{[]byte("a\n"), []byte("b\n")}
	wm, frames, _ := buildImportFixture(t, parts)
	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)

	// Begin + write one frame then abort path via RunImport fail: inject by aborting after Begin manually.
	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	// Abort before commit.
	if err := sink.Abort(context.Background(), importID); err != nil {
		t.Fatal(err)
	}
	// No mapping.
	if _, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("partial must be invisible ok=%v err=%v", ok, err)
	}
	// Journal aborted.
	j, err := meta.GetFleetImport(context.Background(), importID)
	if err != nil || j.Status != store.FleetImportAborted {
		t.Fatalf("%+v %v", j, err)
	}

	// Full import succeeds after partial.
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}

	// Conflict: same locator different digest.
	parts2 := [][]byte{[]byte("DIFFERENT\n"), []byte("CONTENT\n")}
	// Need different job to get different content but same locator - actually locator is from job/build.
	// Force conflict by committing same locator with different digest via manual mapping is hard.
	// Instead re-run PlanImport path: change manifest digest by altering frame content but same locator
	// requires same job - different content = different digest, same locator_hash.
	wm2, frames2, _ := buildImportFixture(t, parts2)
	// Same job/build → same locator_hash, different digest.
	if wm2.LocatorHash != wm.LocatorHash {
		t.Fatalf("locator %s vs %s", wm2.LocatorHash, wm.LocatorHash)
	}
	if wm2.ManifestDigest == wm.ManifestDigest {
		t.Fatal("expected different digest")
	}
	resC, err := fleetcache.RunImport(context.Background(), sink, wm2, frames2)
	if err == nil || resC.Status != fleetcache.ImportStatusRejected {
		t.Fatalf("expected conflict reject %+v %v", resC, err)
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	// Original mapping intact.
	m, ok, _ := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash)
	if !ok || m.ManifestDigest != wm.ManifestDigest {
		t.Fatalf("%+v", m)
	}
}

// Regression (skeptic): CommitFleetImport must reject incomplete journal progress
// so a truncated generation cannot become lookup-visible or freeze behind
// same-digest PlanImport idempotent short-circuit.
func TestPeerImport_CommitRejectsIncompleteFrames(t *testing.T) {
	parts := [][]byte{[]byte("aa\n"), []byte("bb\n")} // 2 frames; full body 4 bytes of interest for probe
	wm, frames, full := buildImportFixture(t, parts)
	if len(full) < 4 {
		t.Fatalf("fixture full len %d", len(full))
	}
	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)

	importID, genID, err := sink.Begin(context.Background(), wm)
	if err != nil {
		t.Fatal(err)
	}
	// Write only the first frame (incomplete vs frames_total=2).
	if err := sink.WriteFrame(context.Background(), importID, genID, wm.Frames[0], frames[0].PureZstd); err != nil {
		t.Fatal(err)
	}
	j, err := meta.GetFleetImport(context.Background(), importID)
	if err != nil || j.FramesDone != 1 || j.FramesTotal != 2 {
		t.Fatalf("journal progress %+v err=%v", j, err)
	}

	// Commit must fail closed (no mapping).
	err = sink.Commit(context.Background(), importID, genID, wm)
	if err == nil {
		t.Fatal("Commit must reject incomplete frames_done != frames_total")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s want policy_denial: %v", apperr.CodeOf(err), err)
	}
	if _, ok, err := meta.GetCommittedFleetMapping(context.Background(), wm.LocatorHash); err != nil || ok {
		t.Fatalf("incomplete commit must not publish mapping ok=%v err=%v", ok, err)
	}

	// Direct Meta.CommitFleetImport same fail-closed path.
	err = meta.CommitFleetImport(context.Background(), importID, genID,
		wm.LocatorHash, wm.ManifestDigest, wm.FleetID, wm.CachePool, wm.ControllerID, wm.TotalRawBytes)
	if err == nil {
		t.Fatal("Meta.CommitFleetImport must reject incomplete")
	}

	// Abort incomplete import; full RunImport must still succeed with full body.
	if err := sink.Abort(context.Background(), importID); err != nil {
		t.Fatal(err)
	}
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Data, full) {
		t.Fatalf("after incomplete reject, full import must yield full body: got %d want %d (%q vs %q)",
			len(rr.Data), len(full), rr.Data, full)
	}
	// Idempotent re-run must not freeze a partial: body still full.
	res2, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	rr2, err := reader.ReadRange(context.Background(), res2.GenerationID, 0, int64(len(full)))
	if err != nil {
		t.Fatal(err)
	}
	if len(rr2.Data) != len(full) {
		t.Fatalf("idempotent path freeze probe: read len=%d want=%d", len(rr2.Data), len(full))
	}
	if !bytes.Equal(rr2.Data, full) {
		t.Fatal("idempotent mapping must still serve full body")
	}
}

func TestPeerImport_SchemaV9Migration(t *testing.T) {
	// Open creates current schema including fleet tables.
	meta, _, _ := openImportStore(t)
	ver, err := meta.SchemaVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ver != store.CurrentSchemaVersion || ver < 9 {
		t.Fatalf("ver %d", ver)
	}
}

// Fix unused variables in parity test - remove dead code
func TestPeerImport_PlaintextNoCrypto(t *testing.T) {
	parts := [][]byte{[]byte("plain-only\n")}
	wm, frames, full := buildImportFixture(t, parts)
	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := fr.Reader()
	rr, err := reader.ReadRange(context.Background(), res.GenerationID, 0, int64(len(full)))
	if err != nil || !bytes.Equal(rr.Data, full) {
		t.Fatalf("%v %q", err, rr.Data)
	}
}
