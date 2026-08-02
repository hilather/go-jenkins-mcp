package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	storecrypto "github.com/hilather/go-jenkins-mcp/internal/store/crypto"
	"github.com/klauspost/compress/zstd"
)

// FLC-070 store-side gates: ExportPureZstd wire identity, bounded ReadRange memory,
// import frame-at-a-time under PeerImportSink. Offline, moderate sizes (≤1 MiB).

// trackPeerSink wraps PeerImportSink to measure pure-zstd wire bytes + max in-flight frame.
type trackPeerSink struct {
	inner      *store.PeerImportSink
	mu         sync.Mutex
	wireBytes  int64
	maxFrame   int
	writeCalls int
}

func (s *trackPeerSink) GetCommitted(ctx context.Context, lh string) (fleetcache.CommittedMapping, bool, error) {
	return s.inner.GetCommitted(ctx, lh)
}
func (s *trackPeerSink) Begin(ctx context.Context, m fleetcache.WireManifest) (int64, int64, error) {
	return s.inner.Begin(ctx, m)
}
func (s *trackPeerSink) GetStaging(ctx context.Context, locatorHash, manifestDigest string) (int64, int64, []int, bool, error) {
	return s.inner.GetStaging(ctx, locatorHash, manifestDigest)
}
func (s *trackPeerSink) WriteFrame(ctx context.Context, importID, generationID int64, wf fleetcache.WireFrame, pureZstd []byte) error {
	s.mu.Lock()
	n := len(pureZstd)
	s.writeCalls++
	s.wireBytes += int64(n)
	if n > s.maxFrame {
		s.maxFrame = n
	}
	s.mu.Unlock()
	return s.inner.WriteFrame(ctx, importID, generationID, wf, pureZstd)
}
func (s *trackPeerSink) Commit(ctx context.Context, importID, generationID int64, m fleetcache.WireManifest) error {
	return s.inner.Commit(ctx, importID, generationID, m)
}
func (s *trackPeerSink) Abort(ctx context.Context, importID int64) error {
	return s.inner.Abort(ctx, importID)
}

func fleetCompressibleParts(frameCount, frameDecoded int) [][]byte {
	parts := make([][]byte, frameCount)
	for i := 0; i < frameCount; i++ {
		line := fmt.Sprintf("store-flc070-f%d-compressible-line\n", i)
		buf := make([]byte, 0, frameDecoded+len(line))
		for len(buf) < frameDecoded {
			buf = append(buf, line...)
		}
		parts[i] = buf[:frameDecoded]
	}
	return parts
}

// TestWireBytes_ExportPureZstd_ReplicateSealed: after store import + ExportPureZstd,
// re-export wire sizes == fixture pure zstd sum and never equal decoded total.
func TestWireBytes_ExportPureZstd_ReplicateSealed(t *testing.T) {
	const framesN = 4
	const frameDecoded = 256 << 10 // 256 KiB × 4 = 1 MiB decoded
	parts := fleetCompressibleParts(framesN, frameDecoded)
	wm, frames, full := buildImportFixture(t, parts)
	decoded := int64(len(full))
	var wantWire int64
	for _, f := range frames {
		wantWire += int64(len(f.PureZstd))
	}
	if wantWire >= decoded {
		t.Fatalf("fixture not compressible: wire=%d decoded=%d", wantWire, decoded)
	}
	if wantWire*2 >= decoded {
		t.Fatalf("expected ≥2× compression: wire=%d decoded=%d", wantWire, decoded)
	}

	meta, fr, _ := openImportStore(t)
	fc, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 3)})
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)
	track := &trackPeerSink{inner: store.NewPeerImportSink(meta, fr)}
	res, err := fleetcache.ReplicateSealed(context.Background(), track, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("ReplicateSealed: %+v %v", res, err)
	}
	track.mu.Lock()
	xfer := track.wireBytes
	maxF := track.maxFrame
	calls := track.writeCalls
	track.mu.Unlock()
	if xfer != wantWire {
		t.Fatalf("import wire bytes=%d want sum(zstd)=%d", xfer, wantWire)
	}
	if maxF > fleetcache.MaxZstdFrameBytes {
		t.Fatalf("max frame %d > MaxZstdFrameBytes", maxF)
	}
	if int64(maxF) >= decoded {
		t.Fatalf("max import frame O(whole log): %d >= %d", maxF, decoded)
	}
	if calls != framesN {
		t.Fatalf("WriteFrame calls=%d want %d", calls, framesN)
	}

	// ExportPureZstd must recover pure wire identity (not AEAD, not decoded).
	exported := exportAllPure(t, meta, fr, res.GenerationID, fc)
	var exportWire int64
	for i, exp := range exported {
		exportWire += int64(len(exp.PureZstd))
		if len(exp.PureZstd) >= 4 && string(exp.PureZstd[:4]) == "JME1" {
			t.Fatal("ExportPureZstd must not emit AEAD envelope")
		}
		if !bytes.Equal(exp.PureZstd, frames[i].PureZstd) {
			t.Fatalf("export wire identity mismatch seq %d", i)
		}
	}
	if exportWire != wantWire {
		t.Fatalf("export wire sum=%d want %d", exportWire, wantWire)
	}
	// Bandwidth gate: export size is pure zstd, not decoded total.
	if exportWire == decoded {
		t.Fatalf("export wire equals decoded (%d)", decoded)
	}
	// Small constant overhead on re-export: exact match (no padding).
	const overheadBudget int64 = 0
	if exportWire > wantWire+overheadBudget {
		t.Fatalf("export %d > sum(zstd)+%d", exportWire, overheadBudget)
	}
	t.Logf("FLC-070 store wire: decoded=%d wire=%d ratio=%.3f gen=%d",
		decoded, exportWire, float64(exportWire)/float64(decoded), res.GenerationID)
}

// TestBoundedMem_ReadRange_NotWholeLog: small window read on multi-frame ~1 MiB gen
// must not allocate O(total log). Frame-bounded decompress is expected (O(frame)).
func TestBoundedMem_ReadRange_NotWholeLog(t *testing.T) {
	const framesN = 4
	const frameDecoded = 256 << 10
	const readLen int64 = 8 << 10 // 8 KiB window
	parts := fleetCompressibleParts(framesN, frameDecoded)
	wm, frames, full := buildImportFixture(t, parts)
	totalDecoded := int64(len(full))

	meta, fr, _ := openImportStore(t)
	fc, err := store.NewFrameCrypto(&storecrypto.Envelope{Enabled: true, Write: testKey(t, 5)})
	if err != nil {
		t.Fatal(err)
	}
	fr.SetCrypto(fc)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	// Mid-log offset lands inside one frame (not whole log).
	start := totalDecoded / 2

	// Warm paths (SQLite + zstd decoder pools) outside measurement.
	warm, err := reader.ReadRange(context.Background(), res.GenerationID, start, readLen)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(warm.Data)) != readLen {
		t.Fatalf("warm returned %d want %d", len(warm.Data), readLen)
	}

	const runs = 20
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var framesOpened int
	for i := 0; i < runs; i++ {
		rr, err := reader.ReadRange(context.Background(), res.GenerationID, start, readLen)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(rr.Data)) != readLen {
			t.Fatalf("run %d returned %d", i, len(rr.Data))
		}
		framesOpened = rr.FramesOpened
		// Must not open every frame of the generation for an 8 KiB mid-window.
		if rr.FramesOpened > 2 {
			t.Fatalf("FramesOpened=%d want ≤2 for 8KiB window (not whole log)", rr.FramesOpened)
		}
		if rr.DecompressedBytes > 2*int64(frameDecoded) {
			t.Fatalf("DecompressedBytes=%d exceeds 2×frame (%d) — O(whole log)?",
				rr.DecompressedBytes, 2*frameDecoded)
		}
	}
	runtime.ReadMemStats(&after)
	var allocDelta uint64
	if after.TotalAlloc >= before.TotalAlloc {
		allocDelta = after.TotalAlloc - before.TotalAlloc
	}
	avgAlloc := allocDelta / runs

	// Gate: average alloc per ReadRange must be well below whole-log size.
	// Allow several frame-sized buffers + decoder overhead; fail if O(total log).
	const maxAvgAlloc = uint64(2 * frameDecoded * 4) // ~2 MiB headroom per call (generous for race)
	if avgAlloc > maxAvgAlloc {
		t.Fatalf("avg alloc/ReadRange=%d exceeds %d (totalDecoded=%d) — possible whole-log path",
			avgAlloc, maxAvgAlloc, totalDecoded)
	}
	// Stronger: avg must be < total decoded (proves not proportional to whole log for 1 MiB).
	if avgAlloc >= uint64(totalDecoded) {
		t.Fatalf("avg alloc %d ≥ totalDecoded %d (memory proportional to whole log)", avgAlloc, totalDecoded)
	}

	// AllocsPerRun: small fixed window should not scale with log size (sanity on object count).
	// Use a separate generation for AllocsPerRun isolation.
	allocs := testing.AllocsPerRun(10, func() {
		_, _ = reader.ReadRange(context.Background(), res.GenerationID, start, readLen)
	})
	// Heuristic: thousands of allocs would suggest buffering whole log; keep a high but
	// useful ceiling that still fails catastrophic regressions.
	if allocs > 5000 {
		t.Fatalf("AllocsPerRun=%.0f too high for 8KiB range (possible unbounded path)", allocs)
	}
	t.Logf("FLC-070 bounded read: totalDecoded=%d read=%d framesOpened=%d avgAlloc=%d AllocsPerRun=%.1f",
		totalDecoded, readLen, framesOpened, avgAlloc, allocs)
}

// TestBoundedMem_Import_MaxInFlightFrame: PeerImportSink WriteFrame is frame-at-a-time;
// max pure-zstd size observed ≤ MaxZstdFrameBytes and equals largest single frame.
func TestBoundedMem_Import_MaxInFlightFrame(t *testing.T) {
	parts := fleetCompressibleParts(3, 200<<10) // 600 KiB decoded
	wm, frames, full := buildImportFixture(t, parts)
	decoded := int64(len(full))
	var maxZ int
	for _, f := range frames {
		if len(f.PureZstd) > maxZ {
			maxZ = len(f.PureZstd)
		}
	}

	meta, fr, _ := openImportStore(t)
	track := &trackPeerSink{inner: store.NewPeerImportSink(meta, fr)}
	res, err := fleetcache.RunImport(context.Background(), track, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	track.mu.Lock()
	defer track.mu.Unlock()
	if track.maxFrame > fleetcache.MaxZstdFrameBytes {
		t.Fatalf("max in-flight %d > MaxZstdFrameBytes %d", track.maxFrame, fleetcache.MaxZstdFrameBytes)
	}
	if track.maxFrame != maxZ {
		t.Fatalf("maxFrame=%d want largest pure zstd %d (frame-at-a-time)", track.maxFrame, maxZ)
	}
	if int64(track.maxFrame) >= decoded {
		t.Fatalf("in-flight O(whole log): %d >= %d", track.maxFrame, decoded)
	}
	if track.writeCalls != len(frames) {
		t.Fatalf("writes=%d want %d", track.writeCalls, len(frames))
	}
	// Residual: SQLite writer contention under concurrent origin+import not measured here.
	if strings.Contains(res.Residual, "token") || strings.Contains(res.LocatorHash, "token=") {
		t.Fatal("import residual must stay secret-free")
	}
}

// TestSLO_ExportWire_LessThanDecoded is a named SLO gate for pure-zstd export bandwidth.
func TestSLO_ExportWire_LessThanDecoded(t *testing.T) {
	parts := fleetCompressibleParts(4, 128<<10)
	wm, frames, full := buildImportFixture(t, parts)
	meta, fr, _ := openImportStore(t)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	exported := exportAllPure(t, meta, fr, res.GenerationID, nil)
	var wire int64
	for _, e := range exported {
		wire += int64(len(e.PureZstd))
	}
	decoded := int64(len(full))
	ratio := float64(wire) / float64(decoded)
	const maxRatio = 0.5
	if ratio >= maxRatio {
		t.Fatalf("export wire/decoded %.3f >= %.2f (wire=%d decoded=%d)", ratio, maxRatio, wire, decoded)
	}
	t.Logf("FLC-070 residual: multi-member lab bandwidth SLO not measured; SQLite contention deep bench residual; unit ratio=%.3f", ratio)
}

// BenchmarkExportPureZstd_MultiFrame optional -bench (gates are Test* assertions).
func BenchmarkExportPureZstd_MultiFrame(b *testing.B) {
	parts := fleetCompressibleParts(4, 64<<10)
	wm, frames, _ := buildImportFixtureTB(b, parts)
	meta, fr, _ := openImportStoreTB(b)
	sink := store.NewPeerImportSink(meta, fr)
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		b.Fatalf("%+v %v", res, err)
	}
	chunks, err := meta.ListChunks(context.Background(), res.GenerationID)
	if err != nil || len(chunks) == 0 {
		b.Fatalf("%v n=%d", err, len(chunks))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, c := range chunks {
			if _, err := store.ExportPureZstd(fr.DataDir(), c, nil); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func buildImportFixtureTB(tb testing.TB, parts [][]byte) (fleetcache.WireManifest, []fleetcache.ImportFrameBytes, []byte) {
	tb.Helper()
	var full bytes.Buffer
	var frames []fleetcache.FrameDescriptor
	var importFrames []fleetcache.ImportFrameBytes
	var rawOff, lineOff int64
	for i, raw := range parts {
		full.Write(raw)
		z := zstdCompressTB(tb, raw)
		lines := int64(0)
		for _, c := range raw {
			if c == '\n' {
				lines++
			}
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			lines++
		}
		sumRaw := sha256.Sum256(raw)
		sumZ := sha256.Sum256(z)
		frames = append(frames, fleetcache.FrameDescriptor{
			Seq: i, RawStart: rawOff, RawEnd: rawOff + int64(len(raw)),
			LineStart: lineOff, LineEnd: lineOff + lines,
			DecodedSize: int64(len(raw)), DecodedSHA256: hex.EncodeToString(sumRaw[:]),
			ZstdSize: int64(len(z)), ZstdSHA256: hex.EncodeToString(sumZ[:]),
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
		tb.Fatal(err)
	}
	return wm, importFrames, full.Bytes()
}

func openImportStoreTB(tb testing.TB) (*store.Meta, *store.Frames, string) {
	tb.Helper()
	dir := tb.TempDir() + "/profiles/recv"
	meta, err := store.Open(dir)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = fr.Close() })
	return meta, fr, dir
}

func zstdCompressTB(tb testing.TB, raw []byte) []byte {
	tb.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true))
	if err != nil {
		tb.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(raw, nil)
}
