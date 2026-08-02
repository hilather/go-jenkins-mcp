package fleetcache_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/klauspost/compress/zstd"
)

// FLC-070: offline performance / memory / bandwidth gates for fleet-cache library
// paths. Thresholds are assertions (not hand-waved logs). Multi-member lab bandwidth
// SLO remains residual; SQLite writer contention deep bench is residual (store side).

// wireTrackSink wraps memSink and records pure-zstd wire bytes + max in-flight frame.
// Proves ReplicateSealed / RunImport write one frame at a time (not whole-log buffers).
type wireTrackSink struct {
	memSink
	mu           sync.Mutex
	wireBytes    int64
	maxFrame     int
	writeCalls   int
	frameSizes   []int
	inFlightPeak int // max concurrent pureZstd held during WriteFrame (always 1 for serial)
}

func (s *wireTrackSink) WriteFrame(ctx context.Context, importID, generationID int64, wf fleetcache.WireFrame, pureZstd []byte) error {
	s.mu.Lock()
	n := len(pureZstd)
	s.writeCalls++
	s.wireBytes += int64(n)
	if n > s.maxFrame {
		s.maxFrame = n
	}
	s.frameSizes = append(s.frameSizes, n)
	// Serial ImportSink path: one frame buffer visible per WriteFrame call.
	if n > s.inFlightPeak {
		s.inFlightPeak = n
	}
	s.mu.Unlock()
	return s.memSink.WriteFrame(ctx, importID, generationID, wf, pureZstd)
}

// compressibleParts builds multi-frame highly compressible decoded payloads.
// total ≈ frameCount * frameDecoded (moderate sizes for race-friendly offline gates).
func compressibleParts(frameCount, frameDecoded int) [][]byte {
	parts := make([][]byte, frameCount)
	for i := 0; i < frameCount; i++ {
		// Fixed line so zstd compresses well; ends with newline for line metadata.
		line := fmt.Sprintf("flc070-f%d-compressible-payload-line\n", i)
		buf := make([]byte, 0, frameDecoded+len(line))
		for len(buf) < frameDecoded {
			buf = append(buf, line...)
		}
		parts[i] = buf[:frameDecoded]
	}
	return parts
}

func sumDecodedAndZstd(t testing.TB, parts [][]byte, frames []fleetcache.ImportFrameBytes) (decoded, wire int64) {
	t.Helper()
	if len(parts) != len(frames) {
		t.Fatalf("parts=%d frames=%d", len(parts), len(frames))
	}
	for i, p := range parts {
		decoded += int64(len(p))
		wire += int64(len(frames[i].PureZstd))
	}
	return decoded, wire
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

func sha256HexTB(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// makeSealedManifestBench publishes a sealed multi-frame wire manifest (testing.TB).
func makeSealedManifestBench(tb testing.TB, parts [][]byte) (fleetcache.WireManifest, []fleetcache.ImportFrameBytes) {
	tb.Helper()
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "job/bench", 1)
	if err != nil {
		tb.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		tb.Fatal(err)
	}
	var frames []fleetcache.FrameDescriptor
	var importFrames []fleetcache.ImportFrameBytes
	var rawOff, lineOff int64
	for i, raw := range parts {
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
		frames = append(frames, fleetcache.FrameDescriptor{
			Seq: i, RawStart: rawOff, RawEnd: rawOff + int64(len(raw)),
			LineStart: lineOff, LineEnd: lineOff + lines,
			DecodedSize: int64(len(raw)), DecodedSHA256: sha256HexTB(raw),
			ZstdSize: int64(len(z)), ZstdSHA256: sha256HexTB(z),
		})
		importFrames = append(importFrames, fleetcache.ImportFrameBytes{Seq: i, PureZstd: z})
		rawOff += int64(len(raw))
		lineOff += lines
	}
	wm, err := fleetcache.PublishSealed(fleetcache.SealedPublishInput{
		FleetID: "fleet", CachePool: "pool", ControllerID: "ctrl",
		JobFullName: "job/bench", BuildNumber: 1, Sealed: true, Frames: frames,
	})
	if err != nil {
		tb.Fatal(err)
	}
	if wm.LocatorHash == "" {
		wm.LocatorHash = lh
	}
	return wm, importFrames
}

// TestWireBytes_ReplicateSealed_PureZstdNotDecoded asserts peer replication path
// transfers pure compressed frames only: wire bytes == sum(zstd) and << decoded when
// compressible. Protocol overhead at the library ImportSink boundary is zero (frames only).
func TestWireBytes_ReplicateSealed_PureZstdNotDecoded(t *testing.T) {
	parts := compressibleParts(4, 256<<10) // 1 MiB decoded across 4 frames
	wm, frames := makeSealedManifest(t, parts)
	decoded, wantWire := sumDecodedAndZstd(t, parts, frames)
	if wantWire <= 0 {
		t.Fatal("expected non-empty zstd frames")
	}
	// Gate: well-compressed corpus must not ship decoded totals on the wire.
	if wantWire >= decoded {
		t.Fatalf("fixture not compressible enough: wire=%d decoded=%d", wantWire, decoded)
	}
	// Stronger: expect at least 2× compression on this synthetic corpus.
	if wantWire*2 >= decoded {
		t.Fatalf("expected ≥2× compression: wire=%d decoded=%d", wantWire, decoded)
	}

	// Manifest declared sizes must match pure-zstd payload lengths.
	var manWire int64
	for _, wf := range wm.Frames {
		manWire += wf.ZstdSize
	}
	if manWire != wantWire {
		t.Fatalf("manifest zstd sum %d != frame bytes %d", manWire, wantWire)
	}

	sink := &wireTrackSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("ReplicateSealed: %+v %v", res, err)
	}
	if res.FramesTransferred != len(frames) {
		t.Fatalf("FramesTransferred=%d want %d", res.FramesTransferred, len(frames))
	}

	sink.mu.Lock()
	gotWire := sink.wireBytes
	maxF := sink.maxFrame
	calls := sink.writeCalls
	peak := sink.inFlightPeak
	sink.mu.Unlock()

	// Library path: wire bytes exactly sum(zstd); no decoded payload on sink writes.
	if gotWire != wantWire {
		t.Fatalf("wire bytes transferred=%d want sum(zstd)=%d (decoded=%d)", gotWire, wantWire, decoded)
	}
	// Never equal decoded total when compressed well (bandwidth gate).
	if gotWire == decoded {
		t.Fatalf("wire equals decoded (%d) — must ship pure zstd only", decoded)
	}
	// Small constant overhead at ImportSink: 0 (frames only; HTTP overhead is residual FLC-071 lab).
	const protocolOverheadBudget int64 = 0
	if gotWire > wantWire+protocolOverheadBudget {
		t.Fatalf("wire %d exceeds sum(zstd)+%d", gotWire, protocolOverheadBudget)
	}
	if calls != len(frames) {
		t.Fatalf("WriteFrame calls=%d want %d (frame-at-a-time)", calls, len(frames))
	}
	if maxF > fleetcache.MaxZstdFrameBytes {
		t.Fatalf("max frame %d exceeds MaxZstdFrameBytes %d", maxF, fleetcache.MaxZstdFrameBytes)
	}
	if peak > fleetcache.MaxZstdFrameBytes {
		t.Fatalf("in-flight peak %d exceeds MaxZstdFrameBytes", peak)
	}
	// In-flight is one frame, not whole log.
	if int64(peak) >= decoded {
		t.Fatalf("in-flight peak %d is O(whole log) decoded=%d", peak, decoded)
	}
	t.Logf("FLC-070 wire gate: decoded=%d wire=%d ratio=%.3f frames=%d maxFrame=%d",
		decoded, gotWire, float64(gotWire)/float64(decoded), len(frames), maxF)
}

// TestWireBytes_RunImport_FrameAtATime asserts RunImport writes frames serially with
// max in-flight pure-zstd size ≤ MaxZstdFrameBytes and not O(total decoded).
func TestWireBytes_RunImport_FrameAtATime(t *testing.T) {
	parts := compressibleParts(3, 128<<10) // 384 KiB decoded
	wm, frames := makeSealedManifest(t, parts)
	decoded, wantWire := sumDecodedAndZstd(t, parts, frames)

	sink := &wireTrackSink{}
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("RunImport: %+v %v", res, err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.wireBytes != wantWire {
		t.Fatalf("import wire=%d want %d", sink.wireBytes, wantWire)
	}
	if sink.maxFrame > fleetcache.MaxZstdFrameBytes {
		t.Fatalf("max in-flight frame %d > MaxZstdFrameBytes", sink.maxFrame)
	}
	// Largest single frame must be the peak (proves no whole-log buffer write).
	var maxPartZ int
	for _, f := range frames {
		if len(f.PureZstd) > maxPartZ {
			maxPartZ = len(f.PureZstd)
		}
	}
	if sink.maxFrame != maxPartZ {
		t.Fatalf("maxFrame=%d want largest pure zstd %d", sink.maxFrame, maxPartZ)
	}
	if int64(sink.maxFrame) >= decoded {
		t.Fatalf("maxFrame O(whole log): %d >= decoded %d", sink.maxFrame, decoded)
	}
	if sink.writeCalls != len(frames) {
		t.Fatalf("writes=%d want %d", sink.writeCalls, len(frames))
	}
}

// TestOriginBytes_PeerHitIncreasesAvoided is the measurable origin-dedup counter gate
// via existing FleetCacheMetrics (FLC-061). Multi-member aggregation residual FLC-062+.
func TestOriginBytes_PeerHitIncreasesAvoided(t *testing.T) {
	// Not parallel: package Metrics registry.
	fleetcache.ResetForTest()
	before := fleetcache.Metrics.OriginBytesAvoided()
	const peerDecoded int64 = 250_000
	fleetcache.RecordLookupOutcome("peer", peerDecoded)
	after := fleetcache.Metrics.OriginBytesAvoided()
	if after-before != peerDecoded {
		t.Fatalf("OriginBytesAvoided delta=%d want %d (before=%d after=%d)",
			after-before, peerDecoded, before, after)
	}
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricPeerHit] < 1 {
		t.Fatalf("peer_hit missing: %v", snap)
	}
	if snap[fleetcache.MetricOriginBytesAvoided] != after {
		t.Fatalf("snapshot origin_bytes_avoided=%d want %d", snap[fleetcache.MetricOriginBytesAvoided], after)
	}
	// Secret-free: snapshot keys are fixed dictionary only (no job names / tokens).
	for k := range snap {
		if strings.Contains(k, "job") || strings.Contains(k, "token") || strings.Contains(k, "/") {
			t.Fatalf("metric label must be secret-free low-cardinality name, got %q", k)
		}
	}
}

// TestSLO_ReplicateSealed_WireVsDecoded reports a machine-checkable bandwidth ratio gate
// for RF2 pure-zstd path (same corpus as wire-bytes gate).
func TestSLO_ReplicateSealed_WireVsDecoded(t *testing.T) {
	parts := compressibleParts(4, 256<<10)
	wm, frames := makeSealedManifest(t, parts)
	decoded, wire := sumDecodedAndZstd(t, parts, frames)
	// SLO gate: peer replication bandwidth ≤ pure zstd sum (library path).
	ratio := float64(wire) / float64(decoded)
	const maxWireRatio = 0.5 // synthetic compressible corpus
	if ratio >= maxWireRatio {
		t.Fatalf("wire/decoded ratio %.3f >= %.2f (wire=%d decoded=%d)", ratio, maxWireRatio, wire, decoded)
	}
	sink := &wireTrackSink{}
	if _, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames); err != nil {
		t.Fatal(err)
	}
	if sink.wireBytes != wire {
		t.Fatalf("transferred %d want %d", sink.wireBytes, wire)
	}
	// Residual honesty: full multi-member lab bandwidth SLO not measured here.
	t.Logf("FLC-070 residual: multi-member lab bandwidth SLO (HTTP overhead) not measured; unit wire=%d decoded=%d ratio=%.3f",
		wire, decoded, ratio)
}

// BenchmarkReplicateSealed_MultiFrame is an optional -bench entry (not a CI gate).
// Gates live in TestWireBytes_* / TestSLO_* so default go test -race stays assertion-based.
func BenchmarkReplicateSealed_MultiFrame(b *testing.B) {
	parts := compressibleParts(4, 64<<10)
	wm, frames := makeSealedManifestBench(b, parts)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink := &wireTrackSink{}
		res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
		if err != nil || res.Status != fleetcache.ImportStatusCommitted {
			b.Fatalf("%+v %v", res, err)
		}
	}
}
