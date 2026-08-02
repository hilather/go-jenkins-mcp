package archive_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/hilather/go-jenkins-mcp/internal/archive"
)

// PERF-002 L2 seekable multi-frame pack baselines (native Go reader; no ratarmount).
//
// Measures pack build (zero-recompress vs compatibility repack), cold open +
// warm range reads, frames opened, and amplification. Default go test stays
// fast; large sizes are env-gated.
//
// Run:
//
//	go test ./internal/archive -bench=L2Pack -benchmem
//	go test ./internal/archive -run 'L2Pack|TestL2' -count=1
//
// Optional large sizes:
//
//	PERF_BENCH_100MIB=1 go test ./internal/archive -bench=L2Pack100MiB -benchmem -count=1
//
// Machine-readable capture (PERF_L2_BASELINE_JSON should be absolute; go test
// CWD is the package directory):
//
//	PERF_L2_BASELINE_JSON="$PWD/dist/perf-l2-baseline.json" \
//	  go test ./internal/archive -run TestL2PackBaselineCapture -count=1

const (
	l2MiB              = 1024 * 1024
	l2RangeRequest     = 8 * 1024 // representative tool-sized range
	l2DefaultMembers   = 4
	l2BenchFrameTarget = 256 * 1024 // compatibility repack target (forces multi-frame on ≥1 MiB)
	// CI unit tests: keep total payload small for default go test.
	l2CIMemberBytes = 4 * 1024
	l2CIMembers     = 4
	l2CIFrameTarget = 1024
	// Amplification budget: decompressed bytes / logical returned for a small range
	// must stay well below full-pack extraction (target: only intersecting frames).
	l2MaxRangeAmplification = 64.0 // 8 KiB range may open ≤ ~512 KiB raw frames
	l2ReadSamples           = 21   // odd count for clean p50
)

// ---------------------------------------------------------------------------
// CI-safe unit tests (always run)
// ---------------------------------------------------------------------------

// TestL2Pack_CISmallMultiFrameSeekAndRange asserts multi-frame layout, seek
// table, and range correctness under budgets on a tiny pack (default go test).
func TestL2Pack_CISmallMultiFrameSeekAndRange(t *testing.T) {
	members := l2SyntheticMembers(l2CIMembers, l2CIMemberBytes)
	data, st, err := archive.WritePack(members, archive.WriteOptions{
		PackID:           "perf002-ci-small",
		TargetFrameBytes: l2CIFrameTarget,
	})
	if err != nil {
		t.Fatalf("WritePack: %v", err)
	}
	if len(st.Frames) < archive.MinContentFrames {
		t.Fatalf("need multi-frame pack, got %d content frames", len(st.Frames))
	}
	if st.PackID != "perf002-ci-small" {
		t.Fatalf("pack id %q", st.PackID)
	}
	if len(st.Members) != l2CIMembers {
		t.Fatalf("members %d want %d", len(st.Members), l2CIMembers)
	}

	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatalf("OpenPack: %v", err)
	}
	defer p.Close()

	if err := p.VerifyContentFrames(); err != nil {
		t.Fatalf("VerifyContentFrames: %v", err)
	}
	if p.SeekTable() == nil || p.SeekTable().TarSize <= 0 {
		t.Fatal("seek table missing or empty tar_size")
	}

	ctx := context.Background()
	// Full member correctness.
	for _, m := range members {
		got, _, stats, err := p.ReadMember(ctx, m.Name)
		if err != nil {
			t.Fatalf("ReadMember %s: %v", m.Name, err)
		}
		if !bytes.Equal(got, m.Body) {
			t.Fatalf("member %s body mismatch", m.Name)
		}
		if stats.LogicalBytes != int64(len(m.Body)) {
			t.Fatalf("logical %d want %d", stats.LogicalBytes, len(m.Body))
		}
	}

	// Range read: middle of last member; must not open every content frame when
	// the pack has enough frames for isolation.
	last := members[len(members)-1]
	off := int64(l2CIMemberBytes / 4)
	length := int64(512)
	if length > int64(len(last.Body))-off {
		length = int64(len(last.Body)) - off
	}
	got, meta, stats, err := p.ReadMemberRange(ctx, last.Name, off, length)
	if err != nil {
		t.Fatalf("ReadMemberRange: %v", err)
	}
	want := last.Body[off : off+length]
	if !bytes.Equal(got, want) {
		t.Fatalf("range body mismatch: got %d want %d bytes", len(got), len(want))
	}
	if stats.FramesOpened < 1 {
		t.Fatal("range must open ≥1 frame")
	}
	if stats.ContentFrames < archive.MinContentFrames {
		t.Fatalf("content frames %d", stats.ContentFrames)
	}
	// No full-pack decompression for a 512-byte range when multi-frame.
	fullTAR, err := p.SequentialTAR()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Frames) >= 4 && stats.DecompressedBytes >= int64(len(fullTAR)) {
		t.Fatalf("range opened full pack: decomp=%d tar=%d frames=%d/%d",
			stats.DecompressedBytes, len(fullTAR), stats.FramesOpened, len(st.Frames))
	}
	if meta.FramesOpened != stats.FramesOpened {
		t.Fatalf("meta frames %d stats %d", meta.FramesOpened, stats.FramesOpened)
	}
	if length > 0 {
		amp := float64(stats.DecompressedBytes) / float64(length)
		if amp > l2MaxRangeAmplification && stats.FramesOpened >= len(st.Frames) {
			t.Fatalf("amplification %.1fx with all frames opened (budget %.0fx)", amp, l2MaxRangeAmplification)
		}
	}
}

// TestL2Pack_ZeroRecompressVsRepackCorrectness checks both pack paths produce
// byte-identical member bodies and that zero-recompress embeds payload frames.
func TestL2Pack_ZeroRecompressVsRepackCorrectness(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	bodies := [][]byte{
		[]byte("zero-recompress-member-a\n" + string(bytes.Repeat([]byte("A"), 800))),
		[]byte("zero-recompress-member-b\n" + string(bytes.Repeat([]byte("B"), 800))),
	}
	genCopy := make([]archive.GenerationMember, len(bodies))
	genRepack := make([]archive.GenerationMember, len(bodies))
	for i, body := range bodies {
		name := fmt.Sprintf("logs/job/%d/consoleText", i+1)
		frame := enc.EncodeAll(body, nil)
		genCopy[i] = archive.GenerationMember{
			Name:          name,
			Body:          body,
			PayloadFrames: [][]byte{frame},
		}
		genRepack[i] = archive.GenerationMember{Name: name, Body: body}
	}

	copyData, copyST, err := archive.PackFromGenerations(genCopy, archive.PackFromGenerationsOptions{
		PackID: "perf002-copy",
	})
	if err != nil {
		t.Fatalf("zero-recompress: %v", err)
	}
	prefer := false
	repackData, repackST, err := archive.PackFromGenerations(genRepack, archive.PackFromGenerationsOptions{
		PackID:           "perf002-repack",
		PreferCopy:       &prefer,
		TargetFrameBytes: 256,
	})
	if err != nil {
		t.Fatalf("repack: %v", err)
	}

	// Copy path must retain payload frames; repack uses content frames.
	if countFrameKind(copyST, archive.FrameKindPayload) < 2 {
		t.Fatalf("zero-recompress expected ≥2 payload frames, got kinds: %v", frameKinds(copyST))
	}
	if countFrameKind(repackST, archive.FrameKindPayload) != 0 {
		t.Fatal("repack path must not emit payload frames")
	}
	if len(repackST.Frames) < archive.MinContentFrames {
		t.Fatalf("repack frames %d", len(repackST.Frames))
	}

	// Payload bytes embedded unchanged in copy pack.
	for _, f := range copyST.Frames {
		if f.Kind != archive.FrameKindPayload {
			continue
		}
		slice := copyData[f.CompressedOffset : f.CompressedOffset+f.CompressedSize]
		if archive.Sha256Hex(slice) != f.FrameSHA256 {
			t.Fatal("payload frame bytes altered in zero-recompress pack")
		}
	}

	for _, label := range []struct {
		name string
		data []byte
	}{
		{"copy", copyData},
		{"repack", repackData},
	} {
		p, err := archive.OpenPack(label.data)
		if err != nil {
			t.Fatalf("OpenPack %s: %v", label.name, err)
		}
		for i, body := range bodies {
			name := fmt.Sprintf("logs/job/%d/consoleText", i+1)
			got, _, _, err := p.ReadMember(context.Background(), name)
			if err != nil {
				p.Close()
				t.Fatalf("%s ReadMember %s: %v", label.name, name, err)
			}
			if !bytes.Equal(got, body) {
				p.Close()
				t.Fatalf("%s body mismatch for %s", label.name, name)
			}
		}
		p.Close()
	}

	// Both packs are multi-frame seekable (not single-frame).
	if len(copyST.Frames) < archive.MinContentFrames {
		t.Fatalf("copy frames %d", len(copyST.Frames))
	}
	_ = repackData // used above
}

// TestL2Pack_RangeDoesNotFullExtract is a CI regression lock for PERF-002:
// a small random range must not decompress the entire multi-frame pack.
func TestL2Pack_RangeDoesNotFullExtract(t *testing.T) {
	const memberBytes = 48 * 1024
	const nMembers = 3
	members := l2SyntheticMembers(nMembers, memberBytes)
	data, st, err := archive.WritePack(members, archive.WriteOptions{
		PackID:           "perf002-amp",
		TargetFrameBytes: 4 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Frames) < 8 {
		t.Fatalf("need many frames for isolation, got %d", len(st.Frames))
	}
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Cold open already done; warm range.
	const off = 1000
	const length = 4096
	body, _, stats, err := p.ReadMemberRange(context.Background(), members[1].Name, off, length)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != length {
		t.Fatalf("got %d bytes", len(body))
	}
	if stats.FramesOpened >= len(st.Frames) {
		t.Fatalf("range opened all %d frames (full-pack extraction); decomp=%d",
			len(st.Frames), stats.DecompressedBytes)
	}
	amp := float64(stats.DecompressedBytes) / float64(length)
	if amp > l2MaxRangeAmplification {
		t.Fatalf("amplification %.1fx exceeds budget %.0fx (frames_opened=%d/%d decomp=%d)",
			amp, l2MaxRangeAmplification, stats.FramesOpened, len(st.Frames), stats.DecompressedBytes)
	}
	want := members[1].Body[off : off+length]
	if !bytes.Equal(body, want) {
		t.Fatal("range content mismatch")
	}
}

// ---------------------------------------------------------------------------
// Continuous benchmarks (opt-in large sizes)
// ---------------------------------------------------------------------------

func BenchmarkL2PackBuild_Repack1MiB(b *testing.B) {
	benchL2PackBuild(b, 1*l2MiB, l2DefaultMembers, false)
}

func BenchmarkL2PackBuild_Repack10MiB(b *testing.B) {
	benchL2PackBuild(b, 10*l2MiB, l2DefaultMembers, false)
}

func BenchmarkL2PackBuild_Repack100MiB(b *testing.B) {
	if os.Getenv("PERF_BENCH_100MIB") == "" {
		b.Skip("set PERF_BENCH_100MIB=1 to run 100 MiB L2 pack build baseline")
	}
	benchL2PackBuild(b, 100*l2MiB, l2DefaultMembers, false)
}

func BenchmarkL2PackBuild_ZeroRecompress1MiB(b *testing.B) {
	benchL2PackBuild(b, 1*l2MiB, l2DefaultMembers, true)
}

func BenchmarkL2PackBuild_ZeroRecompress10MiB(b *testing.B) {
	benchL2PackBuild(b, 10*l2MiB, l2DefaultMembers, true)
}

func BenchmarkL2PackBuild_ZeroRecompress100MiB(b *testing.B) {
	if os.Getenv("PERF_BENCH_100MIB") == "" {
		b.Skip("set PERF_BENCH_100MIB=1 to run 100 MiB zero-recompress L2 pack baseline")
	}
	benchL2PackBuild(b, 100*l2MiB, l2DefaultMembers, true)
}

func BenchmarkL2PackRangeRead_Warm1MiB(b *testing.B) {
	benchL2PackRangeRead(b, 1*l2MiB, l2DefaultMembers, false, false)
}

func BenchmarkL2PackRangeRead_Cold1MiB(b *testing.B) {
	benchL2PackRangeRead(b, 1*l2MiB, l2DefaultMembers, false, true)
}

func BenchmarkL2PackRangeRead_Warm10MiB(b *testing.B) {
	benchL2PackRangeRead(b, 10*l2MiB, l2DefaultMembers, false, false)
}

func BenchmarkL2PackRangeRead_Cold10MiB(b *testing.B) {
	benchL2PackRangeRead(b, 10*l2MiB, l2DefaultMembers, false, true)
}

func BenchmarkL2PackRangeRead_Warm100MiB(b *testing.B) {
	if os.Getenv("PERF_BENCH_100MIB") == "" {
		b.Skip("set PERF_BENCH_100MIB=1 to run 100 MiB range-read baseline")
	}
	benchL2PackRangeRead(b, 100*l2MiB, l2DefaultMembers, false, false)
}

func benchL2PackBuild(b *testing.B, totalBytes, nMembers int, zeroRecompress bool) {
	b.Helper()
	perMember := totalBytes / nMembers
	if perMember < 1 {
		b.Fatal("per-member size < 1")
	}

	var gens []archive.GenerationMember
	var inputs []archive.MemberInput
	if zeroRecompress {
		gens = l2SyntheticGenerations(b, nMembers, perMember, true)
	} else {
		inputs = l2SyntheticMembers(nMembers, perMember)
	}

	// Warmup once outside the loop.
	if zeroRecompress {
		if _, _, err := archive.PackFromGenerations(gens, archive.PackFromGenerationsOptions{
			PackID: "bench-warmup",
		}); err != nil {
			b.Fatalf("warmup zero-recompress: %v", err)
		}
	} else {
		if _, _, err := archive.WritePack(inputs, archive.WriteOptions{
			PackID:           "bench-warmup",
			TargetFrameBytes: l2BenchFrameTarget,
		}); err != nil {
			b.Fatalf("warmup repack: %v", err)
		}
	}

	b.ReportAllocs()
	b.SetBytes(int64(totalBytes))
	b.ResetTimer()

	var lastPackBytes int64
	var lastFrames int
	for i := 0; i < b.N; i++ {
		packID := fmt.Sprintf("bench-build-%d", i)
		var data []byte
		var st *archive.SeekTable
		var err error
		if zeroRecompress {
			data, st, err = archive.PackFromGenerations(gens, archive.PackFromGenerationsOptions{
				PackID: packID,
			})
		} else {
			data, st, err = archive.WritePack(inputs, archive.WriteOptions{
				PackID:           packID,
				TargetFrameBytes: l2BenchFrameTarget,
			})
		}
		if err != nil {
			b.Fatalf("pack: %v", err)
		}
		lastPackBytes = int64(len(data))
		lastFrames = len(st.Frames)
		if lastFrames < archive.MinContentFrames {
			b.Fatalf("not multi-frame: %d", lastFrames)
		}
		// Keep a live reference so the compiler cannot DCE the pack.
		if data[0] == 0 && data[1] == 0 {
			b.Fatalf("unexpected empty-looking pack head")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(lastPackBytes), "pack-B")
	b.ReportMetric(float64(lastFrames), "frames")
	if zeroRecompress {
		b.ReportMetric(1, "zero-recompress")
	} else {
		b.ReportMetric(0, "zero-recompress")
	}
}

func benchL2PackRangeRead(b *testing.B, totalBytes, nMembers int, zeroRecompress, coldOpen bool) {
	b.Helper()
	perMember := totalBytes / nMembers
	data, st, entryID := l2BuildOnce(b, nMembers, perMember, zeroRecompress)
	if len(st.Frames) < archive.MinContentFrames {
		b.Fatalf("frames %d", len(st.Frames))
	}
	memberSize := int64(perMember)
	off := memberSize / 4
	if off+int64(l2RangeRequest) > memberSize {
		off = 0
	}

	// Warm path: open once and reuse. Cold path: OpenPack each iteration.
	var warm *archive.Pack
	if !coldOpen {
		var err error
		warm, err = archive.OpenPack(data)
		if err != nil {
			b.Fatal(err)
		}
		defer warm.Close()
		// Touch once so first-frame decode is outside the timed loop.
		if _, _, _, err := warm.ReadMemberRange(context.Background(), entryID, off, int64(l2RangeRequest)); err != nil {
			b.Fatalf("warmup range: %v", err)
		}
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(int64(l2RangeRequest))
	b.ResetTimer()

	var totalFrames, totalDecomp int64
	for i := 0; i < b.N; i++ {
		var p *archive.Pack
		if coldOpen {
			var err error
			p, err = archive.OpenPack(data)
			if err != nil {
				b.Fatal(err)
			}
		} else {
			p = warm
		}
		body, _, stats, err := p.ReadMemberRange(ctx, entryID, off, int64(l2RangeRequest))
		if coldOpen {
			_ = p.Close()
		}
		if err != nil {
			b.Fatalf("range: %v", err)
		}
		if len(body) != l2RangeRequest {
			b.Fatalf("got %d want %d", len(body), l2RangeRequest)
		}
		totalFrames += int64(stats.FramesOpened)
		totalDecomp += stats.DecompressedBytes
	}
	b.StopTimer()
	n := float64(b.N)
	avgFrames := float64(totalFrames) / n
	avgDecomp := float64(totalDecomp) / n
	b.ReportMetric(avgFrames, "frames-opened")
	b.ReportMetric(avgDecomp, "decomp-B")
	b.ReportMetric(avgDecomp/float64(l2RangeRequest), "amplification-x")
	b.ReportMetric(float64(len(data)), "pack-B")
	b.ReportMetric(float64(len(st.Frames)), "content-frames")
}

// ---------------------------------------------------------------------------
// Machine-readable capture
// ---------------------------------------------------------------------------

// l2PackBaselineSample is one fixed-size measurement for PERF-002 artifacts.
type l2PackBaselineSample struct {
	Name              string  `json:"name"`
	TotalPayloadBytes int64   `json:"total_payload_bytes"`
	Members           int     `json:"members"`
	PackBytes         int64   `json:"pack_bytes"`
	ContentFrames     int     `json:"content_frames"`
	BuildMs           float64 `json:"build_ms"`
	// Range read metrics (8 KiB from mid member).
	RangeOffset    int64   `json:"range_offset"`
	RangeLength    int64   `json:"range_length"`
	ReadColdP50Ms  float64 `json:"read_cold_p50_ms"`
	ReadColdP95Ms  float64 `json:"read_cold_p95_ms"`
	ReadWarmP50Ms  float64 `json:"read_warm_p50_ms"`
	ReadWarmP95Ms  float64 `json:"read_warm_p95_ms"`
	FramesOpened   int     `json:"frames_opened"`
	DecompressedB  int64   `json:"decompressed_bytes"`
	AmplificationX float64 `json:"amplification_x"`
	RemoteBytes    *int64  `json:"remote_bytes"` // always null for local pack (N/A)
	Codec          string  `json:"codec"`
	ZeroRecompress bool    `json:"zero_recompress"`
	RangeCorrect   bool    `json:"range_correct"`
	MultiFrame     bool    `json:"multi_frame"`
}

type l2PackBaselineReport struct {
	TaskID     string                 `json:"task_id"`
	CapturedAt time.Time              `json:"captured_at"`
	GoVersion  string                 `json:"go_version"`
	GOOS       string                 `json:"goos"`
	GOARCH     string                 `json:"goarch"`
	NumCPU     int                    `json:"num_cpu"`
	Notes      string                 `json:"notes"`
	Samples    []l2PackBaselineSample `json:"samples"`
}

// TestL2PackBaselineCapture measures fixed L2 pack sizes once and optionally
// writes JSON when PERF_L2_BASELINE_JSON is set. Always runs 1 MiB / 10 MiB
// (repack + zero-recompress); 100 MiB is opt-in via PERF_BENCH_100MIB.
func TestL2PackBaselineCapture(t *testing.T) {
	scenarios := []struct {
		name           string
		totalBytes     int
		members        int
		zeroRecompress bool
		env            string
	}{
		{name: "repack_1MiB_4m", totalBytes: 1 * l2MiB, members: l2DefaultMembers, zeroRecompress: false},
		{name: "repack_10MiB_4m", totalBytes: 10 * l2MiB, members: l2DefaultMembers, zeroRecompress: false},
		{name: "zero_recompress_1MiB_4m", totalBytes: 1 * l2MiB, members: l2DefaultMembers, zeroRecompress: true},
		{name: "zero_recompress_10MiB_4m", totalBytes: 10 * l2MiB, members: l2DefaultMembers, zeroRecompress: true},
		{name: "repack_100MiB_4m", totalBytes: 100 * l2MiB, members: l2DefaultMembers, zeroRecompress: false, env: "PERF_BENCH_100MIB"},
		{name: "zero_recompress_100MiB_4m", totalBytes: 100 * l2MiB, members: l2DefaultMembers, zeroRecompress: true, env: "PERF_BENCH_100MIB"},
	}

	report := l2PackBaselineReport{
		TaskID:     "PERF-002",
		CapturedAt: time.Now().UTC(),
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		Notes: "PERF-002 MVP: native Go multi-frame seekable .tar.zst (no ratarmount). " +
			"remote_bytes is N/A (local pack only). " +
			"read_*_p50/p95 are wall times for OpenPack+range (cold) or range-only (warm). " +
			"amplification_x = decompressed_bytes / range_length. " +
			"Residual: absolute ms varies by hardware; lock on multi_frame, range_correct, " +
			"and frames_opened << content_frames. ratarmount-rs: no-go until ARC-000 supply " +
			"(see docs/arc/ratarmount-rs-qualification.md). Pack params: codec=zstd, " +
			"compatibility TargetFrameBytes=256KiB, range=8KiB.",
	}

	for _, sc := range scenarios {
		if sc.env != "" && os.Getenv(sc.env) == "" {
			t.Logf("skip %s (set %s=1 to include)", sc.name, sc.env)
			continue
		}
		sample := measureL2PackOnce(t, sc.name, sc.totalBytes, sc.members, sc.zeroRecompress)
		report.Samples = append(report.Samples, sample)
		t.Logf("%s: pack_B=%d members=%d frames=%d build_ms=%.2f warm_p50=%.3fms warm_p95=%.3fms "+
			"cold_p50=%.3fms frames_opened=%d amp=%.2fx zero_recompress=%v multi=%v correct=%v",
			sample.Name, sample.PackBytes, sample.Members, sample.ContentFrames, sample.BuildMs,
			sample.ReadWarmP50Ms, sample.ReadWarmP95Ms, sample.ReadColdP50Ms,
			sample.FramesOpened, sample.AmplificationX, sample.ZeroRecompress,
			sample.MultiFrame, sample.RangeCorrect)

		if !sample.MultiFrame {
			t.Fatalf("%s: pack is not multi-frame (content_frames=%d)", sample.Name, sample.ContentFrames)
		}
		if !sample.RangeCorrect {
			t.Fatalf("%s: range read content mismatch", sample.Name)
		}
		if sample.FramesOpened < 1 {
			t.Fatalf("%s: frames_opened=%d", sample.Name, sample.FramesOpened)
		}
		// No full-pack extraction for 8 KiB range when enough frames exist.
		if sample.ContentFrames >= 4 && sample.FramesOpened >= sample.ContentFrames {
			t.Fatalf("%s: range opened all %d frames (full-pack extraction)", sample.Name, sample.ContentFrames)
		}
		// Compatibility repack uses ~256 KiB frames → amp budget applies.
		// Zero-recompress embeds one L1 payload per member: amp ≈ member/range
		// (can exceed l2MaxRangeAmplification for multi-MiB members). Lock on
		// frames_opened << content_frames instead; record amp for evidence.
		if !sample.ZeroRecompress && sample.ContentFrames >= 4 && sample.AmplificationX > l2MaxRangeAmplification {
			t.Fatalf("%s: repack amplification %.1fx exceeds budget %.0fx",
				sample.Name, sample.AmplificationX, l2MaxRangeAmplification)
		}
		if sample.ZeroRecompress && sample.FramesOpened > 3 && sample.ContentFrames >= 6 {
			// Header+payload(+padding edge) only — opening many frames is a bug.
			t.Fatalf("%s: zero-recompress range opened %d frames (want ≤3 payload-local)",
				sample.Name, sample.FramesOpened)
		}
	}

	if len(report.Samples) < 4 {
		t.Fatalf("expected at least 1MiB+10MiB × (repack|zero_recompress) samples, got %d", len(report.Samples))
	}

	// Cross-path: zero-recompress should not be slower to build by orders of
	// magnitude on the same payload (informational; hardware variance OK).
	var repack1, copy1 *l2PackBaselineSample
	for i := range report.Samples {
		s := &report.Samples[i]
		if s.Name == "repack_1MiB_4m" {
			repack1 = s
		}
		if s.Name == "zero_recompress_1MiB_4m" {
			copy1 = s
		}
	}
	if repack1 != nil && copy1 != nil {
		t.Logf("1MiB build_ms: repack=%.2f zero_recompress=%.2f (CPU benefit of copy path)",
			repack1.BuildMs, copy1.BuildMs)
		if copy1.ZeroRecompress != true || repack1.ZeroRecompress != false {
			t.Fatal("zero_recompress flags inverted")
		}
	}

	if path := os.Getenv("PERF_L2_BASELINE_JSON"); path != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", dir, err)
			}
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote machine-readable L2 baseline to %s", path)
	}
}

func measureL2PackOnce(t *testing.T, name string, totalBytes, nMembers int, zeroRecompress bool) l2PackBaselineSample {
	t.Helper()
	perMember := totalBytes / nMembers
	if perMember < l2RangeRequest*2 {
		t.Fatalf("%s: per-member %d too small for range sample", name, perMember)
	}

	// Build once and time it.
	start := time.Now()
	data, st, entryID, body := l2BuildOnceWithBody(t, nMembers, perMember, zeroRecompress)
	buildMs := float64(time.Since(start).Microseconds()) / 1000.0

	off := int64(perMember / 4)
	length := int64(l2RangeRequest)
	want := body[off : off+length]

	// Cold samples: OpenPack + range each time.
	cold := make([]float64, l2ReadSamples)
	var lastStats archive.ReadStats
	var rangeOK bool
	ctx := context.Background()
	for i := 0; i < l2ReadSamples; i++ {
		t0 := time.Now()
		p, err := archive.OpenPack(data)
		if err != nil {
			t.Fatalf("%s OpenPack cold: %v", name, err)
		}
		got, _, stats, err := p.ReadMemberRange(ctx, entryID, off, length)
		_ = p.Close()
		cold[i] = float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			t.Fatalf("%s cold range: %v", name, err)
		}
		lastStats = stats
		rangeOK = bytes.Equal(got, want)
		if !rangeOK {
			break
		}
	}

	// Warm samples: single open, many ranges.
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatalf("%s OpenPack warm: %v", name, err)
	}
	defer p.Close()
	// Discard first warm touch.
	if _, _, _, err := p.ReadMemberRange(ctx, entryID, off, length); err != nil {
		t.Fatalf("%s warm touch: %v", name, err)
	}
	warm := make([]float64, l2ReadSamples)
	for i := 0; i < l2ReadSamples; i++ {
		t0 := time.Now()
		got, _, stats, err := p.ReadMemberRange(ctx, entryID, off, length)
		warm[i] = float64(time.Since(t0).Microseconds()) / 1000.0
		if err != nil {
			t.Fatalf("%s warm range: %v", name, err)
		}
		lastStats = stats
		if !bytes.Equal(got, want) {
			rangeOK = false
		}
	}

	amp := 0.0
	if length > 0 {
		amp = float64(lastStats.DecompressedBytes) / float64(length)
	}

	return l2PackBaselineSample{
		Name:              name,
		TotalPayloadBytes: int64(totalBytes),
		Members:           nMembers,
		PackBytes:         int64(len(data)),
		ContentFrames:     len(st.Frames),
		BuildMs:           buildMs,
		RangeOffset:       off,
		RangeLength:       length,
		ReadColdP50Ms:     percentile(cold, 50),
		ReadColdP95Ms:     percentile(cold, 95),
		ReadWarmP50Ms:     percentile(warm, 50),
		ReadWarmP95Ms:     percentile(warm, 95),
		FramesOpened:      lastStats.FramesOpened,
		DecompressedB:     lastStats.DecompressedBytes,
		AmplificationX:    amp,
		RemoteBytes:       nil, // N/A — local pack, no Jenkins wire
		Codec:             "zstd",
		ZeroRecompress:    zeroRecompress,
		RangeCorrect:      rangeOK,
		MultiFrame:        len(st.Frames) >= archive.MinContentFrames,
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func l2SyntheticMembers(n, perMember int) []archive.MemberInput {
	out := make([]archive.MemberInput, n)
	for i := 0; i < n; i++ {
		// Deterministic alphabet cycle + member index marker for isolation.
		body := make([]byte, perMember)
		base := byte('A' + (i % 26))
		for j := range body {
			body[j] = base + byte(j%3)
		}
		out[i] = archive.MemberInput{
			Name: fmt.Sprintf("logs/job/%d/consoleText", i+1),
			Body: body,
			Mode: 0o644,
		}
	}
	return out
}

func l2SyntheticGenerations(tb testing.TB, n, perMember int, withPayload bool) []archive.GenerationMember {
	tb.Helper()
	members := l2SyntheticMembers(n, perMember)
	out := make([]archive.GenerationMember, n)
	var enc *zstd.Encoder
	if withPayload {
		var err error
		enc, err = zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderLevel(zstd.SpeedDefault))
		if err != nil {
			tb.Fatalf("zstd encoder: %v", err)
		}
		defer enc.Close()
	}
	for i, m := range members {
		g := archive.GenerationMember{Name: m.Name, Body: m.Body, Mode: m.Mode}
		if withPayload && enc != nil {
			g.PayloadFrames = [][]byte{enc.EncodeAll(m.Body, nil)}
		}
		out[i] = g
	}
	return out
}

func l2BuildOnce(tb testing.TB, nMembers, perMember int, zeroRecompress bool) ([]byte, *archive.SeekTable, string) {
	tb.Helper()
	data, st, entryID, _ := l2BuildOnceWithBody(tb, nMembers, perMember, zeroRecompress)
	return data, st, entryID
}

func l2BuildOnceWithBody(tb testing.TB, nMembers, perMember int, zeroRecompress bool) ([]byte, *archive.SeekTable, string, []byte) {
	tb.Helper()
	entryID := "logs/job/2/consoleText"
	if nMembers < 2 {
		entryID = "logs/job/1/consoleText"
	}
	var (
		data []byte
		st   *archive.SeekTable
		err  error
		body []byte
	)
	if zeroRecompress {
		gens := l2SyntheticGenerations(tb, nMembers, perMember, true)
		data, st, err = archive.PackFromGenerations(gens, archive.PackFromGenerationsOptions{
			PackID: "perf002-measure",
		})
		// Member index 1 (or 0) body for expected range.
		idx := 1
		if nMembers < 2 {
			idx = 0
		}
		body = gens[idx].Body
	} else {
		inputs := l2SyntheticMembers(nMembers, perMember)
		data, st, err = archive.WritePack(inputs, archive.WriteOptions{
			PackID:           "perf002-measure",
			TargetFrameBytes: l2BenchFrameTarget,
		})
		idx := 1
		if nMembers < 2 {
			idx = 0
		}
		body = inputs[idx].Body
	}
	if err != nil {
		tb.Fatalf("build pack: %v", err)
	}
	return data, st, entryID, body
}

func percentile(samples []float64, p int) float64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	if p <= 0 {
		return cp[0]
	}
	if p >= 100 {
		return cp[len(cp)-1]
	}
	// Nearest-rank method.
	rank := (p*len(cp) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(cp) {
		rank = len(cp)
	}
	return cp[rank-1]
}

func countFrameKind(st *archive.SeekTable, kind string) int {
	if st == nil {
		return 0
	}
	n := 0
	for _, f := range st.Frames {
		if f.Kind == kind {
			n++
		}
	}
	return n
}

func frameKinds(st *archive.SeekTable) []string {
	if st == nil {
		return nil
	}
	out := make([]string, len(st.Frames))
	for i, f := range st.Frames {
		out[i] = f.Kind
	}
	return out
}
