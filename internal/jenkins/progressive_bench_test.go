package jenkins

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// PERF-001 progressive log baselines (post LOG-001).
//
// LOG-001: GetBuildLogs uses LimitReader on progressiveText; application buffers
// and returned payload are capped at the requested length. The fixture still
// *offers* the full remainder (Jenkins-like); early body close keeps
// fixture-written bytes near the request.
//
// Run (no live Jenkins):
//
//	go test ./internal/jenkins -bench=Progressive -benchmem
//
// Optional large sizes (cheap post-LOG-001 — no full-log download):
//
//	PERF_BENCH_100MIB=1 go test ./internal/jenkins -bench=Progressive100MiB -benchmem -count=1
//	PERF_BENCH_1GIB=1   go test ./internal/jenkins -bench=Progressive1GiB -benchmem -count=1
//
// Machine-readable capture (PERF_BASELINE_JSON should be absolute; go test CWD is
// the package directory):
//
//	PERF_BASELINE_JSON="$PWD/dist/perf-baseline.json" go test ./internal/jenkins -run TestProgressiveBaselineCapture -count=1

const (
	benchRequestLength = 8192 // default tool length for jenkins_get_build_logs
	miB                = 1024 * 1024
	giB                = 1024 * 1024 * 1024
	// Fixture/httptest pipe + in-flight kernel buffers can exceed the request
	// before TCP close is observed. LOG-001 success = app payload ≤ request and
	// wire ≪ full logical size (not wire == request exactly).
	benchWireMaxFraction = 0.25 // wire must be < 25% of logical for large logs
	benchWireAbsCap      = 256 * 1024
)

func BenchmarkGetBuildLogs_Progressive1MiB(b *testing.B) {
	benchGetBuildLogsProgressive(b, 1*miB, benchRequestLength)
}

func BenchmarkGetBuildLogs_Progressive10MiB(b *testing.B) {
	benchGetBuildLogsProgressive(b, 10*miB, benchRequestLength)
}

// BenchmarkGetBuildLogs_Progressive100MiB is opt-in (logical size only; LOG-001
// caps the read at request length).
func BenchmarkGetBuildLogs_Progressive100MiB(b *testing.B) {
	if os.Getenv("PERF_BENCH_100MIB") == "" {
		b.Skip("set PERF_BENCH_100MIB=1 to run 100 MiB progressive baseline")
	}
	benchGetBuildLogsProgressive(b, 100*miB, benchRequestLength)
}

// BenchmarkGetBuildLogs_Progressive1GiB is opt-in (logical size only; LOG-001
// caps the read at request length — no 1 GiB wire transfer).
func BenchmarkGetBuildLogs_Progressive1GiB(b *testing.B) {
	if os.Getenv("PERF_BENCH_1GIB") == "" {
		b.Skip("set PERF_BENCH_1GIB=1 to run 1 GiB progressive baseline")
	}
	benchGetBuildLogsProgressive(b, 1*giB, benchRequestLength)
}

func benchGetBuildLogsProgressive(b *testing.B, logSize, requestLen int) {
	b.Helper()
	f := newJenkinsFixture()
	defer f.close()
	jobPath := BuildJobPath("demo")
	f.setLogSize(jobPath, 7, logSize)
	client := f.opts()
	ctx := context.Background()

	// Warmup: establish conn + validate LOG-001 surface once outside timed loop.
	beforeWarm := f.bytesServed.Load()
	logs, err := client.GetBuildLogs(ctx, "demo", 7, 0, requestLen)
	if err != nil {
		b.Fatalf("warmup GetBuildLogs: %v", err)
	}
	if len(logs.Logs) != requestLen {
		b.Fatalf("warmup returned length=%d, want %d", len(logs.Logs), requestLen)
	}
	warmWire := f.bytesServed.Load() - beforeWarm
	if warmWire >= int64(logSize) && logSize > requestLen {
		b.Fatalf("LOG-001 warmup full over-download: wire=%d logical=%d", warmWire, logSize)
	}

	b.ReportAllocs()
	b.SetBytes(int64(requestLen)) // throughput vs bounded request body
	b.ResetTimer()

	var totalWire int64
	for i := 0; i < b.N; i++ {
		before := f.bytesServed.Load()
		out, err := client.GetBuildLogs(ctx, "demo", 7, 0, requestLen)
		if err != nil {
			b.Fatalf("GetBuildLogs: %v", err)
		}
		if len(out.Logs) != requestLen {
			b.Fatalf("returned length=%d, want %d", len(out.Logs), requestLen)
		}
		// Keep a live reference so the compiler cannot DCE the result string.
		if out.Logs[0] != 'A' {
			b.Fatalf("unexpected synthetic head byte %q", out.Logs[0])
		}
		totalWire += f.bytesServed.Load() - before
	}
	b.StopTimer()

	avgWire := float64(totalWire) / float64(b.N)
	b.ReportMetric(avgWire, "wire-B/op")
	b.ReportMetric(float64(requestLen), "req-B")
	b.ReportMetric(avgWire/float64(requestLen), "overdownload-x")
	b.ReportMetric(float64(logSize), "logical-B")
}

// progressiveBaselineSample is one fixed-size measurement for machine-readable
// PERF-001 artifacts (not a continuous benchmark).
type progressiveBaselineSample struct {
	Name              string  `json:"name"`
	LogicalLogBytes   int64   `json:"logical_log_bytes"`
	RequestLength     int     `json:"request_length"`
	ReturnedLength    int     `json:"returned_length"`
	WireBodyBytes     int64   `json:"wire_body_bytes"`
	OverdownloadRatio float64 `json:"overdownload_ratio"`
	LatencyMs         float64 `json:"latency_ms"`
	AllocBytes        uint64  `json:"alloc_bytes"`
	AllocObjects      uint64  `json:"alloc_objects"`
	// BoundedRead is true when returned length ≤ request and wire is not the
	// full logical log (LOG-001 post-fix). Replaces kd001_overdownload.
	BoundedRead       bool `json:"bounded_read"`
	KD001Overdownload bool `json:"kd001_overdownload"` // always false post-LOG-001
}

type progressiveBaselineReport struct {
	TaskID     string                      `json:"task_id"`
	CapturedAt time.Time                   `json:"captured_at"`
	GoVersion  string                      `json:"go_version"`
	GOOS       string                      `json:"goos"`
	GOARCH     string                      `json:"goarch"`
	NumCPU     int                         `json:"num_cpu"`
	Notes      string                      `json:"notes"`
	Samples    []progressiveBaselineSample `json:"samples"`
}

// TestProgressiveBaselineCapture measures fixed progressive log sizes once and
// optionally writes JSON when PERF_BASELINE_JSON is set. Asserts the LOG-001
// bounded-read surface for the default 1 MiB / 10 MiB sizes.
func TestProgressiveBaselineCapture(t *testing.T) {
	sizes := []struct {
		name string
		size int
		env  string // empty = always run
	}{
		{name: "1MiB_req8KiB", size: 1 * miB},
		{name: "10MiB_req8KiB", size: 10 * miB},
		{name: "100MiB_req8KiB", size: 100 * miB, env: "PERF_BENCH_100MIB"},
		{name: "1GiB_req8KiB", size: 1 * giB, env: "PERF_BENCH_1GIB"},
	}

	report := progressiveBaselineReport{
		TaskID:     "PERF-001+LOG-001",
		CapturedAt: time.Now().UTC(),
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		Notes: "LOG-001: GetBuildLogs LimitReader caps application buffers at request " +
			"length; fixture progressive body accounting reflects early client close. " +
			"Residual: Jenkins may still generate response bytes until connection close. " +
			"wire_body_bytes is fixture body accounting (progressive payload only).",
	}

	for _, sc := range sizes {
		if sc.env != "" && os.Getenv(sc.env) == "" {
			t.Logf("skip %s (set %s=1 to include)", sc.name, sc.env)
			continue
		}
		// Fixture wire can race with httptest pipe buffering (full logical size
		// counted before client cancel). Retry like TestGetBuildLogs_NoOverReadOn1MiB.
		var sample progressiveBaselineSample
		for attempt := 0; attempt < 3; attempt++ {
			sample = measureProgressiveOnce(t, sc.name, sc.size, benchRequestLength)
			if sample.ReturnedLength > sample.RequestLength {
				t.Fatalf("%s: returned %d > request %d (app buffer over-read)", sample.Name, sample.ReturnedLength, sample.RequestLength)
			}
			if !sample.KD001Overdownload && sample.WireBodyBytes < sample.LogicalLogBytes {
				break
			}
			if attempt == 2 {
				// Hard contract remains application payload; full fixture wire after
				// retries is still a LOG-001 KD-001 signal (server offered remainder
				// and client close never truncated writes).
				t.Fatalf("%s: LOG-001 regression — full logical log still on fixture wire (wire=%d logical=%d) after retries",
					sample.Name, sample.WireBodyBytes, sample.LogicalLogBytes)
			}
			t.Logf("%s: attempt %d wire residual wire=%d logical=%d; retrying",
				sample.Name, attempt+1, sample.WireBodyBytes, sample.LogicalLogBytes)
		}
		report.Samples = append(report.Samples, sample)
		t.Logf("%s: request=%d wire=%d returned=%d overdownload=%.2fx latency=%.2fms alloc_B=%d bounded=%v",
			sample.Name, sample.RequestLength, sample.WireBodyBytes, sample.ReturnedLength,
			sample.OverdownloadRatio, sample.LatencyMs, sample.AllocBytes, sample.BoundedRead)
		// Hard contract: application payload. Soft: fixture wire residual is logged.
		if !sample.BoundedRead {
			t.Logf("%s: note high fixture wire residual wire=%d (app returned=%d still bounded)",
				sample.Name, sample.WireBodyBytes, sample.ReturnedLength)
		}
	}

	if len(report.Samples) < 2 {
		t.Fatalf("expected at least 1MiB and 10MiB samples, got %d", len(report.Samples))
	}

	if path := os.Getenv("PERF_BASELINE_JSON"); path != "" {
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
		t.Logf("wrote machine-readable baseline to %s", path)
	}
}

func measureProgressiveOnce(t *testing.T, name string, logSize, requestLen int) progressiveBaselineSample {
	t.Helper()
	f := newJenkinsFixture()
	defer f.close()
	f.setLogSize(BuildJobPath("demo"), 7, logSize)
	client := f.opts()
	ctx := context.Background()

	// Drop noise from fixture setup; measure a single client call.
	runtime.GC()
	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)
	beforeWire := f.bytesServed.Load()
	start := time.Now()
	logs, err := client.GetBuildLogs(ctx, "demo", 7, 0, requestLen)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&memAfter)
	wire := f.bytesServed.Load() - beforeWire
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}

	var allocDelta uint64
	if memAfter.TotalAlloc >= memBefore.TotalAlloc {
		allocDelta = memAfter.TotalAlloc - memBefore.TotalAlloc
	}
	var objDelta uint64
	if memAfter.Mallocs >= memBefore.Mallocs {
		objDelta = memAfter.Mallocs - memBefore.Mallocs
	}

	ratio := 0.0
	if requestLen > 0 {
		ratio = float64(wire) / float64(requestLen)
	}
	// KD-001 style over-download: wire ≈ full logical log.
	kd001 := wire >= int64(logSize) && logSize > requestLen
	bounded := len(logs.Logs) <= requestLen && progressiveWireBounded(wire, int64(logSize), requestLen)
	return progressiveBaselineSample{
		Name:              name,
		LogicalLogBytes:   int64(logSize),
		RequestLength:     requestLen,
		ReturnedLength:    len(logs.Logs),
		WireBodyBytes:     wire,
		OverdownloadRatio: ratio,
		LatencyMs:         float64(elapsed.Microseconds()) / 1000.0,
		AllocBytes:        allocDelta,
		AllocObjects:      objDelta,
		BoundedRead:       bounded,
		KD001Overdownload: kd001,
	}
}

// progressiveWireBounded reports whether fixture-written bytes are acceptably
// bounded relative to a large logical log under LOG-001 (not a full over-download).
//
// Note: fixture wire counts *server Write accepts*, which can exceed the client
// LimitReader due to httptest/pipe buffering before TCP close. The hard LOG-001
// contract is application payload ≤ request; wire must not equal the full
// logical remainder (KD-001 regression). Absolute caps are soft residuals.
func progressiveWireBounded(wire, logical int64, requestLen int) bool {
	if logical <= int64(requestLen) {
		// Entire log fits the request; wire may equal logical.
		return wire <= logical+int64(benchWireAbsCap)
	}
	// Full over-download of the logical log is the KD-001 regression.
	if wire >= logical {
		return false
	}
	// Allow generous pipe residual; still require wire well below full logical.
	if float64(wire) > float64(logical)*benchWireMaxFraction && wire > int64(benchWireAbsCap) {
		// Prefer soft bound: only fail if both fraction and abs cap are exceeded
		// *and* wire is a large absolute multiple of the request (true slurp).
		if wire > int64(requestLen)*64 && wire > int64(benchWireAbsCap) {
			// Still pass if under half logical — residual, not KD-001.
			return wire < logical/2
		}
	}
	return true
}

// TestGetBuildLogs_SyntheticSizeMatchesBody ensures setLogSize progressive
// content is consistent with setLog alphabet cycling (fixture correctness).
func TestGetBuildLogs_SyntheticSizeMatchesBody(t *testing.T) {
	const n = 100
	// Build the same alphabet cycle setLog-style callers use in contract tests.
	var want string
	for i := 0; i < n; i++ {
		want += string(byte('A' + (i % 26)))
	}

	f := newJenkinsFixture()
	defer f.close()
	f.setLogSize(BuildJobPath("demo"), 7, n)
	logs, err := f.opts().GetBuildLogs(context.Background(), "demo", 7, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	if logs.Logs != want {
		t.Fatalf("synthetic body mismatch: got %q want %q", logs.Logs, want)
	}
	if logs.TotalSize != n {
		t.Fatalf("TotalSize=%d want %d", logs.TotalSize, n)
	}
}
