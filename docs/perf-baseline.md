# Performance baselines (PERF-001 + LOG-001 + PERF-002)

Fixture-only measurements. **No live Jenkins** is required for progressive
logs or L2 pack qualification. Re-run harnesses after log, HTTP, or archive
reader/writer changes.

---

## PERF-001 + LOG-001 — progressive logs

| Item | Value |
|------|--------|
| Tasks | PERF-001 (harness), LOG-001 (bounded progressive reads) |
| Post-fix behavior | `GetBuildLogs` uses `io.LimitReader` + early body close; returned payload ≤ `length` |
| Residual | Server/fixture may push progressive bytes into the pipe until TCP close; fixture `wire-B/op` is typically ~2× request (~16–64 KiB) and is capped in tests at 256 KiB absolute (≪ multi-MiB logical). Application payload is always ≤ request |
| Package | `internal/jenkins` |
| Fixture | `jenkinsFixture` (`setLog` / `setLogSize`) with body-byte accounting via `bytesServed` (per-Write) |

## How to run

Export Go if needed on developer machines:

```bash
export PATH="$HOME/.local/go/bin:$PATH"
```

### Continuous benchmarks (latency, allocs, wire metrics)

```bash
go test ./internal/jenkins -bench=Progressive -benchmem
# benches only (skip unit tests):
go test ./internal/jenkins -run '^$' -bench=Progressive -benchmem
```

Default suite runs **1 MiB** and **10 MiB** logical logs with request length
**8192** (tool default). Opt-in sizes (cheap after LOG-001 — no full-log download):

```bash
PERF_BENCH_100MIB=1 go test ./internal/jenkins -bench=Progressive100MiB -benchmem -count=1
PERF_BENCH_1GIB=1   go test ./internal/jenkins -bench=Progressive1GiB -benchmem -count=1
```

Makefile helper (optional artifact dir):

```bash
make bench-progressive
```

### One-shot machine-readable capture

`go test` runs with CWD = package directory (`internal/jenkins`). Use an
**absolute** path for `PERF_BASELINE_JSON` (or prefer `make bench-progressive`):

```bash
mkdir -p dist
PERF_BASELINE_JSON="$PWD/dist/perf-baseline.json" \
  go test ./internal/jenkins -run TestProgressiveBaselineCapture -count=1 -v
```

JSON schema (fields):

| Field | Meaning |
|-------|---------|
| `logical_log_bytes` | Synthetic progressive log size |
| `request_length` | `length` passed to `GetBuildLogs` (8192) |
| `returned_length` | `len(logs.Logs)` after client cap |
| `wire_body_bytes` | Fixture progressive body bytes written (`bytesServed` delta) |
| `overdownload_ratio` | `wire_body_bytes / request_length` |
| `latency_ms` | Wall time for one call |
| `alloc_bytes` / `alloc_objects` | `runtime.MemStats` delta around the call |
| `bounded_read` | `true` when returned ≤ request and wire is not the full logical log |
| `kd001_overdownload` | `true` only on LOG-001 regression (wire ≥ full logical) |

Go’s native bench JSON is also usable for CI:

```bash
go test ./internal/jenkins -bench='Progressive(1MiB|10MiB)' -benchmem -json > dist/progressive-bench.json
```

## What “good” looks like (post LOG-001)

For request `length=8192` and offset `0`:

| Logical log | Returned tool bytes | Expected wire body (fixture) | Over-download ratio |
|-------------|--------------------:|-----------------------------:|--------------------:|
| 1 MiB | 8192 | **≈ 16–64 KiB** typical, **&lt; 256 KiB**, **not** 1 MiB | ~2–8× typical |
| 10 MiB | 8192 | **≈ 16–64 KiB**, **not** 10 MiB | ~2–8× typical |
| 100 MiB | 8192 | bounded ≪ logical | ~2–8× typical |
| 1 GiB | 8192 | bounded ≪ logical | ~2–8× typical |

Contract tests:

- `TestGetBuildLogs_ReturnsRequestedLength` — returned == 8192; wire ≪ 50 KiB full body
- `TestGetBuildLogs_NoOverReadOn1MiB` — 8 KiB request on 1 MiB logical log
- `TestGetBuildLogTail_UsesSizeHeaderNoFullDownload` — size header path seeks tail

Custom bench metrics (`-benchmem` output):

| Metric | Meaning |
|--------|---------|
| `wire-B/op` | Average progressive body bytes written per op |
| `req-B` | Requested length (8192) |
| `overdownload-x` | `wire-B/op / req-B` (target ~1–8; full-logical ratio is a regression) |
| `logical-B` | Synthetic log size |
| `B/op`, `allocs/op` | Standard `testing.B` allocation stats |
| `MB/s` | From `SetBytes(request)` — throughput of the **bounded** body |

## Reference hardware / software

| Field | Sample capture (LOG-001 re-baseline) |
|-------|----------------------------------------|
| OS | Linux |
| Arch | amd64 |
| Go | go1.25.x |
| CPUs | 12 (`Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz`) |
| Host class | developer workstation |
| Live Jenkins | **none** (httptest fixture only) |

### Sample bench output (post LOG-001)

Captured on Linux amd64, Intel i7-8750H (12 threads), fixture only.
**ns/op and MB/s vary**; wire and overdownload metrics are the regression lock:

```text
# BEFORE LOG-001 (KD-001 lock-in, historical)
BenchmarkGetBuildLogs_Progressive1MiB-12   278   5586249 ns/op  187.71 MB/s
  1048576 logical-B  128.0 overdownload-x  8192 req-B  1048576 wire-B/op
  6377133 B/op  175 allocs/op

BenchmarkGetBuildLogs_Progressive10MiB-12   34  34848448 ns/op  300.90 MB/s
  10485760 logical-B  1280 overdownload-x  8192 req-B  10485760 wire-B/op
  62855153 B/op  372 allocs/op

# AFTER LOG-001 (illustrative host re-run)
BenchmarkGetBuildLogs_Progressive1MiB-12  2361    771535 ns/op   10.62 MB/s
  1048576 logical-B  ~2–8 overdownload-x  8192 req-B  ~16–64k wire-B/op
  ~72 KiB B/op  ~190 allocs/op

BenchmarkGetBuildLogs_Progressive10MiB-12 2799    502391 ns/op   16.31 MB/s
  10485760 logical-B  ~2–8 overdownload-x  8192 req-B  ~16–64k wire-B/op
  ~72 KiB B/op  ~190 allocs/op
```

One-shot capture: request 8192 → wire ≈ 16 KiB (2× chunk) for both 1 MiB and
10 MiB logical sizes; `bounded_read: true`, `kd001_overdownload: false`.

Absolute ns/op will vary by machine; **wire-B/op must not return to full
logical size** (that is a LOG-001 / KD-001 regression).

## Related tests

| Test / bench | Role |
|--------------|------|
| `TestGetBuildLogs_ReturnsRequestedLength` | Contract + LOG-001 no over-read |
| `TestGetBuildLogs_NoOverReadOn1MiB` | LOG-001 acceptance (1 MiB / 8 KiB) |
| `TestGetBuildLogTail_UsesSizeHeaderNoFullDownload` | Tail seeks via X-Text-Size |
| `TestProgressiveBaselineCapture` | Fixed-size metrics + optional JSON artifact |
| `TestGetBuildLogs_SyntheticSizeMatchesBody` | `setLogSize` alphabet consistency |
| `BenchmarkGetBuildLogs_Progressive*` | Latency / allocs / wire metrics |

## Out of scope (this harness)

- Live Jenkins load tests
- MCP stdio result-size benches (follow-up with MCP harness)
- Full NET-003 encoded/decoded body budgets and circuit breaking

## Next steps (PERF-001)

- [x] Re-run baselines after LOG-001 and record before/after wire-B/op
- [x] Continuous regression budgets (QA-003): `docs/perf-budgets.json` + `make perf-regression`
- [ ] Optionally publish `dist/perf-baseline.json` as a CI artifact
- [ ] Extend harness to job list / build detail once those paths grow budgets (NET/OBS)

### QA-003 continuous regression

```bash
make perf-regression
# or:
./scripts/perf-regression.sh
# report: dist/perf-regression-report.json
# override tolerance: PERF_TOLERANCE_PERCENT=150 make perf-regression
```

Compares p50/p95 `ns/op` for progressive 1 MiB, L2 warm range 1 MiB, and policy
evaluate microbench against checked-in budgets. Default `make test` / `make ci`
do **not** run this target (hardware variance).

---

## PERF-002 — L2 seekable multi-frame packs (MVP evidence)

Native Go only (**no ratarmount**). Qualifies multi-frame seekable `.tar.zst`
build and random range reads vs full-pack extraction. Compares **zero-recompress**
(L1 payload frame copy) vs **compatibility repack** (`WritePack`).

| Item | Value |
|------|--------|
| Task | PERF-002 |
| Package | `internal/archive` (`l2_pack_bench_test.go`) |
| Sizes | 1 MiB, 10 MiB always in capture; **100 MiB** opt-in via `PERF_BENCH_100MIB=1` |
| Members | 4 synthetic `logs/job/N/consoleText` payloads per pack |
| Range | 8 KiB from mid-member (representative tool-sized read) |
| Codec | `zstd` |
| Repack frame target | 256 KiB uncompressed (`TargetFrameBytes`) |
| Reader | Native `OpenPack` / `ReadMemberRange` (ARC-003) |
| ratarmount-rs | **No-go** until ARC-000 supply — see `docs/arc/ratarmount-rs-qualification.md` |

### How to run

```bash
export PATH="$HOME/.local/go/bin:$PATH"

# CI-safe unit tests (small packs; always in default go test)
go test ./internal/archive/ ./internal/logmirror/ -count=1
go test ./internal/archive -run 'TestL2Pack_' -count=1

# Continuous benches (1 MiB / 10 MiB; not in default make test)
go test ./internal/archive -run '^$' -bench=L2Pack -benchmem -count=1

# Optional 100 MiB
PERF_BENCH_100MIB=1 go test ./internal/archive -run '^$' -bench=L2Pack.*100MiB -benchmem -count=1

# One-shot machine-readable capture (use absolute path; go test CWD = package dir)
mkdir -p dist
PERF_L2_BASELINE_JSON="$PWD/dist/perf-l2-baseline.json" \
  go test ./internal/archive -run TestL2PackBaselineCapture -count=1 -v

# Makefile helper
make bench-l2-pack
```

### JSON schema (`PERF_L2_BASELINE_JSON`)

Top-level report:

| Field | Meaning |
|-------|---------|
| `task_id` | `PERF-002` |
| `captured_at` | UTC timestamp |
| `go_version` / `goos` / `goarch` / `num_cpu` | Host capture metadata |
| `notes` | Residual + pack parameters |
| `samples` | Array of size/path measurements |

Per-sample fields:

| Field | Meaning |
|-------|---------|
| `name` | Scenario id (e.g. `repack_1MiB_4m`, `zero_recompress_10MiB_4m`) |
| `total_payload_bytes` | Sum of member body sizes |
| `members` | Member count |
| `pack_bytes` | On-disk multi-frame pack size |
| `content_frames` | Seek-table content frame count |
| `build_ms` | Wall time to build one pack |
| `range_offset` / `range_length` | Member range read (offset / 8192) |
| `read_cold_p50_ms` / `read_cold_p95_ms` | OpenPack + range latency percentiles |
| `read_warm_p50_ms` / `read_warm_p95_ms` | Range-only latency on a reused pack |
| `frames_opened` | Independent frames decompressed for the range |
| `decompressed_bytes` | Uncompressed frame bytes opened |
| `amplification_x` | `decompressed_bytes / range_length` |
| `remote_bytes` | Always `null` (N/A — local pack, no Jenkins wire) |
| `codec` | `zstd` |
| `zero_recompress` | `true` when L1 payload frames were copied |
| `range_correct` | Range bytes match synthetic member body |
| `multi_frame` | `content_frames ≥ MinContentFrames` (2) |

### What “good” looks like (MVP)

| Check | Expectation |
|-------|-------------|
| Multi-frame | Pack rejected if single-frame; capture asserts `multi_frame` |
| No full-pack extract | 8 KiB range opens **subset** of content frames (`frames_opened < content_frames` when ≥4 frames) |
| Range correctness | `range_correct: true` |
| Compatibility repack amp | `amplification_x` ≲ 64× for 256 KiB target frames (8 KiB read) |
| Zero-recompress | Payload frames byte-identical; range opens ≤3 local frames; amp ≈ member_frame/range (can be large for multi-MiB members — **recalibrated**, not a regression) |
| Build path | Zero-recompress avoids re-encoding log payload; wall/CPU benefit host-dependent (recorded in `build_ms`) |

CI unit tests (always fast):

| Test | Role |
|------|------|
| `TestL2Pack_CISmallMultiFrameSeekAndRange` | Tiny multi-frame + seek + range budget |
| `TestL2Pack_ZeroRecompressVsRepackCorrectness` | Copy vs repack correctness |
| `TestL2Pack_RangeDoesNotFullExtract` | Amplification / no full-pack extract |
| `TestL2PackBaselineCapture` | 1/10 MiB evidence + optional JSON |

Benches: `BenchmarkL2PackBuild_*`, `BenchmarkL2PackRangeRead_*` (cold/warm).

### Sample capture shape

```json
{
  "task_id": "PERF-002",
  "goos": "linux",
  "goarch": "amd64",
  "samples": [
    {
      "name": "repack_1MiB_4m",
      "total_payload_bytes": 1048576,
      "members": 4,
      "pack_bytes": 12345,
      "content_frames": 8,
      "build_ms": 12.3,
      "range_length": 8192,
      "read_warm_p50_ms": 0.15,
      "frames_opened": 1,
      "amplification_x": 32.0,
      "remote_bytes": null,
      "codec": "zstd",
      "zero_recompress": false,
      "range_correct": true,
      "multi_frame": true
    }
  ]
}
```

Absolute `build_ms` / `read_*_ms` **vary by hardware**; use them for
before/after on the same host. Regression locks are multi-frame, range
correctness, and no full-pack frame open.

### Residuals (honest)

- **Hardware variance:** ns/op and p50/p95 are not cross-machine SLOs.
- **Enterprise 100 GiB physical scale:** not run in default CI; use
  `PERF_BENCH_100MIB` and larger offline jobs for capacity soak. MVP proves
  the same code paths and metrics at representative MiB sizes.
- **ratarmount-rs:** no-go until exact dependency is supplied (ARC-000). Native
  Go reader is the production-capable path for CI and headless hosts.
- **Index/compaction off interactive path:** pack build is offline/maintenance;
  capture separates `build_ms` from warm range latency.
- **Antivirus / concurrent multi-reader RSS:** not instrumented in this MVP
  harness (follow-up if pilot requires).
- **Zero-recompress amplification:** with one L1 frame per large member, amp
  scales with member size; prefer multi-frame L1 generations (ARC-005 path)
  when tighter amp is required.

### Go / no-go (pack parameters + ratarmount)

| Decision | Status |
|----------|--------|
| Native multi-frame + seek table + range subset decompress | **Go** (MVP evidence via tests + capture) |
| Codec `zstd`, repack target ~256 KiB (bench), production default 8 MiB | **Go** (defaults in `types.go`; benches use smaller target for multi-frame density) |
| Zero-recompress when L1 payload frames valid | **Go** (correctness + measured build path) |
| Exact `ratarmount-rs` pin / FUSE path | **No-go** — blocked on ARC-000 supply |

---

## PERF-003 — diagnostics session cache (MVP + Wave 27 single-flight)

High-level triage tools share a per-`Register` `FetchCache` (TTL 60s, max 256
entries by default) and a per-invocation `DiagBudget` so diagnose/compare/graph
do not multiply Jenkins log downloads across repeated agent turns.

| Item | Value |
|------|--------|
| Task | PERF-003 |
| Package | `internal/tools` (`diag_session.go`) |
| Cache keys | `job\|build\|kind={build,logtail,stages,testreport,artifacts,scmchanges}` (+ kind-specific extras) |
| Artifact keys (Wave 41) | `…\|kind=artifacts\|max=<n>\|deny_artifact_paths\|<sorted patterns…>` when deny patterns live; empty patterns omit the fingerprint parts. Fetch uses `listArtifactsWithPolicyFilter`; return always post-filters live patterns (clone) |
| Default op ceilings | diagnose 12 calls / 1 MiB / 30s; compare 24 / 2 MiB / 45s; trace 48 / 2 MiB / 60s; regression 64 / ~2 MiB+ / 90s |
| Build details | `getCachedBuildDetails` wraps `GetBuildDetailsByJob`; **single-flight** + TTL; process-local only |
| Response fields | `budgets` ceilings; optional `perf` with `cache_hits`, `cache_misses`, `remote_calls`, `remote_bytes`, `shared_flights`, `budget_exhausted` |
| Tests | `TestDiagnoseBuild_CacheHitSecondCall`, `TestDiagnoseBuild_BudgetExhaustionIncomplete`, `TestDiagnoseBuild_CancellationStopsWork`, `TestCompareBuilds_SharedCacheWithDiagnose`, `TestDiagnoseBuild_NoDoubleFetchBuildDetails`, `TestGetCachedBuildDetails_SingleFlightNoDuplicateHTTP`, `TestGetCachedArtifactList_*`, `diag_session_internal_test.go` |

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/tools -run 'CacheHit|BudgetExhaustion|Cancellation|SharedCache|NoDoubleFetch|SingleFlight' -count=1
```

Residual: single-flight for concurrent **log-tail** keys (build/stages/tests done);
SCM/graph still use distinct Jenkins `tree=` shapes (not merged into build-details
cache); deeper CPU/alloc profiling of the diagnose path (not blocking MVP).

---

## Survey durable compact summary cache (Wave 28 PERF residual)

`jenkins_survey_recent_failures` avoids re-fetching log tails for the same
(profile, job, build, max_log_bytes) when a compact signature summary is still
valid.

| Item | Value |
|------|--------|
| L1 | Process-scoped TTL map (`internal/tools/survey_cache.go`): 5m / 256 entries |
| L2 | Profile Meta SQLite **schema v7** table `survey_summary_cache` (`internal/store/survey_cache.go`) |
| Key | `profile` + `job` + `build` + `max_log_bytes` |
| Value | Compact only: signature hashes, result, byte counts, short redacted text — **no log bodies** |
| Wire-up | `cmd/jenkins-mcp` passes `storeMeta` as `RegisterOptions.Meta` when profile data dir is open |
| Response | `budgets.cache_hits` / `cache_misses`; `sources` may list `survey_cache` or `survey_cache_durable` |
| Residual | Cold start / no profile store → L1 only; durable is per-profile Meta, not a global disk cache |

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/store -run 'SurveySummaryCache|Migrate_Upgrade' -count=1
go test ./internal/tools -run 'SurveyRecentFailures_(ProcessCacheHit|DurableCacheHit|NoMeta)' -count=1
```
