#!/usr/bin/env bash
# QA-003: continuous performance regression (MVP).
# Runs fixed small benchmarks and compares p50/p95 ns/op to docs/perf-budgets.json.
# Not part of default `make test` / `make ci`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

BUDGETS="${PERF_BUDGETS:-$ROOT/docs/perf-budgets.json}"
OUT_DIR="${PERF_OUT_DIR:-$ROOT/dist}"
mkdir -p "$OUT_DIR"
RAW="$OUT_DIR/perf-regression-raw.txt"
REPORT="$OUT_DIR/perf-regression-report.json"

if [[ ! -f "$BUDGETS" ]]; then
  echo "error: budgets file not found: $BUDGETS" >&2
  exit 2
fi

COUNT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("bench_count",5))' "$BUDGETS")"
BENCHTIME="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("benchtime","50ms"))' "$BUDGETS")"
TOL_DEFAULT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("tolerance_percent",100))' "$BUDGETS")"
TOLERANCE="${PERF_TOLERANCE_PERCENT:-$TOL_DEFAULT}"

echo "QA-003 perf-regression budgets=$BUDGETS count=$COUNT benchtime=$BENCHTIME tolerance=${TOLERANCE}%"
: >"$RAW"

run_pkg_bench() {
  local pkg="$1"
  local pattern="$2"
  echo "==> go test $pkg -bench=$pattern -count=$COUNT -benchtime=$BENCHTIME" | tee -a "$RAW"
  # -run=^$ skips unit tests; keep default suite fast and isolated.
  go test "$pkg" -run='^$' -bench="$pattern" -benchmem -count="$COUNT" -benchtime="$BENCHTIME" 2>&1 | tee -a "$RAW"
}

# CI-safe fixed set (must match docs/perf-budgets.json keys).
run_pkg_bench ./internal/jenkins 'BenchmarkGetBuildLogs_Progressive1MiB$'
run_pkg_bench ./internal/archive 'BenchmarkL2PackRangeRead_Warm1MiB$'
run_pkg_bench ./internal/policy 'BenchmarkPolicyEvaluate_Allow$'

python3 - "$BUDGETS" "$RAW" "$REPORT" "$TOLERANCE" <<'PY'
import json, re, sys, statistics, os

budgets_path, raw_path, report_path, tol_s = sys.argv[1:5]
tol = float(tol_s)
with open(budgets_path) as f:
    cfg = json.load(f)
budget_map = cfg.get("budgets") or {}

# Parse go test bench lines:
# BenchmarkX-12   100   1234 ns/op   ...
line_re = re.compile(
    r'^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+(\d+(?:\.\d+)?)\s+ns/op'
)

samples = {}  # name -> [ns/op, ...]
with open(raw_path) as f:
    for line in f:
        line = line.strip()
        m = line_re.match(line)
        if not m:
            continue
        name, _iters, ns = m.group(1), m.group(2), float(m.group(3))
        # Strip trailing package-style suffixes if any (keep base name).
        base = name.split("/")[0]
        samples.setdefault(base, []).append(ns)

def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)

results = []
failed = False
for name, b in sorted(budget_map.items()):
    xs = sorted(samples.get(name) or [])
    entry = {
        "benchmark": name,
        "package": b.get("package"),
        "samples": len(xs),
        "measured_ns": xs,
        "budget_ns_per_op_p50": b.get("ns_per_op_p50"),
        "budget_ns_per_op_p95": b.get("ns_per_op_p95"),
        "tolerance_percent": tol,
    }
    if not xs:
        entry["status"] = "missing"
        entry["error"] = "no bench samples parsed"
        failed = True
        results.append(entry)
        continue
    p50 = pct(xs, 50)
    p95 = pct(xs, 95)
    entry["p50_ns"] = p50
    entry["p95_ns"] = p95
    # Also record mean for graphing.
    entry["mean_ns"] = statistics.fmean(xs)

    limit50 = b["ns_per_op_p50"] * (1.0 + tol / 100.0)
    limit95 = b["ns_per_op_p95"] * (1.0 + tol / 100.0)
    entry["limit_p50_ns"] = limit50
    entry["limit_p95_ns"] = limit95
    ok50 = p50 <= limit50
    ok95 = p95 <= limit95
    if ok50 and ok95:
        entry["status"] = "pass"
    else:
        entry["status"] = "fail"
        failed = True
        entry["error"] = (
            f"p50={p50:.0f} limit={limit50:.0f} ({'ok' if ok50 else 'EXCEED'}); "
            f"p95={p95:.0f} limit={limit95:.0f} ({'ok' if ok95 else 'EXCEED'})"
        )
    results.append(entry)

report = {
    "schema_version": 1,
    "task": "QA-003",
    "budgets_file": budgets_path,
    "tolerance_percent": tol,
    "goos": os.uname().sysname,
    "machine": os.uname().machine,
    "results": results,
    "overall": "fail" if failed else "pass",
}
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

print()
print("=== QA-003 perf-regression summary ===")
for r in results:
    if r["status"] == "pass":
        print(f"PASS {r['benchmark']}: p50={r['p50_ns']:.0f} p95={r['p95_ns']:.0f} ns/op "
              f"(limits {r['limit_p50_ns']:.0f}/{r['limit_p95_ns']:.0f})")
    elif r["status"] == "missing":
        print(f"FAIL {r['benchmark']}: {r.get('error')}")
    else:
        print(f"FAIL {r['benchmark']}: {r.get('error')}")
print(f"report: {report_path}")
print(f"overall: {report['overall']}")
sys.exit(1 if failed else 0)
PY
