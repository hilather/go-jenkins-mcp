#!/usr/bin/env bash
# QA-001 short native Go fuzz smoke (opt-in; not default make test).
#
# Hardening vs wall-clock FUZZTIME=1s flakes on GHA:
#   - Prefer count-based -fuzztime (Nx) so the coordinator finishes after N
#     execs instead of canceling mid-input (classic "context deadline exceeded").
#   - Bound GOMAXPROCS so worker cancel races stay rare on shared runners.
#   - Per-target -timeout; one automatic retry only for pure deadline flakes
#     (never swallow a written failing input / real assertion failure).
#
# Usage:
#   scripts/fuzz-smoke.sh
#   FUZZTIME=1000x scripts/fuzz-smoke.sh
#   FUZZTIME=2s scripts/fuzz-smoke.sh   # wall-clock still supported
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH}"

GO="${GO:-go}"
# Count-based default: ~500 mutations per target; finishes cleanly on CI.
FUZZTIME="${FUZZTIME:-500x}"
# Hard wall per target (includes compile + baseline + fuzz).
FUZZ_TIMEOUT="${FUZZ_TIMEOUT:-90s}"
# Retry only pure coordinator-cancel flakes once.
FUZZ_RETRIES="${FUZZ_RETRIES:-2}"
# Cap workers on shared CI runners (override with GOMAXPROCS=).
if [[ -z "${GOMAXPROCS:-}" ]]; then
  export GOMAXPROCS=4
fi

# pkg fuzzFunc — one line per target (order stable for log grepping).
TARGETS=(
  "./internal/jenkins FuzzSanitizeArtifactPath"
  "./internal/jenkins FuzzBuildJobPath"
  "./internal/jenkins FuzzNormalizeBaseURL"
  "./internal/jenkins FuzzInventoryZip"
  "./internal/archive FuzzOpenPack"
  "./internal/archive FuzzParseSeekTable"
  "./internal/archive FuzzParseIndex"
  "./internal/redact FuzzStripControlSequences"
  "./internal/redact FuzzRedactText"
  "./internal/redact FuzzSanitizeForModel"
  "./internal/tools FuzzJobFullName"
  "./internal/tools FuzzPolicyTargetFromArgs"
  "./internal/contracts FuzzParseJobFullName"
  "./internal/mutation FuzzNormalizeParams"
  "./internal/mutation FuzzValidateAgainstDefinitions"
  "./internal/update FuzzParseManifest"
  "./internal/update FuzzLoadLKG"
  "./internal/policy FuzzLoadOverlayJSON"
  "./internal/policy FuzzDenyJobPrefixMatch"
  "./internal/auth FuzzClassifyFallthroughProbe"
  "./internal/auth FuzzParseProtectedResourceMetadata"
)

echo "QA-001 fuzz-smoke FUZZTIME=${FUZZTIME} FUZZ_TIMEOUT=${FUZZ_TIMEOUT} GOMAXPROCS=${GOMAXPROCS} retries=${FUZZ_RETRIES}"

# Returns 0 if log looks like a pure cancel flake (safe to retry).
is_deadline_flake() {
  local logf="$1"
  # Real crashers write "failing input written" / minimize paths — never retry those.
  if grep -Eiq 'failing input written|minimizing|got panic|internal error' "$logf"; then
    return 1
  fi
  # Coordinator cancel when fuzztime/timeout fires mid-worker.
  if grep -Eq 'context deadline exceeded|fuzz: elapsed:.*context canceled' "$logf"; then
    return 0
  fi
  return 1
}

run_one() {
  local pkg="$1"
  local name="$2"
  local attempt logf rc
  logf="$(mktemp "${TMPDIR:-/tmp}/fuzz-smoke.XXXXXX")"
  rc=1
  for attempt in $(seq 1 "${FUZZ_RETRIES}"); do
    echo "→ ${pkg} -fuzz=${name} (attempt ${attempt}/${FUZZ_RETRIES})"
    set +e
    "${GO}" test ${GOFLAGS:-} "${pkg}" \
      -run='^$' \
      -fuzz="${name}" \
      -fuzztime="${FUZZTIME}" \
      -timeout="${FUZZ_TIMEOUT}" \
      >"${logf}" 2>&1
    rc=$?
    set -e
    # Always surface the go test output for CI logs.
    cat "${logf}"
    if [[ "${rc}" -eq 0 ]]; then
      rm -f "${logf}"
      return 0
    fi
    if [[ "${attempt}" -lt "${FUZZ_RETRIES}" ]] && is_deadline_flake "${logf}"; then
      echo "warn: ${name}: pure deadline flake on attempt ${attempt}; retrying once" >&2
      continue
    fi
    echo "error: ${name}: failed (exit ${rc})" >&2
    rm -f "${logf}"
    return "${rc}"
  done
  rm -f "${logf}"
  return "${rc}"
}

failed=0
for entry in "${TARGETS[@]}"; do
  # shellcheck disable=SC2086
  set -- ${entry}
  pkg="$1"
  name="$2"
  if ! run_one "${pkg}" "${name}"; then
    failed=1
    # Fail fast: one broken target is enough signal; keeps CI minutes bounded.
    break
  fi
done

if [[ "${failed}" -ne 0 ]]; then
  echo "fuzz-smoke FAILED" >&2
  exit 1
fi
echo "fuzz-smoke complete (see CONTRIBUTING.md for longer runs)"
exit 0
