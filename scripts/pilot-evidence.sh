#!/usr/bin/env bash
# REL-001 / REL-002 lite: offline/local pilot + release evidence bundle.
#
# Collects secret-free CLI outputs into dist/pilot-evidence/<timestamp>/ with
# MANIFEST.json. Never prints or captures tokens, cookies, Authorization material,
# or private keys. Prefer --offline paths; optional PROFILE enables doctor/pilot-check.
#
# Always captures gateway residual-status (Wave 8 residual honesty) when the
# binary has the subcommand, so pilot kits include residual honesty without a
# separate residual-smoke run. Optional consent-residual when present.
# Residual honesty canaries hard-fail (missing residual_ids / ha_multi_replica /
# shared_*_file default false / subject_limiter_max_subjects omit default)
# matching residual-smoke residual-lite style — offline only, not live GO.
# Lightweight path canaries (path set → bool true, path never dumped) and
# SUBJECT_LIMITER_MAX_SUBJECTS canary (env=64 → field 64) also hard-fail when
# python3 is available.
#
# Usage:
#   scripts/pilot-evidence.sh
#   scripts/pilot-evidence.sh --profile corp
#   PROFILE=corp SKIP_GO_TEST=1 scripts/pilot-evidence.sh
#   make pilot-evidence PROFILE=corp
#
# Environment:
#   PROFILE          — optional profile id (also --profile)
#   BIN              — path to jenkins-mcp binary (else bin/jenkins-mcp, PATH, or go build)
#   OUT_ROOT         — root for evidence dirs (default: <repo>/dist/pilot-evidence)
#   SKIP_GO_TEST=1   — skip go test summary
#   SKIP_BUILD=1     — do not auto-build if binary missing
#   SKIP_RESIDUAL_STATUS=1 — skip residual-status capture (not recommended)
#   GO_TEST_PKGS     — packages for optional test summary (default: ./cmd/jenkins-mcp/)
#
# Exit: 0 when overall is pass or warn (or incomplete without hard fail); 1 when
# overall is fail. Bundle is always written when possible.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

PROFILE="${PROFILE:-}"
SKIP_GO_TEST="${SKIP_GO_TEST:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_RESIDUAL_STATUS="${SKIP_RESIDUAL_STATUS:-0}"
OUT_ROOT="${OUT_ROOT:-$ROOT/dist/pilot-evidence}"
GO_TEST_PKGS="${GO_TEST_PKGS:-./cmd/jenkins-mcp/}"
BIN="${BIN:-}"

# residual-status residual_ids required for residual honesty (same as residual-smoke).
# Offline only — not live Entra / AgentCore / multi-replica production GO.
REQUIRED_RESIDUAL_STATUS_IDS=(
  multi_user_offline
  oauth009_offline
  oauth010_offline
  progressive_consent_offline
  host008_single_replica
  gateway_modes_live
)

usage() {
  cat <<'EOF'
Usage: pilot-evidence.sh [--profile ID] [--skip-go-test] [--out-root DIR] [--bin PATH]

Offline/local secret-free evidence for REL-001 pilot and REL-002 gate prep.
Writes dist/pilot-evidence/<timestamp>/ with MANIFEST.json.

  --profile ID     Run doctor --offline and pilot-check --offline for profile
  --skip-go-test   Do not run go test summary
  --out-root DIR   Evidence root (default: dist/pilot-evidence)
  --bin PATH       jenkins-mcp binary path
  -h, --help       Show this help

Always captures gateway residual-status (honesty canaries hard-fail) when the
subcommand exists; optional consent-residual. shared_*_file default-false +
subject_limiter_max_subjects omit default + lightweight path-not-dumped /
SUBJECT_LIMITER_MAX_SUBJECTS canaries align with residual-smoke residual lite.
Offline residual honesty only — not live multi-user GO.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --profile=*)
      PROFILE="${1#*=}"
      shift
      ;;
    --skip-go-test)
      SKIP_GO_TEST=1
      shift
      ;;
    --out-root)
      OUT_ROOT="${2:-}"
      shift 2
      ;;
    --out-root=*)
      OUT_ROOT="${1#*=}"
      shift
      ;;
    --bin)
      BIN="${2:-}"
      shift 2
      ;;
    --bin=*)
      BIN="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# --- resolve binary ---
resolve_bin() {
  if [[ -n "$BIN" && -x "$BIN" ]]; then
    echo "$BIN"
    return 0
  fi
  if [[ -x "$ROOT/bin/jenkins-mcp" ]]; then
    echo "$ROOT/bin/jenkins-mcp"
    return 0
  fi
  if command -v jenkins-mcp >/dev/null 2>&1; then
    command -v jenkins-mcp
    return 0
  fi
  if [[ "$SKIP_BUILD" == "1" ]]; then
    return 1
  fi
  if command -v go >/dev/null 2>&1; then
    mkdir -p "$ROOT/bin"
    # shellcheck disable=SC2086
    (cd "$ROOT" && go build -o "$ROOT/bin/jenkins-mcp" ./cmd/jenkins-mcp) >&2 || return 1
    if [[ -x "$ROOT/bin/jenkins-mcp" ]]; then
      echo "$ROOT/bin/jenkins-mcp"
      return 0
    fi
  fi
  return 1
}

if ! MCP_BIN="$(resolve_bin)"; then
  echo "error: jenkins-mcp binary not found; build with 'make build' or set BIN=" >&2
  exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_ROOT%/}/$TS"
mkdir -p "$OUT_DIR"

echo "pilot-evidence: binary=$MCP_BIN out=$OUT_DIR profile=${PROFILE:-<none>} skip_go_test=$SKIP_GO_TEST"

# Artifact bookkeeping (bash 4+ associative arrays avoided for portability).
# Lines: name|file|status|exit_code|note
ARTIFACT_LINES=()
HARD_FAIL=0
HAS_WARN=0

# Run a command; capture stdout/stderr; never fail the script on command exit.
# Args: artifact_name  output_basename  command...
run_capture() {
  local name="$1"
  local base="$2"
  shift 2
  local out_file="$OUT_DIR/${base}"
  local err_file="$OUT_DIR/${base}.stderr"
  local rc=0
  set +e
  "$@" >"$out_file" 2>"$err_file"
  rc=$?
  set -e
  local status="pass"
  local note=""
  if [[ $rc -ne 0 ]]; then
    status="fail"
    HARD_FAIL=1
    note="exit_code=$rc"
  fi
  # Empty stderr is fine; drop zero-length stderr files to keep bundle tidy.
  if [[ ! -s "$err_file" ]]; then
    rm -f "$err_file"
  fi
  ARTIFACT_LINES+=("${name}|${base}|${status}|${rc}|${note}")
  echo "  [$status] $name (exit $rc) -> $base"
}

run_skip() {
  local name="$1"
  local reason="$2"
  ARTIFACT_LINES+=("${name}||skip|0|${reason}")
  HAS_WARN=1
  echo "  [skip] $name ($reason)"
}

# --- always-on offline generators ---
run_capture "version" "version.json" "$MCP_BIN" version --json
run_capture "security_self_check" "security-self-check.json" "$MCP_BIN" security self-check --json

# gateway qualify --offline (skip cleanly if subcommand missing on older binary)
set +e
"$MCP_BIN" gateway qualify --offline >"$OUT_DIR/gateway-qualify.json" 2>"$OUT_DIR/gateway-qualify.json.stderr"
gw_rc=$?
set -e
if [[ $gw_rc -eq 0 ]]; then
  ARTIFACT_LINES+=("gateway_qualify_offline|gateway-qualify.json|pass|0|")
  rm -f "$OUT_DIR/gateway-qualify.json.stderr"
  echo "  [pass] gateway_qualify_offline (exit 0) -> gateway-qualify.json"
else
  if grep -qiE 'unknown gateway|subcommand required|invalid argument|not found' \
      "$OUT_DIR/gateway-qualify.json.stderr" 2>/dev/null; then
    run_skip "gateway_qualify_offline" "gateway qualify not available on this binary"
    rm -f "$OUT_DIR/gateway-qualify.json" "$OUT_DIR/gateway-qualify.json.stderr"
  else
    ARTIFACT_LINES+=("gateway_qualify_offline|gateway-qualify.json|fail|${gw_rc}|exit_code=${gw_rc}")
    HARD_FAIL=1
    if [[ ! -s "$OUT_DIR/gateway-qualify.json.stderr" ]]; then
      rm -f "$OUT_DIR/gateway-qualify.json.stderr"
    fi
    echo "  [fail] gateway_qualify_offline (exit $gw_rc) -> gateway-qualify.json"
  fi
fi

# --- gateway residual-status (always when binary available; residual honesty) ---
# Captures gateway-residual-status.json into the pilot pack so residual honesty
# is present without a separate residual-smoke run. Hard-fail on missing
# residual_ids / ha_multi_replica / shared_*_file default-false /
# subject_limiter_max_subjects omit-default honesty (residual lite; offline only).
# Optional path + SUBJECT_LIMITER_MAX_SUBJECTS canaries when python3 available.
assert_secret_free_file() {
  local file="$1"
  local label="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  if grep -qiE 'authorization[[:space:]]*:[[:space:]]*\S+|bearer[[:space:]]+[a-z0-9._\-+/=]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' "$file" 2>/dev/null; then
    echo "  [fail] $label contains secret-shaped material (canary)" >&2
    return 1
  fi
  return 0
}

RESIDUAL_STATUS_JSON="$OUT_DIR/gateway-residual-status.json"
if [[ "$SKIP_RESIDUAL_STATUS" == "1" ]]; then
  run_skip "gateway_residual_status" "SKIP_RESIDUAL_STATUS=1"
elif [[ ! -x "$MCP_BIN" ]]; then
  run_skip "gateway_residual_status" "binary not available"
else
  set +e
  "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_JSON" 2>"$OUT_DIR/gateway-residual-status.json.stderr"
  rs_rc=$?
  set -e
  if [[ $rs_rc -ne 0 ]]; then
    if grep -qiE 'unknown gateway subcommand|subcommand required|invalid argument|not found' \
        "$OUT_DIR/gateway-residual-status.json.stderr" 2>/dev/null; then
      run_skip "gateway_residual_status" "gateway residual-status not available on this binary"
      rm -f "$RESIDUAL_STATUS_JSON" "$OUT_DIR/gateway-residual-status.json.stderr"
    else
      ARTIFACT_LINES+=("gateway_residual_status|gateway-residual-status.json|fail|${rs_rc}|exit_code=${rs_rc}")
      HARD_FAIL=1
      if [[ ! -s "$OUT_DIR/gateway-residual-status.json.stderr" ]]; then
        rm -f "$OUT_DIR/gateway-residual-status.json.stderr"
      fi
      echo "  [fail] gateway_residual_status (exit $rs_rc) -> gateway-residual-status.json"
    fi
  else
    rm -f "$OUT_DIR/gateway-residual-status.json.stderr"
    residual_status_ok=1
    if ! assert_secret_free_file "$RESIDUAL_STATUS_JSON" "gateway-residual-status.json"; then
      residual_status_ok=0
      HARD_FAIL=1
    fi
    if [[ ! -f "$RESIDUAL_STATUS_JSON" ]]; then
      residual_status_ok=0
      HARD_FAIL=1
      echo "  [fail] gateway-residual-status.json missing after successful exit" >&2
    elif command -v python3 >/dev/null 2>&1; then
      export PE_RESIDUAL_STATUS_JSON="$RESIDUAL_STATUS_JSON"
      export PE_REQUIRED_STATUS_IDS
      PE_REQUIRED_STATUS_IDS="$(IFS=,; echo "${REQUIRED_RESIDUAL_STATUS_IDS[*]}")"
      if python3 - <<'PY'
import json, os, sys

path = os.environ["PE_RESIDUAL_STATUS_JSON"]
required = [x.strip() for x in os.environ.get("PE_REQUIRED_STATUS_IDS", "").split(",") if x.strip()]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []

# Mode B residual id (oauth009_offline) — always advertised offline.
if data.get("residual_id") != "oauth009_offline":
    errors.append(f"residual_id={data.get('residual_id')!r} want oauth009_offline")
if data.get("oauth009_offline") is not True:
    errors.append(f"oauth009_offline={data.get('oauth009_offline')!r} want true")

ids = data.get("residual_ids") or []
if not isinstance(ids, list):
    errors.append("residual_ids is not a list")
    ids = []
id_set = {str(x) for x in ids}
for rid in required:
    if rid not in id_set:
        errors.append(f"residual_ids missing {rid!r}")

# HOST-008 / multi-pod honesty
if data.get("ha_multi_replica") is not False:
    errors.append(f"ha_multi_replica={data.get('ha_multi_replica')!r} want false")
if data.get("multi_pod_vault_residual") is not True:
    errors.append(f"multi_pod_vault_residual={data.get('multi_pod_vault_residual')!r} want true")
if data.get("gateway_ready") is True:
    errors.append("gateway_ready=true on residual-status CLI (Ready only on serve /readyz)")

# Live mode qualified flags must remain false offline
for k in (
    "mode_a_live_obtain_qualified",
    "mode_b_live_rs_qualified",
    "mode_c_live_agentcore_qualified",
):
    if data.get(k) is True:
        errors.append(f"{k}=true (live pin must stay residual offline)")

# Progressive consent residual object honesty
pc = data.get("progressive_consent") or {}
if isinstance(pc, dict):
    if pc.get("browser_3lo_automated") is True:
        errors.append("progressive_consent.browser_3lo_automated=true")
    if pc.get("metadata_path_done_star") is False:
        errors.append("progressive_consent.metadata_path_done_star must be true (Done*)")
else:
    errors.append("progressive_consent object missing")

# HOST-008 lite: shared_subject_rate_file default false (or absent-as-false).
# Path value never appears; only boolean residual. Aligns with residual-smoke.
ssrf = data.get("shared_subject_rate_file")
if ssrf is True:
    errors.append("shared_subject_rate_file=true without SUBJECT_RATE_PATH (default must be false)")
elif ssrf is not False and ssrf is not None:
    errors.append(f"shared_subject_rate_file={ssrf!r} want false|absent")

# HOST-008 lite: shared_principal_cache_file default false (or absent-as-false).
spcf = data.get("shared_principal_cache_file")
if spcf is True:
    errors.append("shared_principal_cache_file=true without PRINCIPAL_CACHE_PATH (default must be false)")
elif spcf is not False and spcf is not None:
    errors.append(f"shared_principal_cache_file={spcf!r} want false|absent")

# HOST-001 / HOST-008 lite: shared_jwks_file default false (or absent-as-false).
sjwks = data.get("shared_jwks_file")
if sjwks is True:
    errors.append("shared_jwks_file=true without JWKS_CACHE_PATH (default must be false)")
elif sjwks is not False and sjwks is not None:
    errors.append(f"shared_jwks_file={sjwks!r} want false|absent")

# HOST-008 lite: shared_token_cache_file default false (or absent-as-false).
stcf = data.get("shared_token_cache_file")
if stcf is True:
    errors.append("shared_token_cache_file=true without TOKEN_CACHE_PATH (default must be false)")
elif stcf is not False and stcf is not None:
    errors.append(f"shared_token_cache_file={stcf!r} want false|absent")

# HOST-006 residual lite: subject_limiter_max_subjects omit when env unset (unlimited).
# Path never involved — integer hygiene residual only. Aligns with residual-smoke.
slms = data.get("subject_limiter_max_subjects")
if slms is not None and slms is not False and slms != 0 and slms != "":
    errors.append(
        f"subject_limiter_max_subjects={slms!r} want absent|falsey when "
        "JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS unset (default unlimited)"
    )

blob = json.dumps(data).lower()
if "production go complete" in blob:
    errors.append("residual-status overclaims production GO complete")
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in blob:
        errors.append(f"secret-shaped material {needle!r}")
doc = str(data.get("doc") or "") + " " + str(data.get("residual_note") or "")
if "live-pin-blockers" not in doc:
    errors.append("missing live-pin-blockers.md pointer in doc/residual_note")

if errors:
    print("FAIL: residual-status honesty:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print(
    "PASS: gateway residual-status honesty "
    f"(oauth009_offline + ha_multi_replica=false + residual_ids={len(required)} + "
    "shared_subject_rate_file=false default + shared_principal_cache_file=false default + "
    "shared_jwks_file=false default + shared_token_cache_file=false default + "
    "subject_limiter_max_subjects omit default)"
)
sys.exit(0)
PY
      then
        :
      else
        residual_status_ok=0
        HARD_FAIL=1
      fi
    else
      # grep fallback when python3 unavailable
      if grep -q 'oauth009_offline' "$RESIDUAL_STATUS_JSON" \
        && grep -q '"ha_multi_replica": false' "$RESIDUAL_STATUS_JSON" \
        && grep -q 'progressive_consent' "$RESIDUAL_STATUS_JSON" \
        && grep -qE '"shared_subject_rate_file":\s*false' "$RESIDUAL_STATUS_JSON" \
        && grep -qE '"shared_principal_cache_file":\s*false' "$RESIDUAL_STATUS_JSON" \
        && grep -qE '"shared_jwks_file":\s*false' "$RESIDUAL_STATUS_JSON" \
        && grep -qE '"shared_token_cache_file":\s*false' "$RESIDUAL_STATUS_JSON"; then
        echo "  [pass] gateway residual-status greppable honesty markers (no python3)"
      else
        residual_status_ok=0
        HARD_FAIL=1
        echo "  [fail] gateway residual-status missing honesty markers (install python3 for deep assert)" >&2
      fi
    fi

    # Lightweight path + limiter-max canaries (align residual-smoke): path set →
    # shared_*_file=true (path never dumped); SUBJECT_LIMITER_MAX_SUBJECTS=N →
    # subject_limiter_max_subjects==N. Hard-fail when python3 available; residual lite only.
    if [[ $residual_status_ok -eq 1 && -f "$RESIDUAL_STATUS_JSON" ]] \
      && command -v python3 >/dev/null 2>&1; then
      echo "  [=] residual-status shared_*_file path + SUBJECT_LIMITER_MAX canaries (path never dumped)"
      RATE_PATH_MARKER="subject-rate-path-CANARY-never-in-json-$$"
      RATE_TMP_MARKED="$OUT_DIR/${RATE_PATH_MARKER}.dat"
      : >"$RATE_TMP_MARKED"
      RESIDUAL_STATUS_RATE_JSON="$OUT_DIR/gateway-residual-status-rate-path.json"
      set +e
      env JENKINS_MCP_GATEWAY_SUBJECT_RATE_PATH="$RATE_TMP_MARKED" \
        "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_RATE_JSON" 2>"$OUT_DIR/gateway-residual-status-rate-path.stderr"
      rrc=$?
      set -e
      if [[ $rrc -ne 0 ]]; then
        residual_status_ok=0
        HARD_FAIL=1
        echo "  [fail] gateway residual-status with SUBJECT_RATE_PATH exit $rrc" >&2
      else
        assert_secret_free_file "$RESIDUAL_STATUS_RATE_JSON" "gateway-residual-status-rate-path.json" || {
          residual_status_ok=0
          HARD_FAIL=1
        }
        export PE_RATE_JSON="$RESIDUAL_STATUS_RATE_JSON"
        export PE_RATE_MARKER="$RATE_PATH_MARKER"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["PE_RATE_JSON"]
marker = os.environ["PE_RATE_MARKER"]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
if data.get("shared_subject_rate_file") is not True:
    errors.append(
        f"shared_subject_rate_file={data.get('shared_subject_rate_file')!r} want true when SUBJECT_RATE_PATH set"
    )
blob = json.dumps(data)
if marker in blob:
    errors.append("SUBJECT_RATE_PATH / marker leaked into residual-status JSON (path must never dump)")
low = blob.lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in low:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: residual-status SUBJECT_RATE_PATH canary:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print("PASS: residual-status shared_subject_rate_file=true when path set (path not dumped)")
sys.exit(0)
PY
        then
          :
        else
          residual_status_ok=0
          HARD_FAIL=1
        fi
      fi

      PRINCIPAL_PATH_MARKER="principal-cache-path-CANARY-never-in-json-$$"
      PRINCIPAL_TMP_MARKED="$OUT_DIR/${PRINCIPAL_PATH_MARKER}.json"
      : >"$PRINCIPAL_TMP_MARKED"
      RESIDUAL_STATUS_PC_JSON="$OUT_DIR/gateway-residual-status-principal-path.json"
      set +e
      env JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH="$PRINCIPAL_TMP_MARKED" \
        "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_PC_JSON" 2>"$OUT_DIR/gateway-residual-status-principal-path.stderr"
      prc=$?
      set -e
      if [[ $prc -ne 0 ]]; then
        residual_status_ok=0
        HARD_FAIL=1
        echo "  [fail] gateway residual-status with PRINCIPAL_CACHE_PATH exit $prc" >&2
      else
        assert_secret_free_file "$RESIDUAL_STATUS_PC_JSON" "gateway-residual-status-principal-path.json" || {
          residual_status_ok=0
          HARD_FAIL=1
        }
        export PE_PC_JSON="$RESIDUAL_STATUS_PC_JSON"
        export PE_PC_MARKER="$PRINCIPAL_PATH_MARKER"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["PE_PC_JSON"]
marker = os.environ["PE_PC_MARKER"]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
if data.get("shared_principal_cache_file") is not True:
    errors.append(
        f"shared_principal_cache_file={data.get('shared_principal_cache_file')!r} want true when PRINCIPAL_CACHE_PATH set"
    )
blob = json.dumps(data)
if marker in blob:
    errors.append("PRINCIPAL_CACHE_PATH / marker leaked into residual-status JSON (path must never dump)")
low = blob.lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in low:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: residual-status PRINCIPAL_CACHE_PATH canary:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print("PASS: residual-status shared_principal_cache_file=true when path set (path not dumped)")
sys.exit(0)
PY
        then
          :
        else
          residual_status_ok=0
          HARD_FAIL=1
        fi
      fi

      JWKS_PATH_MARKER="jwks-cache-path-CANARY-never-in-json-$$"
      JWKS_TMP_MARKED="$OUT_DIR/${JWKS_PATH_MARKER}.json"
      : >"$JWKS_TMP_MARKED"
      RESIDUAL_STATUS_JWKS_JSON="$OUT_DIR/gateway-residual-status-jwks-path.json"
      set +e
      env JENKINS_MCP_HTTP_JWKS_CACHE_PATH="$JWKS_TMP_MARKED" \
        "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_JWKS_JSON" 2>"$OUT_DIR/gateway-residual-status-jwks-path.stderr"
      jrc=$?
      set -e
      if [[ $jrc -ne 0 ]]; then
        residual_status_ok=0
        HARD_FAIL=1
        echo "  [fail] gateway residual-status with JWKS_CACHE_PATH exit $jrc" >&2
      else
        assert_secret_free_file "$RESIDUAL_STATUS_JWKS_JSON" "gateway-residual-status-jwks-path.json" || {
          residual_status_ok=0
          HARD_FAIL=1
        }
        export PE_JWKS_JSON="$RESIDUAL_STATUS_JWKS_JSON"
        export PE_JWKS_MARKER="$JWKS_PATH_MARKER"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["PE_JWKS_JSON"]
marker = os.environ["PE_JWKS_MARKER"]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
if data.get("shared_jwks_file") is not True:
    errors.append(
        f"shared_jwks_file={data.get('shared_jwks_file')!r} want true when JWKS_CACHE_PATH set"
    )
blob = json.dumps(data)
if marker in blob:
    errors.append("JWKS_CACHE_PATH / marker leaked into residual-status JSON (path must never dump)")
low = blob.lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in low:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: residual-status JWKS_CACHE_PATH canary:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print("PASS: residual-status shared_jwks_file=true when path set (path not dumped)")
sys.exit(0)
PY
        then
          :
        else
          residual_status_ok=0
          HARD_FAIL=1
        fi
      fi

      TOKEN_PATH_MARKER="token-cache-path-CANARY-never-in-json-$$"
      TOKEN_TMP_MARKED="$OUT_DIR/${TOKEN_PATH_MARKER}.json"
      : >"$TOKEN_TMP_MARKED"
      RESIDUAL_STATUS_TOKEN_JSON="$OUT_DIR/gateway-residual-status-token-path.json"
      set +e
      env JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH="$TOKEN_TMP_MARKED" \
        "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_TOKEN_JSON" 2>"$OUT_DIR/gateway-residual-status-token-path.stderr"
      trc=$?
      set -e
      if [[ $trc -ne 0 ]]; then
        residual_status_ok=0
        HARD_FAIL=1
        echo "  [fail] gateway residual-status with TOKEN_CACHE_PATH exit $trc" >&2
      else
        assert_secret_free_file "$RESIDUAL_STATUS_TOKEN_JSON" "gateway-residual-status-token-path.json" || {
          residual_status_ok=0
          HARD_FAIL=1
        }
        export PE_TOKEN_JSON="$RESIDUAL_STATUS_TOKEN_JSON"
        export PE_TOKEN_MARKER="$TOKEN_PATH_MARKER"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["PE_TOKEN_JSON"]
marker = os.environ["PE_TOKEN_MARKER"]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
if data.get("shared_token_cache_file") is not True:
    errors.append(
        f"shared_token_cache_file={data.get('shared_token_cache_file')!r} want true when TOKEN_CACHE_PATH set"
    )
blob = json.dumps(data)
if marker in blob:
    errors.append("TOKEN_CACHE_PATH / marker leaked into residual-status JSON (path must never dump)")
low = blob.lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in low:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: residual-status TOKEN_CACHE_PATH canary:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print("PASS: residual-status shared_token_cache_file=true when path set (path not dumped)")
sys.exit(0)
PY
        then
          :
        else
          residual_status_ok=0
          HARD_FAIL=1
        fi
      fi

      # Optional subtest: SUBJECT_LIMITER_MAX_SUBJECTS set → subject_limiter_max_subjects==N
      # (HOST-006 residual lite). Path never involved; omit when unset (default unlimited).
      echo "  [=] residual-status SUBJECT_LIMITER_MAX_SUBJECTS canary (env=64 → field 64)"
      LIMITER_MAX_CANARY=64
      RESIDUAL_STATUS_LIM_JSON="$OUT_DIR/gateway-residual-status-limiter-max.json"
      set +e
      env JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS="$LIMITER_MAX_CANARY" \
        "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_LIM_JSON" 2>"$OUT_DIR/gateway-residual-status-limiter-max.stderr"
      lrc=$?
      set -e
      if [[ $lrc -ne 0 ]]; then
        residual_status_ok=0
        HARD_FAIL=1
        echo "  [fail] gateway residual-status with SUBJECT_LIMITER_MAX_SUBJECTS exit $lrc" >&2
        if [[ -s "$OUT_DIR/gateway-residual-status-limiter-max.stderr" ]]; then
          head -n 20 "$OUT_DIR/gateway-residual-status-limiter-max.stderr" >&2 || true
        fi
      else
        assert_secret_free_file "$RESIDUAL_STATUS_LIM_JSON" "gateway-residual-status-limiter-max.json" || {
          residual_status_ok=0
          HARD_FAIL=1
        }
        export PE_LIM_JSON="$RESIDUAL_STATUS_LIM_JSON"
        export PE_LIM_WANT="$LIMITER_MAX_CANARY"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["PE_LIM_JSON"]
want = int(os.environ["PE_LIM_WANT"])
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
got = data.get("subject_limiter_max_subjects")
try:
    n = int(got)
except (TypeError, ValueError):
    errors.append(
        f"subject_limiter_max_subjects={got!r} want int {want} when "
        "JENKINS_MCP_GATEWAY_SUBJECT_LIMITER_MAX_SUBJECTS set"
    )
else:
    if n != want:
        errors.append(f"subject_limiter_max_subjects={n} want {want}")
# Path residual fields must not flip solely because limiter max is set.
if data.get("shared_subject_rate_file") is True:
    errors.append("shared_subject_rate_file must stay false without SUBJECT_RATE_PATH")
if data.get("shared_principal_cache_file") is True:
    errors.append("shared_principal_cache_file must stay false without PRINCIPAL_CACHE_PATH")
if data.get("shared_jwks_file") is True:
    errors.append("shared_jwks_file must stay false without JWKS_CACHE_PATH")
if data.get("shared_token_cache_file") is True:
    errors.append("shared_token_cache_file must stay false without TOKEN_CACHE_PATH")
blob = json.dumps(data)
low = blob.lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in low:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: residual-status SUBJECT_LIMITER_MAX_SUBJECTS canary:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print(
    f"PASS: residual-status subject_limiter_max_subjects={want} when env set "
    "(omit when unset; path never involved)"
)
sys.exit(0)
PY
        then
          :
        else
          residual_status_ok=0
          HARD_FAIL=1
        fi
      fi
    fi

    if [[ $residual_status_ok -eq 1 ]]; then
      ARTIFACT_LINES+=("gateway_residual_status|gateway-residual-status.json|pass|0|")
      echo "  [pass] gateway_residual_status (exit 0) -> gateway-residual-status.json"
    else
      ARTIFACT_LINES+=("gateway_residual_status|gateway-residual-status.json|fail|0|honesty_canary_failed")
      echo "  [fail] gateway_residual_status honesty canaries failed -> gateway-residual-status.json"
    fi
  fi
fi

# Optional gateway consent-residual (progressive consent residual; soft skip if missing)
CONSENT_RESIDUAL_JSON="$OUT_DIR/gateway-consent-residual.json"
set +e
"$MCP_BIN" gateway consent-residual >"$CONSENT_RESIDUAL_JSON" 2>"$OUT_DIR/gateway-consent-residual.json.stderr"
cr_rc=$?
set -e
if [[ $cr_rc -ne 0 ]]; then
  if grep -qiE 'unknown gateway subcommand|subcommand required|invalid argument|not found' \
      "$OUT_DIR/gateway-consent-residual.json.stderr" 2>/dev/null; then
    run_skip "gateway_consent_residual" "gateway consent-residual not available on this binary"
  else
    # Non-fatal: residual-status is the required honesty path
    ARTIFACT_LINES+=("gateway_consent_residual||warn|${cr_rc}|exit_code=${cr_rc} non-fatal")
    HAS_WARN=1
    echo "  [warn] gateway_consent_residual (exit $cr_rc; non-fatal; residual-status is required path)"
  fi
  rm -f "$CONSENT_RESIDUAL_JSON" "$OUT_DIR/gateway-consent-residual.json.stderr"
else
  rm -f "$OUT_DIR/gateway-consent-residual.json.stderr"
  consent_ok=1
  if ! assert_secret_free_file "$CONSENT_RESIDUAL_JSON" "gateway-consent-residual.json"; then
    consent_ok=0
    HARD_FAIL=1
  fi
  if [[ -f "$CONSENT_RESIDUAL_JSON" ]] && command -v python3 >/dev/null 2>&1; then
    if python3 - "$CONSENT_RESIDUAL_JSON" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
pc = data.get("progressive_consent") or {}
if not isinstance(pc, dict):
    errors.append("progressive_consent object missing")
else:
    if pc.get("browser_3lo_automated") is True:
        errors.append("browser_3lo_automated=true")
    if pc.get("metadata_path_done_star") is False:
        errors.append("metadata_path_done_star must be true")
blob = json.dumps(data).lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in blob:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: consent-residual honesty:", "; ".join(errors), file=sys.stderr)
    sys.exit(1)
print("PASS: gateway consent-residual progressive consent honesty")
sys.exit(0)
PY
    then
      :
    else
      consent_ok=0
      HARD_FAIL=1
    fi
  fi
  if [[ $consent_ok -eq 1 ]]; then
    ARTIFACT_LINES+=("gateway_consent_residual|gateway-consent-residual.json|pass|0|")
    echo "  [pass] gateway_consent_residual (exit 0) -> gateway-consent-residual.json"
  else
    ARTIFACT_LINES+=("gateway_consent_residual|gateway-consent-residual.json|fail|0|honesty_canary_failed")
    echo "  [fail] gateway_consent_residual honesty canaries failed -> gateway-consent-residual.json"
  fi
fi

# Profile-gated offline checks (doctor is text; pilot-check emits summary + JSON)
if [[ -n "$PROFILE" ]]; then
  run_capture "doctor_offline" "doctor.txt" "$MCP_BIN" doctor --profile "$PROFILE" --offline
  run_capture "pilot_check_offline" "pilot-check.json" "$MCP_BIN" pilot-check --profile "$PROFILE" --offline
else
  run_skip "doctor_offline" "PROFILE not set"
  run_skip "pilot_check_offline" "PROFILE not set"
fi

# Optional go test summary (bounded package list; not full make test)
if [[ "$SKIP_GO_TEST" == "1" ]]; then
  run_skip "go_test_summary" "SKIP_GO_TEST=1"
elif command -v go >/dev/null 2>&1; then
  set +e
  # shellcheck disable=SC2086
  go test $GO_TEST_PKGS -count=1 >"$OUT_DIR/go-test-summary.txt" 2>&1
  gt_rc=$?
  set -e
  if [[ $gt_rc -eq 0 ]]; then
    ARTIFACT_LINES+=("go_test_summary|go-test-summary.txt|pass|0|")
    echo "  [pass] go_test_summary (exit 0) -> go-test-summary.txt"
  else
    ARTIFACT_LINES+=("go_test_summary|go-test-summary.txt|fail|${gt_rc}|exit_code=${gt_rc}")
    HARD_FAIL=1
    echo "  [fail] go_test_summary (exit $gt_rc) -> go-test-summary.txt"
  fi
else
  run_skip "go_test_summary" "go not on PATH"
fi

# --- overall ---
# fail > incomplete (no profile) > warn > pass
OVERALL="pass"
if [[ $HARD_FAIL -eq 1 ]]; then
  OVERALL="fail"
elif [[ -z "$PROFILE" ]]; then
  # PROFILE-gated steps skipped: not a hard fail; evidence pack is incomplete.
  OVERALL="incomplete"
elif [[ $HAS_WARN -eq 1 ]]; then
  OVERALL="warn"
fi

GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"

# Write MANIFEST.json via Python for reliable JSON (stdlib only).
export PE_OUT_DIR="$OUT_DIR"
export PE_GENERATED_AT="$GENERATED_AT"
export PE_OVERALL="$OVERALL"
export PE_PROFILE="$PROFILE"
export PE_BIN="$MCP_BIN"
export PE_HOST_OS="$HOST_OS"
export PE_HOST_ARCH="$HOST_ARCH"
export PE_SCHEMA="jenkins-mcp.pilot-evidence.manifest.v1"

# Serialize artifact lines for Python
PE_ARTIFACTS_FILE="$OUT_DIR/.artifacts.tsv"
: >"$PE_ARTIFACTS_FILE"
for line in "${ARTIFACT_LINES[@]}"; do
  printf '%s\n' "$line" >>"$PE_ARTIFACTS_FILE"
done

python3 - <<'PY'
import json, os, pathlib

out_dir = pathlib.Path(os.environ["PE_OUT_DIR"])
lines = (out_dir / ".artifacts.tsv").read_text(encoding="utf-8").splitlines()
artifacts = []
for line in lines:
    if not line.strip():
        continue
    parts = line.split("|", 4)
    while len(parts) < 5:
        parts.append("")
    name, path, status, exit_code, note = parts
    entry = {
        "name": name,
        "status": status,
        "exit_code": int(exit_code) if str(exit_code).isdigit() or (exit_code.startswith("-") and exit_code[1:].isdigit()) else 0,
    }
    if path:
        entry["path"] = path
    if note:
        entry["note"] = note
    artifacts.append(entry)

profile = (os.environ.get("PE_PROFILE") or "").strip()
manifest = {
    "schema": os.environ["PE_SCHEMA"],
    "generated_at": os.environ["PE_GENERATED_AT"],
    "offline": True,
    "overall": os.environ["PE_OVERALL"],
    "profile_id": profile or None,
    "binary": os.environ.get("PE_BIN") or "",
    "host": {
        "os": os.environ.get("PE_HOST_OS") or "unknown",
        "arch": os.environ.get("PE_HOST_ARCH") or "unknown",
    },
    "artifacts": artifacts,
    "notes": [
        "Secret-free offline/local evidence for REL-001 pilot and REL-002 prep",
        "Do not commit tokens, cookies, or Authorization material into this bundle",
        "gateway-residual-status.json is residual honesty only (not live multi-user / Entra / multi-replica GO)",
    ],
    "residual": [
        "Online pilot-check / whoAmI not run by this script (use pilot-check without --offline when approved)",
        "Full REL-002 make test / package / signing gates not included (see docs/release/gates.md)",
        "Live Rocky/Ubuntu install evidence remains operator-owned",
        "gateway residual-status / consent-residual in this pack are offline honesty — not live Mode B/C pin or multi-pod HA (see docs/gateway/live-pin-blockers.md)",
        "shared_*_file default-false + subject_limiter_max_subjects omit default + path-not-dumped / SUBJECT_LIMITER_MAX_SUBJECTS canaries in this pack; residual-smoke still has fuller residual suite (seeded principal Len, etc.)",
    ],
}
if not profile:
    manifest["notes"].append("PROFILE unset: doctor and pilot-check skipped; overall incomplete until profile run")

# Scrub accidental secret-shaped substrings in string fields (defense in depth).
import re
SECRETISH = re.compile(
    r"(?i)(authorization\s*:\s*\S+|bearer\s+[a-z0-9._\-+/=]{8,}|api[_-]?token\s*[:=]\s*\S+|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)

def scrub(obj):
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        return SECRETISH.sub("[REDACTED]", obj)
    return obj

manifest = scrub(manifest)
# Normalize null profile_id for JSON clarity: omit when empty
if not profile:
    manifest["profile_id"] = ""

path = out_dir / "MANIFEST.json"
path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(f"wrote {path} overall={manifest['overall']}")
PY

rm -f "$PE_ARTIFACTS_FILE"

# Human summary
echo ""
echo "pilot-evidence complete: $OUT_DIR"
echo "  overall=$OVERALL"
echo "  MANIFEST.json + artifact files (secret-free)"
echo "See docs/pilot/README.md and docs/release/gates.md"

if [[ "$OVERALL" == "fail" ]]; then
  exit 1
fi
exit 0
