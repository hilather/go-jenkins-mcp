#!/usr/bin/env bash
# REL offline residual honesty smoke (opt-in; not part of make test / make ci).
#
# Verifies that offline gateway qualify + release-evidence still emit the
# structured residual ids operators must not treat as live multi-user GO:
#   multi_user_offline · oauth009_offline · oauth010_offline · progressive_consent_offline
#   · host008_single_replica · gateway_modes_live
# Offline only — not live Entra / AgentCore / multi-replica production GO.
#
# Steps:
#   1. Build or reuse jenkins-mcp binary
#   2. jenkins-mcp gateway qualify --offline  (must pass; no live network)
#   3. jenkins-mcp release-evidence --offline (assert residual[] honesty)
#   4. jenkins-mcp gateway residual-status (required Wave 8 honesty; JSON under OUT_DIR)
#      - shared_subject_rate_file false by default; true when SUBJECT_RATE_PATH set (path never dumped)
#      - shared_principal_cache_file false by default; true when PRINCIPAL_CACHE_PATH set (path never dumped)
#      - shared_jwks_file false by default; true when JENKINS_MCP_HTTP_JWKS_CACHE_PATH set (path never dumped)
#      - optional: principal_cache_entries Len when file has entries (secret-free count only)
#      - principal_cache_process_note: principal_cache_entries is this-process / file Len only
#   5. Optional: gateway consent-residual when subcommand exists (progressive consent residual)
#   6. Optional: doctor --offline --json gateway_residual_status when PROFILE= is set
#      (doctor requires --profile; when PROFILE empty, doctor residual is skipped —
#       doctor offline does not run without a profile)
#
# Usage:
#   scripts/gateway-residual-smoke.sh
#   BIN=bin/jenkins-mcp scripts/gateway-residual-smoke.sh
#   PROFILE=corp scripts/gateway-residual-smoke.sh   # also doctor residual embed
#   make residual-smoke
#   make gateway-residual-smoke   # alias
#
# Environment:
#   BIN              — path to jenkins-mcp (else bin/jenkins-mcp, PATH, or go build)
#   OUT_DIR          — artifact dir (default: dist/residual-smoke/<UTC-ts>)
#   PROFILE          — optional; enables doctor --offline --json gateway_residual_status checks
#   SKIP_BUILD=1     — do not auto-build if binary missing
#   SKIP_QUALIFY=1   — skip gateway qualify (still check release-evidence residuals)
#   SKIP_RESIDUAL_STATUS=1 — skip residual-status (not recommended; Wave 8 honesty)
#   KEEP_ARTIFACTS=1 — keep OUT_DIR on success (default: keep always for evidence)
#
# Exit: 0 on pass; non-zero if qualify fails, residual honesty missing, or residual-status
# honesty fields fail. Secret-free: never prints tokens/cookies/Authorization; fail closed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

BIN="${BIN:-}"
OUT_DIR="${OUT_DIR:-}"
PROFILE="${PROFILE:-}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_QUALIFY="${SKIP_QUALIFY:-0}"
SKIP_RESIDUAL_STATUS="${SKIP_RESIDUAL_STATUS:-0}"

# Required residual ids (REL lite honesty — see docs/release/gates.md + pilot checklist §0).
# Offline Done* foundations + open live pins only; never production GO.
REQUIRED_RESIDUAL_IDS=(
  multi_user_offline
  oauth009_offline
  oauth010_offline
  progressive_consent_offline
  host008_single_replica
  gateway_modes_live
)

# residual-status JSON must advertise these residual_ids (Wave 8 CLI honesty).
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
Usage: gateway-residual-smoke.sh [--bin PATH] [--out-dir DIR] [--profile ID]

REL offline residual honesty smoke (opt-in; not default make test).

  --bin PATH       jenkins-mcp binary
  --out-dir DIR    write artifacts here (default: dist/residual-smoke/<ts>)
  --profile ID     also run doctor --offline residual field checks
  --skip-qualify   only assert release-evidence residual ids
  -h, --help       Show this help

Required residual ids (offline honesty): multi_user_offline oauth009_offline
  oauth010_offline progressive_consent_offline host008_single_replica gateway_modes_live
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      BIN="${2:-}"
      shift 2
      ;;
    --bin=*)
      BIN="${1#*=}"
      shift
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --out-dir=*)
      OUT_DIR="${1#*=}"
      shift
      ;;
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --profile=*)
      PROFILE="${1#*=}"
      shift
      ;;
    --skip-qualify)
      SKIP_QUALIFY=1
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

fail=0
pass() { echo "PASS: $*"; }
fail_msg() { echo "FAIL: $*" >&2; fail=1; }

# --- resolve binary ---
resolve_bin() {
  if [[ -n "$BIN" && -x "$BIN" ]]; then
    echo "$BIN"
    return 0
  fi
  if [[ -n "$BIN" && -f "$BIN" ]]; then
    chmod +x "$BIN" 2>/dev/null || true
    if [[ -x "$BIN" ]]; then
      echo "$BIN"
      return 0
    fi
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
    echo "== build bin/jenkins-mcp ==" >&2
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

if [[ -z "$OUT_DIR" ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  OUT_DIR="$ROOT/dist/residual-smoke/$TS"
fi
mkdir -p "$OUT_DIR"

echo "gateway-residual-smoke: binary=$MCP_BIN out=$OUT_DIR profile=${PROFILE:-<none>} skip_qualify=$SKIP_QUALIFY"

# --- secret canary helper (defense in depth; planted patterns must never appear) ---
assert_secret_free() {
  local file="$1"
  local label="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  if grep -qiE 'authorization[[:space:]]*:[[:space:]]*\S+|bearer[[:space:]]+[a-z0-9._\-+/=]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' "$file" 2>/dev/null; then
    fail_msg "$label contains secret-shaped material (canary)"
    return 1
  fi
  return 0
}

# --- 1) gateway qualify --offline ---
QUALIFY_JSON="$OUT_DIR/gateway-qualify.json"
if [[ "$SKIP_QUALIFY" == "1" ]]; then
  echo "  [skip] gateway qualify (SKIP_QUALIFY=1)"
else
  echo "== gateway qualify --offline =="
  set +e
  "$MCP_BIN" gateway qualify --offline >"$QUALIFY_JSON" 2>"$OUT_DIR/gateway-qualify.stderr"
  qrc=$?
  set -e
  if [[ $qrc -ne 0 ]]; then
    fail_msg "gateway qualify --offline exit $qrc"
    if [[ -s "$OUT_DIR/gateway-qualify.stderr" ]]; then
      echo "--- stderr (truncated) ---" >&2
      head -n 40 "$OUT_DIR/gateway-qualify.stderr" >&2 || true
    fi
  else
    pass "gateway qualify --offline exit 0"
    rm -f "$OUT_DIR/gateway-qualify.stderr"
  fi
  assert_secret_free "$QUALIFY_JSON" "gateway-qualify.json" || true

  if [[ -f "$QUALIFY_JSON" ]]; then
    # Prefer python3 (stdlib) for portable JSON; jq optional.
    if command -v python3 >/dev/null 2>&1; then
      if python3 - "$QUALIFY_JSON" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
ok = data.get("ok") is True
suite = data.get("suite")
failed = int(data.get("failed") or 0)
cases = data.get("cases") or []
names = {c.get("name") for c in cases if isinstance(c, dict)}
residuals = data.get("residuals") or []
errors = []
if not ok:
    errors.append(f"ok={data.get('ok')!r} want true")
if suite != "offline":
    errors.append(f"suite={suite!r} want 'offline'")
if failed != 0:
    errors.append(f"failed={failed} want 0")
# Offline Mode B/C residual cases must be present and passed when suite is complete.
case_map = {c.get("name"): c for c in cases if isinstance(c, dict)}
want_cases = [
    ("oauth009_offline_bearer_matrix", ("OAUTH-009", "oauth009")),
    ("oauth010_mode_c_offline_matrix", ("OAUTH-010", "oauth010")),
    ("progressive_consent_residual", ("progressive consent", "OAUTH-010", "progressive_consent")),
]
for want_case, residual_needles in want_cases:
    if want_case not in case_map:
        # Older binaries may rename; still require residual honesty strings when present.
        blob_r = " ".join(str(r) for r in residuals).lower()
        if not any(n.lower() in blob_r for n in residual_needles):
            errors.append(f"missing case {want_case} and no residual honesty string {residual_needles}")
    else:
        if not case_map[want_case].get("passed"):
            errors.append(f"case {want_case} not passed: {case_map[want_case]}")
if not residuals:
    errors.append("residuals[] empty — qualify must list live pins as residual")
# Must not claim production live GO complete (honest residuals may say
# "do not claim live Entra Done" — only flag explicit production GO complete).
blob = json.dumps(data).lower()
if "production go complete" in blob:
    errors.append("qualify summary overclaims production GO complete")
if errors:
    print("FAIL: gateway qualify JSON:", "; ".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"PASS: gateway qualify ok suite={suite} passed={data.get('passed')} residual_count={len(residuals)}")
sys.exit(0)
PY
      then
        :
      else
        fail=1
      fi
    elif command -v jq >/dev/null 2>&1; then
      if jq -e '.ok == true and .suite == "offline" and .failed == 0 and (.residuals | length) > 0' "$QUALIFY_JSON" >/dev/null; then
        pass "gateway qualify JSON ok/suite/failed/residuals"
      else
        fail_msg "gateway qualify JSON structure failed jq assertions"
      fi
    else
      if grep -q '"ok": true' "$QUALIFY_JSON" && grep -q '"suite": "offline"' "$QUALIFY_JSON"; then
        pass "gateway qualify JSON contains ok/suite (no python3/jq for deep assert)"
      else
        fail_msg "gateway qualify JSON missing ok/suite markers"
      fi
    fi
  fi
fi

# --- 2) release-evidence --offline + residual id honesty ---
EVIDENCE_JSON="$OUT_DIR/release-evidence.json"
echo "== release-evidence --offline =="
set +e
"$MCP_BIN" release-evidence --offline --output "$EVIDENCE_JSON" 2>"$OUT_DIR/release-evidence.stderr"
erc=$?
set -e
if [[ $erc -ne 0 ]]; then
  fail_msg "release-evidence --offline exit $erc"
  if [[ -s "$OUT_DIR/release-evidence.stderr" ]]; then
    head -n 40 "$OUT_DIR/release-evidence.stderr" >&2 || true
  fi
else
  pass "release-evidence --offline exit 0"
  # stderr is expected ("wrote release evidence…"); keep for artifacts
fi
assert_secret_free "$EVIDENCE_JSON" "release-evidence.json" || true

if [[ ! -f "$EVIDENCE_JSON" ]]; then
  fail_msg "release-evidence.json missing"
else
  # Export required ids for Python.
  export GRS_EVIDENCE_JSON="$EVIDENCE_JSON"
  export GRS_REQUIRED_IDS
  GRS_REQUIRED_IDS="$(IFS=,; echo "${REQUIRED_RESIDUAL_IDS[*]}")"
  if command -v python3 >/dev/null 2>&1; then
    if python3 - <<'PY'
import json, os, sys

path = os.environ["GRS_EVIDENCE_JSON"]
required = [x.strip() for x in os.environ.get("GRS_REQUIRED_IDS", "").split(",") if x.strip()]
with open(path, encoding="utf-8") as f:
    data = json.load(f)

errors = []
schema = data.get("schema") or ""
if schema != "jenkins-mcp.release-evidence.v2":
    errors.append(f"schema={schema!r} want jenkins-mcp.release-evidence.v2")
if data.get("offline") is not True:
    errors.append(f"offline={data.get('offline')!r} want true")
overall = data.get("overall") or ""
if overall == "fail":
    errors.append(f"overall=fail (lite offline must not hard-fail without suite)")

residuals = data.get("residual") or []
if not isinstance(residuals, list):
    errors.append("residual is not a list")
    residuals = []

by_id = {}
for r in residuals:
    if not isinstance(r, dict):
        continue
    rid = (r.get("id") or "").strip()
    if rid:
        by_id[rid] = r

for rid in required:
    if rid not in by_id:
        errors.append(f"missing residual id {rid!r}")
        continue
    msg = (by_id[rid].get("message") or "").strip()
    if not msg:
        errors.append(f"residual {rid!r} has empty message")
    # Honesty: multi_user / oauth009 / oauth010 / progressive_consent mark Done* offline;
    # host008 single-replica; modes live residual. Offline only — not production GO.
    low = msg.lower()
    if rid == "multi_user_offline" and "done*" not in low:
        errors.append(f"{rid} message should mark Done* foundation: {msg[:120]!r}")
    if rid == "oauth009_offline":
        if "done*" not in low:
            errors.append(f"{rid} message should mark Done* offline foundation: {msg[:120]!r}")
        if "oauth-009" not in low and "oauth009" not in low:
            errors.append(f"{rid} message should reference OAUTH-009: {msg[:120]!r}")
    if rid == "oauth010_offline":
        if "done*" not in low:
            errors.append(f"{rid} message should mark Done* offline foundation: {msg[:120]!r}")
        if "oauth-010" not in low and "oauth010" not in low:
            errors.append(f"{rid} message should reference OAUTH-010: {msg[:120]!r}")
    if rid == "progressive_consent_offline":
        if "done*" not in low:
            errors.append(f"{rid} message should mark Done* metadata foundation: {msg[:120]!r}")
        if "browser" not in low and "3lo" not in low:
            errors.append(f"{rid} message should note browser 3LO residual: {msg[:120]!r}")
    if rid == "host008_single_replica" and "single-replica" not in low and "single replica" not in low:
        errors.append(f"{rid} message should state single-replica honesty: {msg[:120]!r}")
    if rid == "gateway_modes_live" and "residual" not in low and "live" not in low:
        errors.append(f"{rid} message should mark live modes residual: {msg[:120]!r}")

# Must not claim production sign-off complete.
blob = json.dumps(data).lower()
if "production go complete" in blob:
    errors.append("release-evidence claims production GO complete")

# gateway_qualify_offline check when present should be pass (or skip if qualify skipped in builder).
checks = {c.get("id"): c for c in (data.get("checks") or []) if isinstance(c, dict)}
gq = checks.get("gateway_qualify_offline")
if gq is not None:
    st = gq.get("status")
    if st not in ("pass", "skip"):
        errors.append(f"gateway_qualify_offline status={st!r} want pass|skip")

if errors:
    print("FAIL: release-evidence residual honesty:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    present = sorted(by_id.keys())
    print(f"  present residual ids ({len(present)}): {', '.join(present)}", file=sys.stderr)
    sys.exit(1)

print(f"PASS: release-evidence residual ids present ({len(required)} required): {', '.join(required)}")
print(f"      schema={schema} overall={overall} residual_count={len(by_id)}")
sys.exit(0)
PY
    then
      :
    else
      fail=1
    fi
  elif command -v jq >/dev/null 2>&1; then
    missing=0
    for rid in "${REQUIRED_RESIDUAL_IDS[@]}"; do
      if jq -e --arg id "$rid" '.residual[]? | select(.id == $id) | .message | length > 0' "$EVIDENCE_JSON" >/dev/null 2>&1; then
        pass "residual id $rid present with message"
      else
        fail_msg "missing residual id $rid (or empty message)"
        missing=1
      fi
    done
    if [[ $missing -eq 0 ]]; then
      pass "all required residual ids via jq"
    fi
  else
    # Last-resort grep (weaker).
    for rid in "${REQUIRED_RESIDUAL_IDS[@]}"; do
      if grep -q "\"id\": \"$rid\"" "$EVIDENCE_JSON"; then
        pass "residual id $rid greppable"
      else
        fail_msg "missing residual id $rid (grep fallback; install python3)"
      fi
    done
  fi
fi

# --- 3) gateway residual-status (Wave 8 CLI; required honesty canaries) ---
RESIDUAL_STATUS_JSON="$OUT_DIR/gateway-residual-status.json"
if [[ "$SKIP_RESIDUAL_STATUS" == "1" ]]; then
  echo "  [skip] gateway residual-status (SKIP_RESIDUAL_STATUS=1)"
else
  echo "== gateway residual-status =="
  set +e
  "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_JSON" 2>"$OUT_DIR/gateway-residual-status.stderr"
  rsrc=$?
  set -e
  if [[ $rsrc -ne 0 ]]; then
    # Unknown subcommand on very old binaries → soft skip; any other failure is hard fail.
    if grep -qiE 'unknown gateway subcommand|subcommand required' "$OUT_DIR/gateway-residual-status.stderr" 2>/dev/null; then
      echo "  [skip] gateway residual-status not present on this binary"
      rm -f "$RESIDUAL_STATUS_JSON" 2>/dev/null || true
    else
      fail_msg "gateway residual-status exit $rsrc"
      if [[ -s "$OUT_DIR/gateway-residual-status.stderr" ]]; then
        head -n 40 "$OUT_DIR/gateway-residual-status.stderr" >&2 || true
      fi
    fi
  else
    pass "gateway residual-status exit 0"
    rm -f "$OUT_DIR/gateway-residual-status.stderr"
    assert_secret_free "$RESIDUAL_STATUS_JSON" "gateway-residual-status.json" || true
    if [[ ! -f "$RESIDUAL_STATUS_JSON" ]]; then
      fail_msg "gateway-residual-status.json missing after successful exit"
    elif command -v python3 >/dev/null 2>&1; then
      export GRS_RESIDUAL_STATUS_JSON="$RESIDUAL_STATUS_JSON"
      export GRS_REQUIRED_STATUS_IDS
      GRS_REQUIRED_STATUS_IDS="$(IFS=,; echo "${REQUIRED_RESIDUAL_STATUS_IDS[*]}")"
      if python3 - <<'PY'
import json, os, sys

path = os.environ["GRS_RESIDUAL_STATUS_JSON"]
required = [x.strip() for x in os.environ.get("GRS_REQUIRED_STATUS_IDS", "").split(",") if x.strip()]
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
# Path value never appears; only boolean residual.
ssrf = data.get("shared_subject_rate_file")
if ssrf is True:
    errors.append("shared_subject_rate_file=true without SUBJECT_RATE_PATH (default must be false)")
elif ssrf is not False and ssrf is not None:
    errors.append(f"shared_subject_rate_file={ssrf!r} want false|absent")

# HOST-008 lite: shared_principal_cache_file default false (or absent-as-false).
# Path value never appears; only boolean residual + secret-free count.
spcf = data.get("shared_principal_cache_file")
if spcf is True:
    errors.append("shared_principal_cache_file=true without PRINCIPAL_CACHE_PATH (default must be false)")
elif spcf is not False and spcf is not None:
    errors.append(f"shared_principal_cache_file={spcf!r} want false|absent")

# HOST-001 / HOST-008 lite: shared_jwks_file default false (or absent-as-false).
# Path value never appears; only boolean residual (public JWKS snapshot only).
sjwks = data.get("shared_jwks_file")
if sjwks is True:
    errors.append("shared_jwks_file=true without JWKS_CACHE_PATH (default must be false)")
elif sjwks is not False and sjwks is not None:
    errors.append(f"shared_jwks_file={sjwks!r} want false|absent")

# principal_cache_entries is this-process count only (CLI/admin ≠ remote serve).
pc_note = str(data.get("principal_cache_process_note") or "")
note_blob = pc_note + " " + str(data.get("residual_note") or "")
if pc_note:
    low_pc = pc_note.lower()
    if "this process" not in low_pc and "process only" not in low_pc and "process memory" not in low_pc:
        errors.append("principal_cache_process_note missing process-local honesty")
elif "process" not in note_blob.lower() and "principal_cache" not in note_blob.lower():
    # Older binaries may omit the field; residual_note still carries honesty.
    pass  # residual_note pointer checked below
# Always require residual honesty pointer when process note absent.
if not pc_note and not str(data.get("residual_note") or "").strip():
    errors.append("missing principal_cache_process_note and residual_note")

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
    "progressive_consent + shared_subject_rate_file=false default + "
    "shared_principal_cache_file=false default + shared_jwks_file=false default + "
    "principal_cache process note)"
)
sys.exit(0)
PY
      then
        :
      else
        fail=1
      fi
    else
      # grep fallback when python3 unavailable
      if grep -q 'oauth009_offline' "$RESIDUAL_STATUS_JSON" \
        && grep -q '"ha_multi_replica": false' "$RESIDUAL_STATUS_JSON" \
        && grep -q 'progressive_consent' "$RESIDUAL_STATUS_JSON"; then
        pass "gateway residual-status greppable honesty markers (no python3)"
      else
        fail_msg "gateway residual-status missing honesty markers (install python3 for deep assert)"
      fi
    fi

    # Optional subtest: SUBJECT_RATE_PATH set → shared_subject_rate_file=true (path never dumped).
    if [[ -f "$RESIDUAL_STATUS_JSON" ]] && command -v python3 >/dev/null 2>&1; then
      echo "== gateway residual-status (SUBJECT_RATE_PATH canary) =="
      RATE_TMP="$OUT_DIR/subject-rate-path-canary.dat"
      : >"$RATE_TMP"
      # Unique path marker used only to assert it is NOT echoed in JSON.
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
        fail_msg "gateway residual-status with SUBJECT_RATE_PATH exit $rrc"
        if [[ -s "$OUT_DIR/gateway-residual-status-rate-path.stderr" ]]; then
          head -n 20 "$OUT_DIR/gateway-residual-status-rate-path.stderr" >&2 || true
        fi
      else
        assert_secret_free "$RESIDUAL_STATUS_RATE_JSON" "gateway-residual-status-rate-path.json" || true
        export GRS_RATE_JSON="$RESIDUAL_STATUS_RATE_JSON"
        export GRS_RATE_MARKER="$RATE_PATH_MARKER"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["GRS_RATE_JSON"]
marker = os.environ["GRS_RATE_MARKER"]
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
# secret-shaped canaries
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
          fail=1
        fi
      fi

      # Optional subtest: PRINCIPAL_CACHE_PATH set → shared_principal_cache_file=true
      # (path never dumped). When file has entries, principal_cache_entries is Len only.
      echo "== gateway residual-status (PRINCIPAL_CACHE_PATH canary) =="
      PRINCIPAL_PATH_MARKER="principal-cache-path-CANARY-never-in-json-$$"
      PRINCIPAL_TMP_MARKED="$OUT_DIR/${PRINCIPAL_PATH_MARKER}.json"
      # Seed secret-free FilePrincipalCache doc (2 entries) to exercise file Len residual.
      # Subject keys / principals must never appear in residual-status JSON — only count.
      PRINCIPAL_SEED_SK="t1|seed-sub-canary|corp"
      PRINCIPAL_SEED_JP="seed-jenkins-principal-CANARY-never-in-json"
      cat >"$PRINCIPAL_TMP_MARKED" <<EOF
{
  "version": 1,
  "entries": {
    "${PRINCIPAL_SEED_SK}": {
      "principal": "${PRINCIPAL_SEED_JP}",
      "last_access": "2020-01-01T00:00:00Z"
    },
    "t1|seed-sub-canary-2|corp": {
      "principal": "seed-jp-2-CANARY",
      "last_access": "2020-01-01T00:00:01Z"
    }
  }
}
EOF
      RESIDUAL_STATUS_PC_JSON="$OUT_DIR/gateway-residual-status-principal-path.json"
      set +e
      env JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH="$PRINCIPAL_TMP_MARKED" \
        "$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_PC_JSON" 2>"$OUT_DIR/gateway-residual-status-principal-path.stderr"
      prc=$?
      set -e
      if [[ $prc -ne 0 ]]; then
        fail_msg "gateway residual-status with PRINCIPAL_CACHE_PATH exit $prc"
        if [[ -s "$OUT_DIR/gateway-residual-status-principal-path.stderr" ]]; then
          head -n 20 "$OUT_DIR/gateway-residual-status-principal-path.stderr" >&2 || true
        fi
      else
        assert_secret_free "$RESIDUAL_STATUS_PC_JSON" "gateway-residual-status-principal-path.json" || true
        export GRS_PC_JSON="$RESIDUAL_STATUS_PC_JSON"
        export GRS_PC_MARKER="$PRINCIPAL_PATH_MARKER"
        export GRS_PC_SEED_SK="$PRINCIPAL_SEED_SK"
        export GRS_PC_SEED_JP="$PRINCIPAL_SEED_JP"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["GRS_PC_JSON"]
marker = os.environ["GRS_PC_MARKER"]
seed_sk = os.environ.get("GRS_PC_SEED_SK", "")
seed_jp = os.environ.get("GRS_PC_SEED_JP", "")
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
if data.get("shared_principal_cache_file") is not True:
    errors.append(
        f"shared_principal_cache_file={data.get('shared_principal_cache_file')!r} want true when PRINCIPAL_CACHE_PATH set"
    )
# File Len residual: seeded 2 secret-free entries → principal_cache_entries == 2.
entries = data.get("principal_cache_entries")
try:
    n = int(entries)
except (TypeError, ValueError):
    errors.append(f"principal_cache_entries={entries!r} want int count when path set")
else:
    if n != 2:
        errors.append(f"principal_cache_entries={n} want 2 (seeded file Len; secret-free count only)")
blob = json.dumps(data)
if marker in blob:
    errors.append("PRINCIPAL_CACHE_PATH / marker leaked into residual-status JSON (path must never dump)")
if seed_sk and seed_sk in blob:
    errors.append("subject key inventory leaked into residual-status JSON")
if seed_jp and seed_jp in blob:
    errors.append("jenkins principal value leaked into residual-status JSON")
if "seed-jp-2-CANARY" in blob:
    errors.append("second seed principal leaked into residual-status JSON")
# secret-shaped canaries
low = blob.lower()
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in low:
        errors.append(f"secret-shaped material {needle!r}")
if errors:
    print("FAIL: residual-status PRINCIPAL_CACHE_PATH canary:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print(
    "PASS: residual-status shared_principal_cache_file=true when path set "
    "(path not dumped; principal_cache_entries=2 file Len)"
)
sys.exit(0)
PY
        then
          :
        else
          fail=1
        fi
      fi

      # Optional subtest: JWKS_CACHE_PATH set → shared_jwks_file=true (path never dumped).
      # residual-status uses auth.JWKSCachePathConfiguredFromEnviron — empty path file is enough.
      echo "== gateway residual-status (JWKS_CACHE_PATH canary) =="
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
        fail_msg "gateway residual-status with JWKS_CACHE_PATH exit $jrc"
        if [[ -s "$OUT_DIR/gateway-residual-status-jwks-path.stderr" ]]; then
          head -n 20 "$OUT_DIR/gateway-residual-status-jwks-path.stderr" >&2 || true
        fi
      else
        assert_secret_free "$RESIDUAL_STATUS_JWKS_JSON" "gateway-residual-status-jwks-path.json" || true
        export GRS_JWKS_JSON="$RESIDUAL_STATUS_JWKS_JSON"
        export GRS_JWKS_MARKER="$JWKS_PATH_MARKER"
        if python3 - <<'PY'
import json, os, sys

path = os.environ["GRS_JWKS_JSON"]
marker = os.environ["GRS_JWKS_MARKER"]
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
# secret-shaped canaries (public JWKS only — never tokens)
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
          fail=1
        fi
      fi
    fi
  fi
fi

# --- 4) optional gateway consent-residual (progressive consent residual snapshot) ---
CONSENT_RESIDUAL_JSON="$OUT_DIR/gateway-consent-residual.json"
echo "== gateway consent-residual (optional if subcommand exists) =="
set +e
"$MCP_BIN" gateway consent-residual >"$CONSENT_RESIDUAL_JSON" 2>"$OUT_DIR/gateway-consent-residual.stderr"
crc=$?
set -e
if [[ $crc -ne 0 ]]; then
  if grep -qiE 'unknown gateway subcommand|subcommand required' "$OUT_DIR/gateway-consent-residual.stderr" 2>/dev/null; then
    echo "  [skip] gateway consent-residual not present on this binary"
  else
    echo "  [warn] gateway consent-residual exit $crc (non-fatal; residual-status is required path)"
  fi
  rm -f "$CONSENT_RESIDUAL_JSON" 2>/dev/null || true
else
  pass "gateway consent-residual exit 0"
  rm -f "$OUT_DIR/gateway-consent-residual.stderr"
  assert_secret_free "$CONSENT_RESIDUAL_JSON" "gateway-consent-residual.json" || true
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
      fail=1
    fi
  fi
fi

# --- 5) optional doctor --offline residual embed (requires PROFILE; doctor needs --profile) ---
# Doctor offline does not run without a profile — skip when PROFILE empty.
if [[ -n "$PROFILE" ]]; then
  echo "== doctor --offline --json gateway_residual_status (PROFILE=$PROFILE) =="
  DOCTOR_JSON="$OUT_DIR/doctor-offline.json"
  DOCTOR_TXT="$OUT_DIR/doctor-offline.txt"
  set +e
  "$MCP_BIN" doctor --profile "$PROFILE" --offline --json >"$DOCTOR_JSON" 2>"$OUT_DIR/doctor-offline.stderr"
  drc=$?
  set -e
  # Doctor may exit non-zero for unrelated profile issues (e.g. missing keyring);
  # residual embed asserts still run when JSON is parseable.
  if [[ $drc -ne 0 ]]; then
    echo "  [warn] doctor exit $drc (still scanning gateway_residual_status if present)"
  else
    pass "doctor --offline --json exit 0"
  fi
  assert_secret_free "$DOCTOR_JSON" "doctor-offline.json" || true
  # Also capture text form for greppable residual section (non-fatal).
  set +e
  "$MCP_BIN" doctor --profile "$PROFILE" --offline >"$DOCTOR_TXT" 2>/dev/null
  set -e
  assert_secret_free "$DOCTOR_TXT" "doctor-offline.txt" || true

  if [[ -f "$DOCTOR_JSON" ]] && command -v python3 >/dev/null 2>&1; then
    export GRS_DOCTOR_JSON="$DOCTOR_JSON"
    export GRS_REQUIRED_STATUS_IDS
    GRS_REQUIRED_STATUS_IDS="$(IFS=,; echo "${REQUIRED_RESIDUAL_STATUS_IDS[*]}")"
    if python3 - <<'PY'
import json, os, sys

path = os.environ["GRS_DOCTOR_JSON"]
required = [x.strip() for x in os.environ.get("GRS_REQUIRED_STATUS_IDS", "").split(",") if x.strip()]
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"FAIL: doctor JSON unparseable: {e}", file=sys.stderr)
    sys.exit(1)

errors = []
grs = data.get("gateway_residual_status")
if not isinstance(grs, dict):
    errors.append("gateway_residual_status missing or not object (OPS doctor residual embed)")
    grs = {}

# Same honesty contract as gateway residual-status (nested under doctor JSON).
if grs.get("residual_id") != "oauth009_offline":
    errors.append(f"gateway_residual_status.residual_id={grs.get('residual_id')!r} want oauth009_offline")
if grs.get("oauth009_offline") is not True:
    errors.append(f"gateway_residual_status.oauth009_offline={grs.get('oauth009_offline')!r} want true")
if grs.get("ha_multi_replica") is not False:
    errors.append(f"gateway_residual_status.ha_multi_replica={grs.get('ha_multi_replica')!r} want false")
if grs.get("gateway_ready") is True:
    errors.append("gateway_residual_status.gateway_ready=true (Ready only on serve /readyz)")
if grs.get("multi_pod_vault_residual") is not True:
    errors.append(f"gateway_residual_status.multi_pod_vault_residual={grs.get('multi_pod_vault_residual')!r} want true")

ids = grs.get("residual_ids") or []
if not isinstance(ids, list):
    errors.append("gateway_residual_status.residual_ids is not a list")
    ids = []
id_set = {str(x) for x in ids}
for rid in required:
    if rid not in id_set:
        errors.append(f"gateway_residual_status.residual_ids missing {rid!r}")

for k in (
    "mode_a_live_obtain_qualified",
    "mode_b_live_rs_qualified",
    "mode_c_live_agentcore_qualified",
):
    if grs.get(k) is True:
        errors.append(f"gateway_residual_status.{k}=true (live pin must stay residual)")

blob = json.dumps(data).lower()
if "production go complete" in blob:
    errors.append("doctor JSON overclaims production GO complete")
for needle in ("access_token=", "refresh_token=", "client_secret=", "authorization: bearer"):
    if needle in blob:
        errors.append(f"secret-shaped material {needle!r} in doctor JSON")
doc = str(grs.get("doc") or "") + " " + str(grs.get("residual_note") or "")
if grs and "live-pin-blockers" not in doc:
    errors.append("gateway_residual_status missing live-pin-blockers.md pointer")

if errors:
    print("FAIL: doctor gateway_residual_status honesty:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    sys.exit(1)
print(
    "PASS: doctor --offline --json gateway_residual_status honesty "
    f"(oauth009_offline + ha_multi_replica=false + residual_ids={len(required)})"
)
sys.exit(0)
PY
    then
      :
    else
      fail=1
    fi
  elif [[ -f "$DOCTOR_JSON" ]]; then
    if grep -q 'gateway_residual_status' "$DOCTOR_JSON" \
      && grep -q 'oauth009_offline' "$DOCTOR_JSON" \
      && grep -q 'ha_multi_replica' "$DOCTOR_JSON"; then
      pass "doctor JSON greppable gateway_residual_status honesty (no python3)"
    else
      fail_msg "doctor JSON missing gateway_residual_status honesty markers (install python3)"
    fi
  else
    fail_msg "doctor-offline.json missing"
  fi

  # Text form residual section (best-effort; older binaries may omit).
  if [[ -f "$DOCTOR_TXT" ]]; then
    if grep -q 'gateway_residual_status' "$DOCTOR_TXT" || grep -q 'ha_multi_replica' "$DOCTOR_TXT"; then
      if grep -q 'ha_multi_replica=true' "$DOCTOR_TXT" && ! grep -q 'ha_multi_replica=false\|ha_multi_replica: false' "$DOCTOR_TXT"; then
        fail_msg "doctor text claims ha_multi_replica=true (HOST-008 residual violated)"
      else
        pass "doctor text surfaces residual / ha_multi_replica honesty"
      fi
    else
      echo "  [warn] doctor text missing residual markers (non-fatal when JSON path passed)"
    fi
  fi
else
  echo "  [skip] doctor residual embed (PROFILE not set; doctor requires --profile)"
fi

# --- summary ---
SUMMARY="$OUT_DIR/SUMMARY.txt"
{
  echo "gateway-residual-smoke"
  echo "binary=$MCP_BIN"
  echo "out=$OUT_DIR"
  echo "profile=${PROFILE:-}"
  echo "required_residual_ids=${REQUIRED_RESIDUAL_IDS[*]}"
  echo "residual_status=required_unless_skip"
  echo "consent_residual=optional"
  if [[ $fail -eq 0 ]]; then
    echo "result=pass"
  else
    echo "result=fail"
  fi
} >"$SUMMARY"

echo ""
if [[ $fail -eq 0 ]]; then
  echo "gateway-residual-smoke complete: PASS (artifacts: $OUT_DIR)"
  echo "Honest residual: offline qualify + residual-status + residual ids ≠ live multi-user / Entra / AgentCore / multi-replica GO"
  echo "See docs/release/gates.md and docs/pilot/checklist.md §0"
  exit 0
fi

echo "gateway-residual-smoke complete: FAIL (artifacts: $OUT_DIR)" >&2
exit 1
