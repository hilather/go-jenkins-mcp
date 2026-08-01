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
#   4. Optional: gateway residual-status when subcommand exists (Mode B residual id + HA honesty)
#   5. Optional: doctor --offline residual fields when PROFILE= is set
#
# Usage:
#   scripts/gateway-residual-smoke.sh
#   BIN=bin/jenkins-mcp scripts/gateway-residual-smoke.sh
#   PROFILE=corp scripts/gateway-residual-smoke.sh   # also doctor residual fields
#   make residual-smoke
#   make gateway-residual-smoke   # alias
#
# Environment:
#   BIN              — path to jenkins-mcp (else bin/jenkins-mcp, PATH, or go build)
#   OUT_DIR          — artifact dir (default: dist/residual-smoke/<UTC-ts>)
#   PROFILE          — optional; enables doctor --offline residual field checks
#   SKIP_BUILD=1     — do not auto-build if binary missing
#   SKIP_QUALIFY=1   — skip gateway qualify (still check release-evidence residuals)
#   KEEP_ARTIFACTS=1 — keep OUT_DIR on success (default: keep always for evidence)
#
# Exit: 0 on pass; non-zero if qualify fails or residual honesty is missing.
# Secret-free: never prints tokens/cookies/Authorization; fail closed on canaries.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

BIN="${BIN:-}"
OUT_DIR="${OUT_DIR:-}"
PROFILE="${PROFILE:-}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_QUALIFY="${SKIP_QUALIFY:-0}"

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

# --- 3) optional gateway residual-status (unified snapshot; skip on older binaries) ---
RESIDUAL_STATUS_JSON="$OUT_DIR/gateway-residual-status.json"
echo "== gateway residual-status (optional if subcommand exists) =="
set +e
"$MCP_BIN" gateway residual-status >"$RESIDUAL_STATUS_JSON" 2>"$OUT_DIR/gateway-residual-status.stderr"
rsrc=$?
set -e
if [[ $rsrc -ne 0 ]]; then
  # Older binaries lack residual-status — non-fatal skip.
  echo "  [skip] gateway residual-status exit $rsrc (subcommand may be absent on older binary)"
  rm -f "$RESIDUAL_STATUS_JSON" "$OUT_DIR/gateway-residual-status.stderr" 2>/dev/null || true
else
  pass "gateway residual-status exit 0"
  rm -f "$OUT_DIR/gateway-residual-status.stderr"
  assert_secret_free "$RESIDUAL_STATUS_JSON" "gateway-residual-status.json" || true
  if [[ -f "$RESIDUAL_STATUS_JSON" ]] && command -v python3 >/dev/null 2>&1; then
    if python3 - "$RESIDUAL_STATUS_JSON" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
errors = []
if data.get("residual_id") != "oauth009_offline" and data.get("oauth009_offline") is not True:
    # residual_ids list must still advertise Mode B honesty.
    ids = data.get("residual_ids") or []
    if "oauth009_offline" not in ids:
        errors.append("missing Mode B residual id oauth009_offline")
if data.get("ha_multi_replica") is True:
    errors.append("ha_multi_replica=true (HOST-008 single-replica residual violated)")
if data.get("multi_pod_vault_residual") is False:
    errors.append("multi_pod_vault_residual must be true")
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
    print("FAIL: residual-status honesty:", "; ".join(errors), file=sys.stderr)
    sys.exit(1)
print("PASS: gateway residual-status Mode B residual id + HA/multi-pod honesty")
sys.exit(0)
PY
    then
      :
    else
      fail=1
    fi
  elif [[ -f "$RESIDUAL_STATUS_JSON" ]]; then
    if grep -q 'oauth009_offline' "$RESIDUAL_STATUS_JSON" && grep -q 'ha_multi_replica' "$RESIDUAL_STATUS_JSON"; then
      pass "gateway residual-status greppable oauth009_offline + ha_multi_replica"
    else
      fail_msg "gateway residual-status missing oauth009_offline or ha_multi_replica markers"
    fi
  fi
fi

# --- 4) optional doctor --offline residual fields ---
if [[ -n "$PROFILE" ]]; then
  echo "== doctor --offline residual fields (PROFILE=$PROFILE) =="
  DOCTOR_OUT="$OUT_DIR/doctor-offline.txt"
  set +e
  "$MCP_BIN" doctor --profile "$PROFILE" --offline >"$DOCTOR_OUT" 2>"$OUT_DIR/doctor-offline.stderr"
  drc=$?
  set -e
  # Doctor may exit non-zero for unrelated profile issues; residual field asserts are best-effort honesty.
  if [[ $drc -ne 0 ]]; then
    echo "  [warn] doctor exit $drc (still scanning residual honesty fields if present)"
  else
    pass "doctor --offline exit 0"
  fi
  assert_secret_free "$DOCTOR_OUT" "doctor-offline.txt" || true
  if [[ -f "$DOCTOR_OUT" ]]; then
    # Text doctor output includes gateway_status message with ha_multi_replica=false.
    if grep -q 'ha_multi_replica=false' "$DOCTOR_OUT" || grep -q 'ha_multi_replica' "$DOCTOR_OUT"; then
      if grep -q 'ha_multi_replica=false' "$DOCTOR_OUT"; then
        pass "doctor surfaces ha_multi_replica=false (host008 single-replica honesty)"
      else
        # If true appears, that would be dishonest for Tier A.
        if grep -q 'ha_multi_replica=true' "$DOCTOR_OUT"; then
          fail_msg "doctor claims ha_multi_replica=true (HOST-008 single-replica residual violated)"
        else
          pass "doctor mentions ha_multi_replica"
        fi
      fi
    else
      echo "  [warn] doctor output missing ha_multi_replica field (older binary or check skipped)"
    fi
    if grep -qiE 'oauth009|mode_matrix_residual|gateway_ready=false|multi_user' "$DOCTOR_OUT"; then
      pass "doctor surfaces multi-user / oauth009 / gateway residual markers"
    else
      echo "  [warn] doctor output missing multi-user/oauth residual markers (non-fatal)"
    fi
  fi
else
  echo "  [skip] doctor residual fields (PROFILE not set)"
fi

# --- summary ---
SUMMARY="$OUT_DIR/SUMMARY.txt"
{
  echo "gateway-residual-smoke"
  echo "binary=$MCP_BIN"
  echo "out=$OUT_DIR"
  echo "profile=${PROFILE:-}"
  echo "required_residual_ids=${REQUIRED_RESIDUAL_IDS[*]}"
  if [[ $fail -eq 0 ]]; then
    echo "result=pass"
  else
    echo "result=fail"
  fi
} >"$SUMMARY"

echo ""
if [[ $fail -eq 0 ]]; then
  echo "gateway-residual-smoke complete: PASS (artifacts: $OUT_DIR)"
  echo "Honest residual: offline qualify + residual ids ≠ live multi-user / Entra / AgentCore / multi-replica GO"
  echo "See docs/release/gates.md and docs/pilot/checklist.md §0"
  exit 0
fi

echo "gateway-residual-smoke complete: FAIL (artifacts: $OUT_DIR)" >&2
exit 1
