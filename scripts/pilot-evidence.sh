#!/usr/bin/env bash
# REL-001 / REL-002 lite: offline/local pilot + release evidence bundle.
#
# Collects secret-free CLI outputs into dist/pilot-evidence/<timestamp>/ with
# MANIFEST.json. Never prints or captures tokens, cookies, Authorization material,
# or private keys. Prefer --offline paths; optional PROFILE enables doctor/pilot-check.
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
OUT_ROOT="${OUT_ROOT:-$ROOT/dist/pilot-evidence}"
GO_TEST_PKGS="${GO_TEST_PKGS:-./cmd/jenkins-mcp/}"
BIN="${BIN:-}"

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
    ],
    "residual": [
        "Online pilot-check / whoAmI not run by this script (use pilot-check without --offline when approved)",
        "Full REL-002 make test / package / signing gates not included (see docs/release/gates.md)",
        "Live Rocky/Ubuntu install evidence remains operator-owned",
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
