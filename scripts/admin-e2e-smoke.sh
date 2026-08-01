#!/usr/bin/env bash
# UI-009: opt-in admin console E2E smoke (BFF + SPA assets + token gate).
#
# Starts a real `jenkins-mcp admin serve` against a temp profile/XDG tree and
# minimal SPA assets, curls health/me/metrics/policy/audit + 401 gate, writes
# a small status artifact under dist/admin-e2e/ (or $OUT_DIR).
#
# NOT part of default `make test` / `make ci` — residual full-browser Playwright
# / Cypress automation is intentionally deferred (document in docs/admin).
#
# Usage:
#   scripts/admin-e2e-smoke.sh
#   BIN=bin/jenkins-mcp make admin-e2e
#   OUT_DIR=/tmp/admin-e2e scripts/admin-e2e-smoke.sh
#
# Exit: 0 on pass; non-zero on failure. Always tears down the server (trap).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${HOME}/.local/node-v22.14.0-linux-x64/bin:${PATH:-}"

BIN="${BIN:-}"
if [[ -z "${BIN}" ]]; then
  if [[ -x "${ROOT}/bin/jenkins-mcp" ]]; then
    BIN="${ROOT}/bin/jenkins-mcp"
  else
    echo "== build bin/jenkins-mcp =="
    mkdir -p "${ROOT}/bin"
    go build -o "${ROOT}/bin/jenkins-mcp" ./cmd/jenkins-mcp
    BIN="${ROOT}/bin/jenkins-mcp"
  fi
fi
if [[ ! -f "${BIN}" ]]; then
  echo "FAIL: binary not found: ${BIN}" >&2
  exit 1
fi
if [[ ! -x "${BIN}" ]]; then
  chmod +x "${BIN}" || true
fi

OUT_DIR="${OUT_DIR:-${ROOT}/dist/admin-e2e}"
mkdir -p "${OUT_DIR}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/admin-e2e.XXXXXX")"
SERVER_PID=""
cleanup() {
  local ec=$?
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORKDIR}"
  exit "${ec}"
}
trap cleanup EXIT INT TERM

# Isolated XDG tree + planted profile (secret-free).
export XDG_CONFIG_HOME="${WORKDIR}/xdg-config"
export XDG_DATA_HOME="${WORKDIR}/xdg-data"
export XDG_CACHE_HOME="${WORKDIR}/xdg-cache"
mkdir -p \
  "${XDG_CONFIG_HOME}/jenkins-mcp/profiles" \
  "${XDG_DATA_HOME}/jenkins-mcp/profiles/corp/audit" \
  "${XDG_CACHE_HOME}/jenkins-mcp"

cat > "${XDG_CONFIG_HOME}/jenkins-mcp/profiles/corp.json" <<'EOF'
{
  "configVersion": 1,
  "id": "corp",
  "displayName": "UI009 E2E Corp",
  "jenkinsURL": "https://jenkins.example.corp/",
  "authMethod": "api_token",
  "username": "alice"
}
EOF

# Minimal SPA shell (or reuse web/admin/dist / embed via --assets-dir).
ASSETS_DIR="${WORKDIR}/assets"
mkdir -p "${ASSETS_DIR}"
if [[ -f "${ROOT}/web/admin/dist/index.html" ]]; then
  # Prefer production dist when present (no npm install required here).
  ASSETS_DIR="${ROOT}/web/admin/dist"
  echo "using SPA assets: ${ASSETS_DIR}"
else
  cat > "${ASSETS_DIR}/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>jenkins-mcp admin e2e</title></head>
<body data-admin-e2e="1"><h1>admin e2e shell</h1></body>
</html>
EOF
  printf 'e2e-smoke\n' > "${ASSETS_DIR}/UI_BUILD"
  echo "using minimal SPA shell: ${ASSETS_DIR}"
fi

# Shared secret via env (never argv). Canary must not appear in API bodies.
export UI009_E2E_ADMIN_TOKEN='planted-admin-secret-UI009-E2E-NEVER-ECHO'
CANARY="${UI009_E2E_ADMIN_TOKEN}"

# Free high loopback port (CLI :0 is hard to discover from logs alone).
pick_port() {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
    return
  fi
  # Fallback: try random high ports.
  local p
  for _ in $(seq 1 40); do
    p=$(( 19000 + RANDOM % 4000 ))
    if ! (echo >/dev/tcp/127.0.0.1/"${p}") 2>/dev/null; then
      echo "${p}"
      return
    fi
  done
  echo "FAIL: could not pick free port" >&2
  exit 1
}
PORT="$(pick_port)"
ADDR="127.0.0.1:${PORT}"
BASE="http://${ADDR}"

echo "== admin serve ${ADDR} (role=viewer, require-token) =="
"${BIN}" admin serve \
  --addr "${ADDR}" \
  --profile corp \
  --admin-token-env UI009_E2E_ADMIN_TOKEN \
  --admin-role viewer \
  --require-token \
  --assets-dir "${ASSETS_DIR}" \
  >"${WORKDIR}/server.stdout" 2>"${WORKDIR}/server.stderr" &
SERVER_PID=$!

# Wait until health is up (with token).
deadline=$(( SECONDS + 15 ))
ready=0
while (( SECONDS < deadline )); do
  if curl -fsS -H "Authorization: Bearer ${CANARY}" "${BASE}/admin/v1/health" \
    -o "${WORKDIR}/health.json" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "FAIL: admin serve exited early" >&2
    cat "${WORKDIR}/server.stderr" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ "${ready}" != "1" ]]; then
  echo "FAIL: health not ready within timeout" >&2
  cat "${WORKDIR}/server.stderr" >&2 || true
  exit 1
fi

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_no_canary() {
  local file="$1"
  if grep -F -q "${CANARY}" "${file}" 2>/dev/null; then
    fail "secret canary appeared in ${file}"
  fi
}

auth_hdr=(-H "Authorization: Bearer ${CANARY}")

echo "== GET /admin/v1/health =="
curl -fsS "${auth_hdr[@]}" "${BASE}/admin/v1/health" -o "${WORKDIR}/health.json"
grep -q '"status":"ok"' "${WORKDIR}/health.json" || grep -q '"status": "ok"' "${WORKDIR}/health.json" \
  || fail "health missing status ok: $(cat "${WORKDIR}/health.json")"
assert_no_canary "${WORKDIR}/health.json"

echo "== GET /admin/v1/me =="
curl -fsS "${auth_hdr[@]}" "${BASE}/admin/v1/me" -o "${WORKDIR}/me.json"
grep -q '"role":"viewer"' "${WORKDIR}/me.json" || grep -q '"role": "viewer"' "${WORKDIR}/me.json" \
  || fail "me role not viewer: $(cat "${WORKDIR}/me.json")"
assert_no_canary "${WORKDIR}/me.json"

echo "== GET /admin/v1/metrics =="
curl -fsS "${auth_hdr[@]}" "${BASE}/admin/v1/metrics" -o "${WORKDIR}/metrics.json"
assert_no_canary "${WORKDIR}/metrics.json"

echo "== GET /admin/v1/profiles/corp/policy/effective =="
curl -fsS "${auth_hdr[@]}" "${BASE}/admin/v1/profiles/corp/policy/effective" -o "${WORKDIR}/policy.json"
assert_no_canary "${WORKDIR}/policy.json"

echo "== GET /admin/v1/profiles/corp/audit (empty ok) =="
curl -fsS "${auth_hdr[@]}" "${BASE}/admin/v1/profiles/corp/audit" -o "${WORKDIR}/audit.json"
assert_no_canary "${WORKDIR}/audit.json"
grep -q '"events"' "${WORKDIR}/audit.json" || fail "audit missing events field"

echo "== 401 without token when required =="
code="$(curl -sS -o "${WORKDIR}/unauth.json" -w '%{http_code}' "${BASE}/admin/v1/health" || true)"
[[ "${code}" == "401" ]] || fail "want 401 without token, got ${code}"
assert_no_canary "${WORKDIR}/unauth.json"

echo "== SPA shell GET / =="
curl -fsS "${BASE}/" -o "${WORKDIR}/index.html"
grep -qi 'html' "${WORKDIR}/index.html" || fail "root not HTML"
assert_no_canary "${WORKDIR}/index.html"

echo "== SPA deep link /metrics =="
curl -fsS "${BASE}/metrics" -o "${WORKDIR}/metrics-spa.html"
grep -qi 'html' "${WORKDIR}/metrics-spa.html" || fail "deep link not HTML shell"

# CSP present on API
csp="$(curl -sS -D - -o /dev/null "${auth_hdr[@]}" "${BASE}/admin/v1/health" | tr -d '\r' | awk -F': ' 'tolower($1)=="content-security-policy"{print $2; exit}')"
[[ -n "${csp}" ]] || fail "missing Content-Security-Policy on health"
echo "${csp}" | grep -q "script-src" || fail "CSP missing script-src"

# Viewer cannot apply policy (RBAC smoke; matches Go TestUI009_ViewerCannotApplyPolicy)
echo "== viewer POST policy/apply → 403 =="
code="$(curl -sS -o "${WORKDIR}/apply.json" -w '%{http_code}' \
  -X POST "${auth_hdr[@]}" -H 'Content-Type: application/json' \
  -d '{"overlay":{"version":1,"force_read_only":true,"mode":"pilot"}}' \
  "${BASE}/admin/v1/policy/apply" || true)"
[[ "${code}" == "403" ]] || fail "viewer apply want 403, got ${code} body=$(cat "${WORKDIR}/apply.json")"
assert_no_canary "${WORKDIR}/apply.json"

# Write artifact (secret-free status JSON).
STATUS_JSON="${OUT_DIR}/status.json"
cat > "${STATUS_JSON}" <<EOF
{
  "task": "UI-009",
  "result": "pass",
  "addr": "${ADDR}",
  "role": "viewer",
  "tokenRequired": true,
  "assets": "${ASSETS_DIR}",
  "checks": [
    "health",
    "me",
    "metrics",
    "policy_effective",
    "audit",
    "unauth_401",
    "spa_root",
    "spa_deeplink",
    "csp",
    "viewer_apply_403",
    "secret_canary_absent"
  ],
  "residual": "No Playwright/Cypress; full browser XSS execute residual. Primary gate is go test ./internal/admin -run UI009"
}
EOF
# Never write canary into artifact.
assert_no_canary "${STATUS_JSON}"

echo "admin-e2e-smoke PASS (artifact: ${STATUS_JSON})"
echo "residual: Playwright/Cypress full-browser E2E not added (opt-in Go+curl smoke only)"
