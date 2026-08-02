#!/usr/bin/env bash
# Opt-in free lab: Keycloak OIDC + real Jenkins jwt-auth-filter (OAUTH-009).
# NOT part of default make test / make ci.
#
# Usage (repo root):
#   scripts/jwt-rs-lab-smoke.sh              # up + checks
#   scripts/jwt-rs-lab-smoke.sh --smoke-only # assume compose already up
#   scripts/jwt-rs-lab-smoke.sh --down       # smoke then down -v
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${COMPOSE_JWT_RS:-testdata/jwt-rs-lab/docker-compose.yml}"
HOST_BIND="${JWT_RS_HOST_BIND:-127.0.0.1}"
KC_PORT="${JWT_RS_KC_PORT:-18091}"
J_PORT="${JWT_RS_JENKINS_PORT:-18092}"
KC_BASE="http://${HOST_BIND}:${KC_PORT}"
J_BASE="http://${HOST_BIND}:${J_PORT}"
REALM="${JWT_RS_KC_REALM:-jwt-rs-lab}"
AUDIENCE="${JWT_RS_AUDIENCE:-jenkins-api}"
CLIENT_OK="${JWT_RS_CLIENT_ID:-jenkins-api}"
CLIENT_BAD="${JWT_RS_WRONG_CLIENT_ID:-wrong-audience-client}"
USER="${JWT_RS_LAB_USER:-alice}"
PASS="${JWT_RS_LAB_PASSWORD:-alice-lab}"

SMOKE_ONLY=0
DO_DOWN=0
for a in "$@"; do
  case "$a" in
    --smoke-only) SMOKE_ONLY=1 ;;
    --down) DO_DOWN=1 ;;
    -h|--help)
      sed -n '1,12p' "$0"
      exit 0
      ;;
  esac
done

die() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

cleanup() {
  if [[ "$DO_DOWN" -eq 1 ]]; then
    echo "== compose down (trap) =="
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v docker >/dev/null || die "docker required"
command -v curl >/dev/null || die "curl required"
command -v python3 >/dev/null || die "python3 required (token JSON parse)"

if [[ "$SMOKE_ONLY" -eq 0 ]]; then
  echo "== compose up (Keycloak + Jenkins jwt-auth-filter) =="
  JWT_RS_HOST_BIND="$HOST_BIND" JWT_RS_KC_PORT="$KC_PORT" JWT_RS_JENKINS_PORT="$J_PORT" \
    docker compose -f "$COMPOSE_FILE" up -d --build
fi

echo "== wait for Keycloak realm $REALM at $KC_BASE =="
ok=0
for _ in $(seq 1 90); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 \
    "$KC_BASE/realms/$REALM" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then
    ok=1
    break
  fi
  sleep 2
done
[[ "$ok" -eq 1 ]] || die "Keycloak realm not ready ($KC_BASE/realms/$REALM)"
pass "Keycloak realm HTTP 200"

echo "== wait for Jenkins at $J_BASE =="
ok=0
for _ in $(seq 1 120); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 \
    "$J_BASE/login" 2>/dev/null || true)"
  if [[ "$code" == "200" || "$code" == "403" ]]; then
    ok=1
    break
  fi
  sleep 3
done
[[ "$ok" -eq 1 ]] || die "Jenkins not ready ($J_BASE/login)"
pass "Jenkins login reachable"

mint_token() {
  local client="$1"
  local out
  out="$(curl -fsS --connect-timeout 10 \
    -X POST "$KC_BASE/realms/$REALM/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=password" \
    -d "client_id=${client}" \
    -d "username=${USER}" \
    -d "password=${PASS}" \
    -d "scope=openid profile email" 2>&1)" || {
    echo "token endpoint error for client=$client: $out" >&2
    return 1
  }
  python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$out"
}

echo "== mint access token (client=$CLIENT_OK, aud expected=$AUDIENCE) =="
TOK="$(mint_token "$CLIENT_OK")" || die "failed to mint good token"
[[ -n "$TOK" ]] || die "empty access_token"
# Never print the token.
pass "minted access token (length ${#TOK})"

echo "== Bearer whoAmI (expect authenticated success) =="
WHOAMI_BODY="$(mktemp)"
WHOAMI_CODE="$(curl -sS -o "$WHOAMI_BODY" -w '%{http_code}' --connect-timeout 10 \
  -H "Authorization: Bearer ${TOK}" \
  "$J_BASE/whoAmI/api/json" || true)"
if [[ "$WHOAMI_CODE" != "200" ]]; then
  echo "whoAmI body:" >&2
  head -c 800 "$WHOAMI_BODY" >&2 || true
  die "whoAmI HTTP $WHOAMI_CODE (want 200) with valid Bearer"
fi
# Jenkins whoAmI: anonymous users still report authenticated=true with name=anonymous.
# Real RS success = non-anonymous principal (preferred_username from JWT).
python3 - "$WHOAMI_BODY" "$USER" <<'PY' || die "whoAmI body not authenticated as lab user"
import json, sys
path, want = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
if d.get("anonymous") is True or str(d.get("name", "")).lower() == "anonymous":
    raise SystemExit(f"anonymous principal (want {want}): {d!r}")
name = str(d.get("name") or d.get("id") or "")
if want not in name and want not in str(d.get("id", "")):
    raise SystemExit(f"unexpected principal {name!r}, want {want!r}: {d!r}")
print("whoAmI ok name=", name, "anonymous=", d.get("anonymous"))
PY
pass "Bearer whoAmI authenticated as lab user (HTTP 200)"

echo "== Bearer /api/json (expect 200; non-anonymous Jenkins root API) =="
API_BODY="$(mktemp)"
API_CODE="$(curl -sS -o "$API_BODY" -w '%{http_code}' --connect-timeout 10 \
  -H "Authorization: Bearer ${TOK}" \
  "$J_BASE/api/json?tree=mode" || true)"
[[ "$API_CODE" == "200" ]] || die "Bearer /api/json HTTP $API_CODE (want 200) body=$(head -c 200 "$API_BODY")"
pass "Bearer /api/json HTTP 200"

is_real_principal() {
  # exit 0 if JSON whoAmI is a real (non-anonymous) principal
  python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
anon = d.get("anonymous") is True or str(d.get("name","")).lower()=="anonymous"
sys.exit(0 if (not anon and d.get("name")) else 1)' "$1"
}

echo "== invalid Bearer /api/json (expect non-2xx; no silent API success) =="
# jwt-auth-filter ignores invalid JWT and continues; with allowAnonymousRead=false,
# unauthenticated /api/** must not return 2xx job data.
INV_BODY="$(mktemp)"
INV_CODE="$(curl -sS -o "$INV_BODY" -w '%{http_code}' --connect-timeout 10 \
  -H "Authorization: Bearer CANARY_invalid_jwt_not_a_token_xyz" \
  "$J_BASE/api/json?tree=mode" || true)"
if [[ "$INV_CODE" =~ ^2 ]]; then
  die "invalid Bearer /api/json got HTTP $INV_CODE (want non-2xx) body=$(head -c 200 "$INV_BODY")"
fi
pass "invalid Bearer /api/json fail-closed HTTP $INV_CODE"

# whoAmI residual note: anonymous still reports authenticated=true name=anonymous
INV_W="$(mktemp)"
curl -sS -o "$INV_W" --connect-timeout 10 \
  -H "Authorization: Bearer CANARY_invalid_jwt_not_a_token_xyz" \
  "$J_BASE/whoAmI/api/json" >/dev/null || true
if is_real_principal "$INV_W"; then
  die "invalid Bearer whoAmI is a real principal"
fi
pass "invalid Bearer whoAmI not a real principal"

echo "== wrong-audience Bearer /api/json (expect non-2xx) =="
BAD_TOK="$(mint_token "$CLIENT_BAD")" || die "failed to mint wrong-aud token"
BAD_BODY="$(mktemp)"
BAD_CODE="$(curl -sS -o "$BAD_BODY" -w '%{http_code}' --connect-timeout 10 \
  -H "Authorization: Bearer ${BAD_TOK}" \
  "$J_BASE/api/json?tree=mode" || true)"
if [[ "$BAD_CODE" =~ ^2 ]]; then
  die "wrong-aud Bearer /api/json got HTTP $BAD_CODE body=$(head -c 200 "$BAD_BODY")"
fi
pass "wrong-aud Bearer /api/json fail-closed HTTP $BAD_CODE"

# Canary: secrets never printed above (token values not echoed).
echo
echo "Lab ready (free Keycloak OIDC + real jwt-auth-filter):"
echo "  Keycloak:  $KC_BASE  (admin / lab-only)"
echo "  Realm:     $REALM"
echo "  Jenkins:   $J_BASE"
echo "  Audience:  $AUDIENCE"
echo "  Lab user:  $USER / (lab password)"
echo
echo "Residual: free plugin lab ≠ site Entra / production RS GO."
echo "  Product bar: docs/gateway/free-lab-qualification.md"
echo "  Operator pin: docs/gateway/live-pin-blockers.md"
echo "  Mock fallback: make live-oauth-* (testdata/oauth-lab)"

if [[ "$DO_DOWN" -eq 1 ]]; then
  echo "== compose down =="
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
  pass "lab torn down"
  DO_DOWN=0  # prevent double cleanup on EXIT
fi

echo "jwt-rs-lab-smoke: OK"
