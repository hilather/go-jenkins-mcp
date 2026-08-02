#!/usr/bin/env bash
# Opt-in Keycloak SAML lab smoke (POL-007).
# NOT part of default make test / make ci.
#
# Usage (repo root):
#   scripts/saml-lab-smoke.sh              # up + checks + offline unit suite
#   scripts/saml-lab-smoke.sh --smoke-only # assume compose already up
#   scripts/saml-lab-smoke.sh --down       # tear down after smoke (full test)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${COMPOSE_SAML:-testdata/saml-lab/docker-compose.yml}"
HOST_BIND="${SAML_HOST_BIND:-127.0.0.1}"
KC_PORT="${SAML_KC_PORT:-18090}"
BASE="http://${HOST_BIND}:${KC_PORT}"
REALM="${SAML_KC_REALM:-jenkins-mcp-lab}"
GEN_DIR="${SAML_LAB_GEN:-testdata/saml-lab/.generated}"
SP_ENTITY="${SAML_SP_ENTITY_ID:-http://127.0.0.1:8787/sp}"
ACS_URL="${SAML_ACS_URL:-http://127.0.0.1:8787/admin/v1/saml/acs}"

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

command -v docker >/dev/null || die "docker required"
command -v curl >/dev/null || die "curl required"

export PATH="${HOME}/.local/go/bin:${PATH:-}"

if [[ "$SMOKE_ONLY" -eq 0 ]]; then
  echo "== compose up =="
  SAML_HOST_BIND="$HOST_BIND" SAML_KC_PORT="$KC_PORT" \
    docker compose -f "$COMPOSE_FILE" up -d
fi

echo "== wait for realm $REALM at $BASE =="
ok=0
for _ in $(seq 1 60); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 \
    "$BASE/realms/$REALM" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then
    ok=1
    break
  fi
  sleep 2
done
[[ "$ok" -eq 1 ]] || die "Keycloak realm not ready after wait ($BASE/realms/$REALM)"
pass "realm HTTP 200"

META_URL="$BASE/realms/$REALM/protocol/saml/descriptor"
meta="$(curl -fsS --connect-timeout 5 "$META_URL")" || die "fetch SAML descriptor"
echo "$meta" | grep -Eqi 'EntityDescriptor|entityID|X509Certificate' \
  || die "descriptor missing EntityDescriptor/X509Certificate markers"
pass "SAML IdP descriptor reachable"

mkdir -p "$GEN_DIR"
# Prefer ds: prefix then plain element.
cert_b64="$(printf '%s\n' "$meta" | tr -d '\r\n' | sed -n 's/.*<ds:X509Certificate>\([^<]*\)<\/ds:X509Certificate>.*/\1/p' | head -1)"
if [[ -z "$cert_b64" ]]; then
  cert_b64="$(printf '%s\n' "$meta" | tr -d '\r\n' | sed -n 's/.*<X509Certificate>\([^<]*\)<\/X509Certificate>.*/\1/p' | head -1)"
fi
[[ -n "$cert_b64" ]] || die "no X509Certificate in IdP metadata"
{
  echo "-----BEGIN CERTIFICATE-----"
  printf '%s' "$cert_b64" | fold -w 64
  echo
  echo "-----END CERTIFICATE-----"
} >"$GEN_DIR/idp.pem"
pass "wrote $GEN_DIR/idp.pem"

CERT_ABS="$(cd "$(dirname "$GEN_DIR/idp.pem")" && pwd)/$(basename "$GEN_DIR/idp.pem")"
IDP_ENTITY="$BASE/realms/$REALM"

cat >"$GEN_DIR/saml-config.json" <<EOF
{
  "schema_version": 1,
  "enabled": true,
  "require": false,
  "sp_entity_id": "${SP_ENTITY}",
  "acs_url": "${ACS_URL}",
  "idp_entity_id": "${IDP_ENTITY}",
  "idp_certificate_pem_path": "${CERT_ABS}",
  "attribute_map": {
    "subject_attribute": "",
    "groups_attribute": "groups"
  },
  "group_roles": {
    "mcp-operators": "operator",
    "mcp-viewers": "viewer",
    "mcp-admins": "policy_admin",
    "/mcp-operators": "operator",
    "/mcp-viewers": "viewer",
    "/mcp-admins": "policy_admin"
  },
  "max_groups": 64
}
EOF
pass "wrote $GEN_DIR/saml-config.json"

if command -v go >/dev/null; then
  go run scripts/saml-lab-check-config.go "$GEN_DIR/saml-config.json" \
    || die "product config/trust load failed"
  go test -count=1 ./internal/saml/ ./internal/admin/ -run 'SAML|Saml' \
    || die "saml unit suite failed"
  pass "offline SAML unit suite + product config load"
else
  echo "WARN: go not on PATH; skipped product checks"
fi

echo
echo "Lab ready (disposable Keycloak SAML IdP):"
echo "  Console:      $BASE  (admin / ${SAML_KC_ADMIN_PASSWORD:-admin})"
echo "  Realm:        $REALM"
echo "  IdP entity:   $IDP_ENTITY"
echo "  Metadata:     $META_URL"
echo "  Lab users:    alice / alice-lab  (group mcp-operators → operator)"
echo "                bob / bob-lab      (group mcp-viewers → viewer)"
echo "  SP config:    $ROOT/$GEN_DIR/saml-config.json"
echo "  Trust PEM:    $CERT_ABS"
echo
echo "Wire admin serve on host:"
echo "  export JENKINS_MCP_SAML_CONFIG=$ROOT/$GEN_DIR/saml-config.json"
echo "  jenkins-mcp admin serve --addr 127.0.0.1:8787 --admin-role viewer"
echo
echo "IdP account console (create/browse clients):"
echo "  $BASE/admin  (master realm admin)"
echo
echo "Residual: live Entra pin; browser ACS + full XML-DSig Keycloak assertions"
echo "  may need SP hardening — offline unit path remains CI source of truth."

if [[ "$DO_DOWN" -eq 1 ]]; then
  echo "== compose down =="
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
  pass "lab torn down"
fi

echo "saml-lab-smoke: OK"
