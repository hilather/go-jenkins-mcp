#!/usr/bin/env bash
# HOST-012: disposable OAuth lab smoke (modes B/C mocks).
# Opt-in only — NOT part of default `make test` / `make ci`.
# Never prints access tokens.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/testdata/oauth-lab/docker-compose.yml}"
OIDC_PORT="${OAUTH_OIDC_PORT:-18081}"
RS_PORT="${OAUTH_RS_PORT:-18082}"
TOKEN_PORT="${OAUTH_TOKEN_PORT:-18083}"
BIND="${OAUTH_HOST_BIND:-127.0.0.1}"
ISSUER="${LAB_ISSUER:-http://${BIND}:${OIDC_PORT}}"
AUD="${LAB_AUDIENCE:-jenkins-api}"
KEEP="${OAUTH_LIVE_KEEP:-}"
SKIP_DOWN=0
MANAGE_COMPOSE=1

log() { printf 'oauth-lab-smoke: %s\n' "$*"; }
die() { printf 'oauth-lab-smoke: error: %s\n' "$*" >&2; exit 1; }

# Secret-free: never echo token values.
redact_json_tokens() {
  # shellcheck disable=SC2001
  sed -e 's/"access_token"[[:space:]]*:[[:space:]]*"[^"]*"/"access_token":"***"/g' \
      -e 's/Bearer [A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/Bearer ***/g'
}

cleanup() {
  local ec=$?
  if [[ "$MANAGE_COMPOSE" -eq 0 ]]; then
    exit "$ec"
  fi
  if [[ "$SKIP_DOWN" -eq 1 || "$KEEP" == "1" ]]; then
    log "leaving compose running (OAUTH_LIVE_KEEP=1)"
    exit "$ec"
  fi
  log "compose down -v (destroy lab_keys volume)"
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$ec"
}

if [[ "${1:-}" == "--smoke-only" ]]; then
  MANAGE_COMPOSE=0
  shift || true
fi

if ! command -v docker >/dev/null 2>&1; then
  die "docker not found"
fi
if ! docker compose version >/dev/null 2>&1; then
  die "docker compose v2 not available"
fi
if ! command -v curl >/dev/null 2>&1; then
  die "curl not found"
fi
if [[ ! -f "$COMPOSE_FILE" ]]; then
  die "compose file missing: $COMPOSE_FILE"
fi

if [[ "$MANAGE_COMPOSE" -eq 1 ]]; then
  trap cleanup EXIT
  log "compose up --build --wait"
  OAUTH_OIDC_PORT="$OIDC_PORT" OAUTH_RS_PORT="$RS_PORT" OAUTH_TOKEN_PORT="$TOKEN_PORT" \
    OAUTH_HOST_BIND="$BIND" LAB_ISSUER="$ISSUER" LAB_AUDIENCE="$AUD" \
    docker compose -f "$COMPOSE_FILE" up -d --build --wait
fi

OIDC="http://${BIND}:${OIDC_PORT}"
RS="http://${BIND}:${RS_PORT}"
TOK="http://${BIND}:${TOKEN_PORT}"

wait_http() {
  local url=$1 name=$2
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "$name healthy"
      return 0
    fi
    sleep 1
  done
  die "timeout waiting for $name at $url"
}

wait_http "$OIDC/healthz" "mock-oidc"
wait_http "$RS/healthz" "mock-rs"
wait_http "$TOK/healthz" "mock-token"

log "OIDC discovery"
disc="$(curl -fsS "$OIDC/.well-known/openid-configuration")"
echo "$disc" | grep -q '"issuer"' || die "discovery missing issuer"
echo "$disc" | grep -q 'jwks_uri' || die "discovery missing jwks_uri"
echo "$disc" | grep -q 'token_endpoint' || die "discovery missing token_endpoint"

log "JWKS"
jwks="$(curl -fsS "$OIDC/jwks")"
echo "$jwks" | grep -q '"keys"' || die "jwks missing keys"

log "mint valid token (client_credentials)"
# Capture token in variable only; never log it.
mint_json="$(curl -fsS -X POST "$OIDC/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "audience=${AUD}" \
  --data-urlencode "subject=smoke-user")"
access="$(printf '%s' "$mint_json" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ -z "$access" ]]; then
  die "mint returned empty access_token"
fi
# Sanity: JWT shape without printing.
dots="$(printf '%s' "$access" | awk -F. '{print NF-1}')"
[[ "$dots" == "2" ]] || die "minted token is not compact JWT shape"

log "mock-rs whoAmI with valid token → 200"
who="$(curl -fsS -H "Authorization: Bearer ${access}" "$RS/api/whoAmI")"
echo "$who" | grep -q '"ok":true\|"ok": true' || die "whoAmI not ok: $(printf '%s' "$who" | redact_json_tokens)"
echo "$who" | grep -q 'smoke-user' || die "whoAmI missing sub"

log "mock-rs wrong audience → 401"
bad_json="$(curl -fsS "$OIDC/token?scenario=wrong_audience")"
bad_tok="$(printf '%s' "$bad_json" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
code="$(curl -sS -o /tmp/oauth-lab-rs-body.$$ -w '%{http_code}' \
  -H "Authorization: Bearer ${bad_tok}" "$RS/api/whoAmI" || true)"
rm -f /tmp/oauth-lab-rs-body.$$
[[ "$code" == "401" ]] || die "wrong aud expected 401 got $code"

log "mock-rs expired token → 401"
exp_json="$(curl -fsS "$OIDC/token?scenario=expired")"
exp_tok="$(printf '%s' "$exp_json" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
code="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${exp_tok}" "$RS/api/whoAmI" || true)"
[[ "$code" == "401" ]] || die "expired expected 401 got $code"

log "mock-rs Basic alone → 401 (no fallthrough)"
code="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Authorization: Basic YWRtaW46dGVzdA==' "$RS/api/whoAmI" || true)"
[[ "$code" == "401" ]] || die "basic expected 401 got $code"

log "mock-rs missing auth → 401"
code="$(curl -sS -o /dev/null -w '%{http_code}' "$RS/mcp-rs/check" || true)"
[[ "$code" == "401" ]] || die "missing auth expected 401 got $code"

log "mock-token success (HOST-015 shape)"
tok_json="$(curl -fsS -X POST "$TOK/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject=gw-smoke" \
  --data-urlencode "audience=${AUD}")"
echo "$tok_json" | grep -q 'access_token' || die "token peer missing access_token"
echo "$tok_json" | grep -q "jenkins_principal" || die "token peer missing jenkins_principal"
# Use returned token against RS
gw_tok="$(printf '%s' "$tok_json" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
who2="$(curl -fsS -H "Authorization: Bearer ${gw_tok}" "$RS/api/whoAmI")"
echo "$who2" | grep -q 'gw-smoke' || die "gateway token whoAmI sub mismatch"

log "mock-token consent scenario → 403, no token"
consent="$(curl -sS -w '\n%{http_code}' "$TOK/token?scenario=consent")"
c_body="$(printf '%s' "$consent" | sed '$d')"
c_code="$(printf '%s' "$consent" | tail -n1)"
[[ "$c_code" == "403" ]] || die "consent expected 403 got $c_code"
echo "$c_body" | grep -q 'consent_required' || die "consent missing error"
echo "$c_body" | grep -q 'authorization_url' || die "consent missing authorization_url"
if echo "$c_body" | grep -q 'access_token'; then
  die "consent body must not include access_token"
fi

log "mock-token error scenario → 500"
code="$(curl -sS -o /dev/null -w '%{http_code}' "$TOK/token?scenario=error" || true)"
[[ "$code" == "500" ]] || die "error scenario expected 500 got $code"

log "PASS (HOST-012 smoke; HOST-013/014/015 paths exercised)"
log "residual: real Entra, real jwt-auth-filter plugin, real AgentCore vault"
