#!/usr/bin/env bash
# TST-001: disposable Jenkins LTS up → live smoke tests → down -v.
# Not part of default `make test`. Never prints API tokens.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/testdata/jenkins-compose/docker-compose.yml}"
export JENKINS_ADMIN_PASSWORD="${JENKINS_ADMIN_PASSWORD:-test}"
export JENKINS_HOST_PORT="${JENKINS_HOST_PORT:-18080}"
KEEP="${JENKINS_LIVE_KEEP:-}"
SKIP_DOWN=0

log() { printf 'jenkins-live-smoke: %s\n' "$*"; }
die() { printf 'jenkins-live-smoke: error: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local ec=$?
  if [[ "$SKIP_DOWN" -eq 1 || "$KEEP" == "1" ]]; then
    log "leaving compose running (JENKINS_LIVE_KEEP=1 or early skip)"
    exit "$ec"
  fi
  log "compose down -v (destroy ephemeral volume + credentials)"
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$ec"
}

if ! command -v docker >/dev/null 2>&1; then
  die "docker not found"
fi
if ! docker compose version >/dev/null 2>&1; then
  die "docker compose v2 not available"
fi
if ! command -v go >/dev/null 2>&1; then
  die "go not found (export PATH=\"\$HOME/.local/go/bin:\$PATH\")"
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
  die "compose file missing: $COMPOSE_FILE"
fi

trap cleanup EXIT

log "compose up --build --wait (port ${JENKINS_HOST_PORT})"
docker compose -f "$COMPOSE_FILE" up -d --build --wait

# Wait for init groovy token + seed marker (healthcheck only proves HTTP login page).
log "waiting for mcp-api-token and mcp-init-complete"
deadline=$((SECONDS + 300))
token=""
user="admin"
while (( SECONDS < deadline )); do
  if docker compose -f "$COMPOSE_FILE" exec -T jenkins test -f /var/jenkins_home/mcp-api-token 2>/dev/null; then
    token="$(docker compose -f "$COMPOSE_FILE" exec -T jenkins cat /var/jenkins_home/mcp-api-token 2>/dev/null | tr -d '\r\n' || true)"
    if docker compose -f "$COMPOSE_FILE" exec -T jenkins test -f /var/jenkins_home/mcp-api-user 2>/dev/null; then
      user="$(docker compose -f "$COMPOSE_FILE" exec -T jenkins cat /var/jenkins_home/mcp-api-user 2>/dev/null | tr -d '\r\n' || true)"
    fi
    if [[ -n "$token" ]]; then
      # Prefer init-complete, but do not block forever if builds are slow.
      if docker compose -f "$COMPOSE_FILE" exec -T jenkins test -f /var/jenkins_home/mcp-init-complete 2>/dev/null; then
        break
      fi
      # Token is enough to start whoAmI; jobs may still be seeding.
      if (( SECONDS + 30 >= deadline )); then
        log "token ready; init-complete not yet present — continuing"
        break
      fi
    fi
  fi
  sleep 3
done

if [[ -z "$token" ]]; then
  die "timed out waiting for /var/jenkins_home/mcp-api-token (check compose logs)"
fi
if [[ -z "$user" ]]; then
  user="admin"
fi

export JENKINS_URL="${JENKINS_URL:-http://127.0.0.1:${JENKINS_HOST_PORT}}"
export JENKINS_USER="$user"
export JENKINS_API_TOKEN="$token"
# Do not export token to child processes via xtrace
set +x

log "running live smoke: go test ./internal/jenkins/live/ -tags=live_jenkins (JENKINS_URL=${JENKINS_URL})"
# -count=1 disables cache; never pass token on the command line.
go test ./internal/jenkins/live/ -count=1 -tags=live_jenkins -timeout=5m

log "live smoke OK"
# cleanup trap tears down unless KEEP=1
