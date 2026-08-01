#!/usr/bin/env bash
# Trigger rebuilds for all mock-inv-* fixture jobs on the disposable Jenkins lab.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/testdata/jenkins-compose/docker-compose.yml}"
JENKINS_HOST_PORT="${JENKINS_HOST_PORT:-18080}"
JENKINS_URL="${JENKINS_URL:-http://127.0.0.1:${JENKINS_HOST_PORT}}"

if ! command -v docker >/dev/null; then
  echo "docker required" >&2
  exit 1
fi

if ! docker compose -f "$COMPOSE_FILE" ps --status running -q jenkins >/dev/null 2>&1; then
  echo "Jenkins container is not running. Start with: make live-jenkins-up" >&2
  exit 1
fi

JENKINS_USER="$(docker compose -f "$COMPOSE_FILE" exec -T jenkins cat /var/jenkins_home/mcp-api-user)"
JENKINS_API_TOKEN="$(docker compose -f "$COMPOSE_FILE" exec -T jenkins cat /var/jenkins_home/mcp-api-token)"

jobs=(
  mock-inv-baseline-green
  mock-inv-regression-broken
  mock-inv-compile-failure
  mock-inv-test-failure
  mock-inv-unstable
  mock-inv-nested-stages
  mock-inv-parallel-mixed
  mock-inv-docker-error
  mock-inv-oom-killed
  mock-inv-long-log
  mock-inv-post-failure
  mock-inv-multi-artifact
  mock-inv-build-graph-downstream
  mock-inv-build-graph-upstream
  # queue-blocked stays queued; optional rebuild skip
)

echo "Triggering ${#jobs[@]} fixture builds on ${JENKINS_URL} ..."
for job in "${jobs[@]}"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    -u "${JENKINS_USER}:${JENKINS_API_TOKEN}" \
    -X POST "${JENKINS_URL}/job/${job}/build")"
  if [[ "$code" != "201" && "$code" != "200" && "$code" != "302" ]]; then
    echo "WARN: ${job} build trigger returned HTTP ${code} (job may not exist yet)" >&2
  else
    echo "  queued ${job}"
  fi
done

echo "Done. Wait for builds in Jenkins UI or re-run MCP diagnose when queue drains."
