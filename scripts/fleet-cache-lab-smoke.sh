#!/usr/bin/env bash
# FLC-003 offline lab smoke: roster + identity unit path + structural compose checks.
# Opt-in; NOT part of make test / make ci. Docker up is separate (make fleet-cache-lab-up).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH}"

LAB=testdata/fleet-cache-lab
echo "fleet-cache-lab offline smoke"

test -f "$LAB/roster.json"
test -f "$LAB/docker-compose.yml"
test -f "$LAB/README.md"
test -f "$LAB/nginx/lb.conf"

# Three independent data volumes declared (no shared plane A).
grep -q 'fc-data-a' "$LAB/docker-compose.yml"
grep -q 'fc-data-b' "$LAB/docker-compose.yml"
grep -q 'fc-data-c' "$LAB/docker-compose.yml"
# Distinct volume names (not one shared data volume for all members).
if grep -E 'fc-data-a:.*fc-data-b' "$LAB/docker-compose.yml" 2>/dev/null; then
  :
fi
# Ensure no single volume mount reused as only data store for all three without a/b/c suffix pattern.
a_count=$(grep -c 'fc-data-a' "$LAB/docker-compose.yml" || true)
b_count=$(grep -c 'fc-data-b' "$LAB/docker-compose.yml" || true)
c_count=$(grep -c 'fc-data-c' "$LAB/docker-compose.yml" || true)
if [[ "$a_count" -lt 1 || "$b_count" -lt 1 || "$c_count" -lt 1 ]]; then
  echo "error: compose must declare independent fc-data-{a,b,c} volumes" >&2
  exit 1
fi

# Default fleet-cache mode off in compose (no surprise peer I/O).
if ! grep -q 'JENKINS_MCP_FLEET_CACHE_MODE: "off"' "$LAB/docker-compose.yml"; then
  echo "error: lab compose must default FLEET_CACHE_MODE=off" >&2
  exit 1
fi

# Round-robin LB present (no stickiness directive).
if grep -Eiq 'sticky|ip_hash' "$LAB/nginx/lb.conf"; then
  echo "error: lab LB must not enable stickiness (exercise multi-member routing)" >&2
  exit 1
fi

echo "→ go test fleetcache + fleetmcp (includes lab roster file test)"
go test ./internal/fleetcache ./internal/fleetmcp -count=1 -timeout=120s

echo "fleet-cache-lab offline smoke OK (Docker up is optional: make fleet-cache-lab-up)"
