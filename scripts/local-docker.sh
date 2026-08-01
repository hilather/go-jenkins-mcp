#!/usr/bin/env bash
# Local Docker support stack helper (deploy/local).
# First-class operator UX: auto .env token, optional profile bootstrap, status.
# Usage: scripts/local-docker.sh up|down|build|ps|logs|status|doctor|init-profile|version|shell|run -- <cli args>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${LOCAL_COMPOSE_FILE:-$ROOT/deploy/local/docker-compose.yml}"
ENV_FILE="${LOCAL_ENV_FILE:-$ROOT/deploy/local/.env}"
ENV_EXAMPLE="${LOCAL_ENV_EXAMPLE:-$ROOT/deploy/local/.env.example}"
PROJECT_DIR="$ROOT/deploy/local"

# First-class default: auto-bootstrap secret-free profile after healthy up.
# Set LOCAL_DOCKER_AUTO_PROFILE=0 to disable.
LOCAL_DOCKER_AUTO_PROFILE="${LOCAL_DOCKER_AUTO_PROFILE:-1}"
LOCAL_DOCKER_HEALTH_WAIT_SECS="${LOCAL_DOCKER_HEALTH_WAIT_SECS:-120}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker required" >&2
  exit 1
fi

compose=()

rebuild_compose() {
  compose=(docker compose -f "$COMPOSE_FILE")
  if [[ -f "$ENV_FILE" ]]; then
    compose+=(--env-file "$ENV_FILE")
  fi
  # Optional profiles: export LOCAL_COMPOSE_PROFILES=http,with-jenkins
  if [[ -n "${LOCAL_COMPOSE_PROFILES:-${COMPOSE_PROFILES:-}}" ]]; then
    IFS=',' read -ra _profiles <<<"${LOCAL_COMPOSE_PROFILES:-${COMPOSE_PROFILES}}"
    for p in "${_profiles[@]}"; do
      p="$(echo "$p" | tr -d ' ')"
      [[ -n "$p" ]] && compose+=(--profile "$p")
    done
  fi
}

rebuild_compose

# --- helpers -----------------------------------------------------------------

gen_lab_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  elif command -v od >/dev/null 2>&1; then
    od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
  else
    echo "openssl (or od) required to generate lab admin token" >&2
    exit 1
  fi
}

# True if ENV_FILE has a non-empty JENKINS_MCP_ADMIN_TOKEN assignment.
env_has_admin_token() {
  [[ -f "$ENV_FILE" ]] || return 1
  # shellcheck disable=SC2016
  grep -Eq '^[[:space:]]*JENKINS_MCP_ADMIN_TOKEN=[^[:space:]#]+' "$ENV_FILE"
}

# True if TOKEN_FILE path is set (env or .env); value not inspected.
env_has_admin_token_file() {
  [[ -n "${JENKINS_MCP_ADMIN_TOKEN_FILE:-}" ]] && return 0
  [[ -f "$ENV_FILE" ]] || return 1
  grep -Eq '^[[:space:]]*JENKINS_MCP_ADMIN_TOKEN_FILE=[^[:space:]#]+' "$ENV_FILE"
}

# Ensure deploy/local/.env exists with a lab-safe admin token when missing.
# Never prints the token value. Never bakes secrets into image layers.
ensure_env_file() {
  local created=0
  if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$ENV_EXAMPLE" ]]; then
      cp "$ENV_EXAMPLE" "$ENV_FILE"
    else
      touch "$ENV_FILE"
    fi
    created=1
  fi

  if env_has_admin_token || env_has_admin_token_file; then
    if [[ "$created" -eq 1 ]]; then
      echo "local-docker: created $ENV_FILE (token already present or TOKEN_FILE set)" >&2
    fi
    rebuild_compose
    return 0
  fi

  local tok
  tok="$(gen_lab_token)"
  # Drop empty / commented placeholder assignments so compose sees one real value.
  if grep -qE '^[[:space:]]*#?[[:space:]]*JENKINS_MCP_ADMIN_TOKEN=' "$ENV_FILE" 2>/dev/null; then
    local tmp
    tmp="$(mktemp)"
    grep -vE '^[[:space:]]*#?[[:space:]]*JENKINS_MCP_ADMIN_TOKEN=' "$ENV_FILE" >"$tmp" || true
    mv "$tmp" "$ENV_FILE"
  fi
  {
    echo ""
    echo "# Auto-generated lab token ($(date -u +%Y-%m-%dT%H:%MZ)); never commit .env"
    echo "JENKINS_MCP_ADMIN_TOKEN=${tok}"
  } >>"$ENV_FILE"
  # One-line hint only — token lives in .env, never commit.
  echo "local-docker: generated JENKINS_MCP_ADMIN_TOKEN into $ENV_FILE (lab-safe; never commit)" >&2
  rebuild_compose
}

# Read a single KEY=value from .env without sourcing (no expand, no log of secrets).
env_get() {
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  local line
  line="$(grep -E "^[[:space:]]*${key}=" "$ENV_FILE" 2>/dev/null | tail -n1 || true)"
  [[ -n "$line" ]] || return 0
  line="${line#*=}"
  # strip optional surrounding quotes
  if [[ "$line" == \"*\" && "$line" == *\" ]]; then
    line="${line:1:${#line}-2}"
  elif [[ "$line" == \'*\' && "$line" == *\' ]]; then
    line="${line:1:${#line}-2}"
  fi
  printf '%s' "$line"
}

admin_host_port() {
  local p
  p="${LOCAL_ADMIN_HOST_PORT:-}"
  if [[ -z "$p" ]]; then
    p="$(env_get LOCAL_ADMIN_HOST_PORT)"
  fi
  echo "${p:-8787}"
}

compose_profiles_csv() {
  echo "${LOCAL_COMPOSE_PROFILES:-${COMPOSE_PROFILES:-}}"
}

profiles_include() {
  local want="$1"
  local csv
  csv="$(compose_profiles_csv)"
  [[ -n "$csv" ]] || return 1
  IFS=',' read -ra _ps <<<"$csv"
  local p
  for p in "${_ps[@]}"; do
    p="$(echo "$p" | tr -d ' ')"
    [[ "$p" == "$want" ]] && return 0
  done
  return 1
}

# Default Jenkins URL for profile bootstrap.
# with-jenkins → compose DNS; else residual host-mapped placeholder for offline doctor.
resolve_jenkins_url() {
  if [[ -n "${JENKINS_URL:-}" ]]; then
    echo "${JENKINS_URL}"
    return
  fi
  local from_env
  from_env="$(env_get JENKINS_URL)"
  if [[ -n "$from_env" ]]; then
    echo "$from_env"
    return
  fi
  if profiles_include with-jenkins; then
    echo "http://jenkins:8080"
    return
  fi
  # Residual: admin-only stack; offline doctor tolerates unreachable URL.
  echo "http://127.0.0.1:18080"
}

resolve_profile_id() {
  if [[ -n "${JENKINS_MCP_PROFILE:-}" ]]; then
    echo "${JENKINS_MCP_PROFILE}"
    return
  fi
  local from_env
  from_env="$(env_get JENKINS_MCP_PROFILE)"
  echo "${from_env:-corp}"
}

auto_profile_enabled() {
  case "${LOCAL_DOCKER_AUTO_PROFILE}" in
    0|false|FALSE|no|NO|off|OFF) return 1 ;;
    *) return 0 ;;
  esac
}

wait_admin_healthy() {
  local port max i token url
  port="$(admin_host_port)"
  max="${LOCAL_DOCKER_HEALTH_WAIT_SECS}"
  token="$(env_get JENKINS_MCP_ADMIN_TOKEN)"
  url="http://127.0.0.1:${port}/admin/v1/health"
  i=0
  echo "local-docker: waiting for admin health on ${url} (up to ${max}s)…" >&2
  while ((i < max)); do
    if [[ -n "$token" ]]; then
      if curl -fsS -H "Authorization: Bearer ${token}" "$url" >/dev/null 2>&1; then
        echo "local-docker: admin healthy" >&2
        return 0
      fi
    else
      if curl -fsS "$url" >/dev/null 2>&1; then
        echo "local-docker: admin healthy" >&2
        return 0
      fi
    fi
    sleep 2
    i=$((i + 2))
  done
  echo "local-docker: warning: admin not healthy after ${max}s (check: $0 logs / $0 status)" >&2
  return 1
}

profile_exists_on_volume() {
  local pid="$1"
  local out
  # Prefer entrypoint ready JSON when image supports it; fall back to list.
  if out="$("${compose[@]}" run --rm --no-deps mcp ready 2>/dev/null)"; then
    if echo "$out" | grep -q '"profile"[[:space:]]*:[[:space:]]*true'; then
      # ready checks JENKINS_MCP_PROFILE / arg; ensure id matches when possible
      if echo "$out" | grep -q "\"profileId\"[[:space:]]*:[[:space:]]*\"${pid}\""; then
        return 0
      fi
      # profile true for default id
      return 0
    fi
    return 1
  fi
  out="$("${compose[@]}" run --rm --no-deps mcp profile list 2>/dev/null || true)"
  echo "$out" | awk '{print $1}' | grep -qx "$pid"
}

run_init_profile() {
  local pid="${1:-$(resolve_profile_id)}"
  local url="${2:-$(resolve_jenkins_url)}"
  # Prefer image init (idempotent). Fall back to profile add + list.
  if "${compose[@]}" run --rm --no-deps \
    -e "JENKINS_MCP_PROFILE=${pid}" \
    -e "JENKINS_URL=${url}" \
    mcp init "${pid}" "${url}"; then
    return 0
  fi
  # Older image residual: direct CLI
  "${compose[@]}" run --rm --no-deps mcp profile add "${pid}" --url "${url}" --display-name "docker-lab-${pid}" || true
  "${compose[@]}" run --rm --no-deps mcp profile list
  echo "Profile '${pid}' ready on docker volume (url=${url}). Login/token still host or lab residual."
}

maybe_auto_init_profile() {
  auto_profile_enabled || {
    echo "local-docker: AUTO_PROFILE disabled (LOCAL_DOCKER_AUTO_PROFILE=${LOCAL_DOCKER_AUTO_PROFILE})" >&2
    return 0
  }
  local pid url
  pid="$(resolve_profile_id)"
  url="$(resolve_jenkins_url)"
  if profile_exists_on_volume "$pid"; then
    echo "local-docker: profile '${pid}' already present on volume; skip auto-init" >&2
    return 0
  fi
  echo "local-docker: auto-init profile '${pid}' url=${url} (LOCAL_DOCKER_AUTO_PROFILE=1; set 0 to disable)" >&2
  run_init_profile "$pid" "$url"
}

print_status() {
  local port token health_code ready_json tmp
  port="$(admin_host_port)"
  token="$(env_get JENKINS_MCP_ADMIN_TOKEN)"
  tmp="$(mktemp)"

  echo "=== compose ps ==="
  "${compose[@]}" ps || true
  echo

  echo "=== admin health (secret-free body) ==="
  health_code="000"
  if [[ -n "$token" ]]; then
    health_code="$(curl -sS -o "$tmp" -w '%{http_code}' \
      -H "Authorization: Bearer ${token}" \
      "http://127.0.0.1:${port}/admin/v1/health" 2>/dev/null || echo "000")"
  else
    health_code="$(curl -sS -o "$tmp" -w '%{http_code}' \
      "http://127.0.0.1:${port}/admin/v1/health" 2>/dev/null || echo "000")"
  fi
  if [[ -s "$tmp" ]]; then
    cat "$tmp"
    echo
  fi
  rm -f "$tmp"
  echo "(http_code=${health_code})"
  echo

  echo "=== ready (container volume) ==="
  ready_json="$("${compose[@]}" run --rm --no-deps mcp ready 2>/dev/null || echo '{"admin":false,"profile":false,"profileId":"","error":"ready unavailable"}')"
  echo "${ready_json}"
  echo

  echo "=== profiles (secret-free) ==="
  "${compose[@]}" run --rm --no-deps mcp profile list 2>/dev/null || echo "(profile list failed — is the image built?)"
  echo

  echo "=== summary ==="
  echo "Admin UI:  http://127.0.0.1:${port}"
  echo "Env file:  ${ENV_FILE}"
  echo "Profiles:  $(compose_profiles_csv | sed 's/^$/(none)/')"
  echo "AUTO_PROFILE=${LOCAL_DOCKER_AUTO_PROFILE}  JENKINS_URL=$(resolve_jenkins_url)"
  echo "Token:     present in .env (value never printed). Use: source ${ENV_FILE}  # for curl Bearer"
}

# --- commands ----------------------------------------------------------------

cmd="${1:-}"
shift || true

case "$cmd" in
  build)
    "${compose[@]}" build "$@"
    ;;
  up)
    ensure_env_file
    "${compose[@]}" up -d --build "$@"
    echo "Admin BFF (if healthy): http://127.0.0.1:$(admin_host_port)"
    # Wait + optional first-class profile bootstrap (default on).
    if wait_admin_healthy; then
      maybe_auto_init_profile || echo "local-docker: warning: auto profile init failed (retry: $0 init-profile)" >&2
    else
      echo "local-docker: skip auto-profile until healthy (retry: $0 init-profile / $0 status)" >&2
    fi
    echo "Status: $0 status"
    echo "Tear down: $0 down"
    echo "Disable auto-profile: LOCAL_DOCKER_AUTO_PROFILE=0 $0 up"
    ;;
  down)
    "${compose[@]}" down -v --remove-orphans "$@"
    ;;
  ps)
    "${compose[@]}" ps "$@"
    ;;
  status)
    ensure_env_file
    print_status
    ;;
  logs)
    "${compose[@]}" logs -f mcp "$@"
    ;;
  doctor)
    "${compose[@]}" run --rm --no-deps mcp doctor --offline "$@"
    ;;
  init-profile)
    # Bootstrap a secret-free profile on the config volume for support labs.
    # Usage: init-profile [id] [jenkins-url]
    ensure_env_file
    pid="${1:-$(resolve_profile_id)}"
    url="${2:-$(resolve_jenkins_url)}"
    shift 2 2>/dev/null || true
    run_init_profile "$pid" "$url"
    ;;
  ready)
    # Host-side ready: run container ready command (JSON, secret-free).
    ensure_env_file
    "${compose[@]}" run --rm --no-deps \
      -e "JENKINS_MCP_PROFILE=$(resolve_profile_id)" \
      mcp ready
    ;;
  version)
    "${compose[@]}" run --rm --no-deps mcp version
    ;;
  shell)
    "${compose[@]}" run --rm --no-deps mcp shell
    ;;
  run)
    # scripts/local-docker.sh run -- policy show-effective --profile corp
    if [[ "${1:-}" == "--" ]]; then shift; fi
    "${compose[@]}" run --rm --no-deps mcp "$@"
    ;;
  smoke)
    exec bash "$ROOT/scripts/local-docker-smoke.sh" "$@"
    ;;
  config)
    "${compose[@]}" config "$@"
    ;;
  *)
    cat <<EOF
Usage: $0 <command>

Commands:
  build     Build jenkins-mcp-local image
  up        Ensure .env + token, build + start stack, wait healthy, auto-profile
  down      Stop and remove volumes
  ps        Compose status
  status    Compose ps + admin health + ready JSON + profile list (secret-free)
  logs      Follow mcp service logs
  doctor    Offline doctor one-shot
  init-profile [id] [jenkins-url]  Bootstrap secret-free profile on volume
  ready     Print ready JSON from volume (secret-free)
  version   version --json
  shell     Interactive bash in image
  run -- <jenkins-mcp args...>
  config    Validate compose file

Profiles (LOCAL_COMPOSE_PROFILES or COMPOSE_PROFILES):
  http           also start Streamable HTTP on 127.0.0.1:8081
  with-jenkins   also start disposable Jenkins lab on 127.0.0.1:18080
                 (auto-profile defaults JENKINS_URL=http://jenkins:8080)

First-class env:
  LOCAL_DOCKER_AUTO_PROFILE=1   (default) auto profile add after healthy up
  LOCAL_DOCKER_AUTO_PROFILE=0   disable auto-profile
  JENKINS_URL                   profile bootstrap URL override
  JENKINS_MCP_PROFILE           profile id (default corp)
  JENKINS_MCP_ADMIN_TOKEN_FILE  mount path residual (operators who avoid env inspect)

Env file: $ENV_FILE (auto-created from .env.example; token auto-generated)
Compose:  $COMPOSE_FILE
EOF
    exit 1
    ;;
esac
