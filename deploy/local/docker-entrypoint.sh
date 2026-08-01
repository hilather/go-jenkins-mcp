#!/bin/bash
# Support entrypoint for jenkins-mcp local Docker image (first-class admin SPA + bootstrap).
# Secrets: never pass token values as argv; use env var *names* or files (mode 0600).
set -euo pipefail

PROFILE="${JENKINS_MCP_PROFILE:-corp}"
ADMIN_ADDR="${JENKINS_MCP_ADMIN_ADDR:-0.0.0.0:8787}"
HTTP_ADDR="${JENKINS_MCP_HTTP_ADDR:-0.0.0.0:8081}"
ADMIN_ROLE="${JENKINS_MCP_ADMIN_ROLE:-viewer}"
READ_ONLY="${JENKINS_MCP_READ_ONLY:-true}"
# Profile bootstrap URL (with-jenkins compose DNS or residual placeholder).
JENKINS_URL="${JENKINS_URL:-http://127.0.0.1:18080}"

# Optional shared secret for admin HTTP (value in env, name passed to CLI).
# Residual: JENKINS_MCP_ADMIN_TOKEN_FILE for operators who avoid env in inspect.
admin_token_args=()
if [[ -n "${JENKINS_MCP_ADMIN_TOKEN:-}" ]]; then
  export JENKINS_MCP_ADMIN_TOKEN
  admin_token_args+=(--admin-token-env=JENKINS_MCP_ADMIN_TOKEN --require-token)
elif [[ -n "${JENKINS_MCP_ADMIN_TOKEN_FILE:-}" ]]; then
  admin_token_args+=(--admin-token-file="${JENKINS_MCP_ADMIN_TOKEN_FILE}" --require-token)
fi

http_token_args=()
if [[ -n "${JENKINS_MCP_HTTP_TOKEN:-}" ]]; then
  export JENKINS_MCP_HTTP_TOKEN
  http_token_args+=(--http-token-env=JENKINS_MCP_HTTP_TOKEN --http-require-token)
elif [[ -n "${JENKINS_MCP_HTTP_TOKEN_FILE:-}" ]]; then
  http_token_args+=(--http-token-file="${JENKINS_MCP_HTTP_TOKEN_FILE}" --http-require-token)
fi

ro_args=()
if [[ "${READ_ONLY}" == "true" || "${READ_ONLY}" == "1" || "${READ_ONLY}" == "yes" ]]; then
  ro_args+=(--read-only)
fi

# profile_exists: true if id is first column of `profile list` (not "(no profiles)").
profile_exists() {
  local id="$1"
  local line
  while IFS= read -r line; do
    [[ -z "$line" || "$line" == "(no profiles)" ]] && continue
    local first="${line%%$'\t'*}"
    first="${first%% *}"
    if [[ "$first" == "$id" ]]; then
      return 0
    fi
  done < <(jenkins-mcp profile list 2>/dev/null || true)
  return 1
}

cmd="${1:-admin}"
shift || true

case "${cmd}" in
  admin|admin-serve)
    # Operator console BFF + SPA (baked at /usr/share/jenkins-mcp/admin-ui).
    # Bind 0.0.0.0 inside container; compose publishes 127.0.0.1 on host only.
    # Non-loopback bind requires --admin-allow-non-local and a token (fail closed).
    admin_extra=()
    if [[ "${ADMIN_ADDR}" == 0.0.0.0:* || "${ADMIN_ADDR}" == :* || "${ADMIN_ADDR}" == "[::]:"* ]]; then
      admin_extra+=(--admin-allow-non-local)
      if [[ ${#admin_token_args[@]} -eq 0 ]]; then
        echo "admin: non-loopback bind requires JENKINS_MCP_ADMIN_TOKEN or JENKINS_MCP_ADMIN_TOKEN_FILE" >&2
        exit 1
      fi
    fi
    # Explicit assets-dir when package tree has index.html (image SPA bake).
    if [[ -f /usr/share/jenkins-mcp/admin-ui/index.html ]]; then
      admin_extra+=(--assets-dir=/usr/share/jenkins-mcp/admin-ui)
      if [[ -f /usr/share/jenkins-mcp/admin-ui/UI_BUILD ]]; then
        echo "admin: serving packaged SPA ui_build=$(tr -d '\r\n' </usr/share/jenkins-mcp/admin-ui/UI_BUILD | head -c 128)" >&2
      else
        echo "admin: serving packaged SPA from /usr/share/jenkins-mcp/admin-ui" >&2
      fi
    else
      echo "admin: no packaged SPA at /usr/share/jenkins-mcp/admin-ui (embed/placeholder residual)" >&2
    fi
    exec jenkins-mcp admin serve \
      --addr "${ADMIN_ADDR}" \
      --profile "${PROFILE}" \
      --admin-role "${ADMIN_ROLE}" \
      "${admin_extra[@]}" \
      "${admin_token_args[@]}" \
      "$@"
    ;;
  serve-http|http)
    exec jenkins-mcp serve \
      --profile "${PROFILE}" \
      "${ro_args[@]}" \
      --http "${HTTP_ADDR}" \
      --http-allow-non-local \
      "${http_token_args[@]}" \
      "$@"
    ;;
  serve-stdio|stdio)
    exec jenkins-mcp serve \
      --profile "${PROFILE}" \
      --stdio \
      "${ro_args[@]}" \
      "$@"
    ;;
  init|bootstrap)
    # Idempotent secret-free profile bootstrap for first-class local Docker UX.
    pid="${1:-${PROFILE}}"
    url="${2:-${JENKINS_URL}}"
    if profile_exists "${pid}"; then
      echo "profile ${pid} already exists; skip" >&2
      exit 0
    fi
    jenkins-mcp profile add "${pid}" --url "${url}" --display-name "docker-lab-${pid}"
    echo "profile ${pid} created (url=${url}; secret-free)" >&2
    jenkins-mcp profile list
    ;;
  ready)
    # Secret-free readiness JSON for operators / scripts.
    pid="${1:-${PROFILE}}"
    admin_ready=false
    if [[ -n "${JENKINS_MCP_ADMIN_TOKEN:-}" ]]; then
      admin_ready=true
    elif [[ -n "${JENKINS_MCP_ADMIN_TOKEN_FILE:-}" && -f "${JENKINS_MCP_ADMIN_TOKEN_FILE}" ]]; then
      admin_ready=true
    fi
    profile_ready=false
    if profile_exists "${pid}"; then
      profile_ready=true
    fi
    printf '{"admin":%s,"profile":%s,"profileId":"%s"}\n' \
      "${admin_ready}" "${profile_ready}" "${pid}"
    ;;
  doctor)
    exec jenkins-mcp doctor --profile "${PROFILE}" "$@"
    ;;
  support-bundle)
    exec jenkins-mcp support-bundle --profile "${PROFILE}" "$@"
    ;;
  version)
    exec jenkins-mcp version --json
    ;;
  shell|bash)
    exec /bin/bash "$@"
    ;;
  jenkins-mcp)
    exec jenkins-mcp "$@"
    ;;
  *)
    exec jenkins-mcp "${cmd}" "$@"
    ;;
esac
