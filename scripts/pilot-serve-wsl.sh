#!/usr/bin/env bash
# WSL pilot helper: unlock Secret Service, then run jenkins-mcp serve (read-only stdio).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${JENKINS_MCP_BIN:-$ROOT/bin/jenkins-mcp}"
PROFILE="${JENKINS_MCP_PROFILE:-local}"

if [[ ! -x "$BIN" ]]; then
  echo "jenkins-mcp binary not found: $BIN" >&2
  exit 1
fi

if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
  if [[ -S "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus" ]]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/bus"
  else
    eval "$(dbus-launch --sh-syntax)"
  fi
fi

if command -v gnome-keyring-daemon >/dev/null 2>&1; then
  printf '\n' | gnome-keyring-daemon --unlock >/dev/null 2>&1 || true
  gnome-keyring-daemon --start --components=secrets >/dev/null 2>&1 || true
fi

export JENKINS_MCP_READ_ONLY=true
exec "$BIN" serve \
  --profile "$PROFILE" \
  --read-only \
  --stdio
