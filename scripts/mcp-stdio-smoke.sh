#!/usr/bin/env bash
# FND-006 Wave 25 + Wave 33: offline MCP stdio binary host-lifecycle smoke
# (no Cursor product binary, no Docker).
#
# Builds (or reuses) jenkins-mcp, then runs scripts/mcpstdiosmoke which:
#   1. Starts httptest fixture Jenkins (whoAmI + /api/json jobs + hanging job path)
#   2. Spawns the real binary over stdio via mcp.CommandTransport
#   3. Host-lifecycle matrix: Initialize, ListTools RO, CallTool success /
#      invalid / unknown / cancel mid-flight, ListTools again, shutdown + canary scrub
#
# Residual: real Cursor host / product-binary stdio CI remains open
# (see docs/packaging.md). Offline host-lifecycle matrix is Done*.
#
# Usage:
#   scripts/mcp-stdio-smoke.sh
#   BIN=bin/jenkins-mcp scripts/mcp-stdio-smoke.sh
#   make stdio-smoke
#
# Exit: 0 on pass; non-zero on failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

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

if [[ ! -x "${BIN}" && -f "${BIN}" ]]; then
  chmod +x "${BIN}" || true
fi
if [[ ! -f "${BIN}" ]]; then
  echo "FAIL: binary not found: ${BIN}" >&2
  exit 1
fi

echo "using binary: ${BIN}"
echo "== go run ./scripts/mcpstdiosmoke =="
export BIN
go run ./scripts/mcpstdiosmoke
echo "mcp-stdio-smoke complete (offline host-lifecycle Done*; Cursor product binary still residual)"
