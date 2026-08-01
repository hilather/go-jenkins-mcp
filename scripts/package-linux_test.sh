#!/usr/bin/env bash
# PKG-001 offline package smoke (no rpmbuild/dpkg required).
#
# Builds or reuses a binary, runs package-linux.sh into a temp dist with
# SKIP_DEB=1 SKIP_RPM=1, and asserts:
#   - tarball exists
#   - SHA256SUMS present and lists the tarball
#   - BUILD_INFO has version/commit and no secret material
#   - package tree has no .env / key material canaries
#
# Usage:
#   scripts/package-linux_test.sh
#   BIN=bin/jenkins-mcp scripts/package-linux_test.sh
#   make package-smoke
#
# Exit: 0 on pass; non-zero on assertion failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PATH="${HOME}/.local/go/bin:/usr/local/go/bin:${PATH:-}"

SCRIPT="$ROOT/scripts/package-linux.sh"
if [[ ! -x "$SCRIPT" ]]; then
  chmod +x "$SCRIPT" || true
fi
if [[ ! -f "$SCRIPT" ]]; then
  echo "FAIL: missing $SCRIPT" >&2
  exit 1
fi

VERSION="${PACKAGE_SMOKE_VERSION:-0.0.0-pkg-smoke}"
COMMIT="${PACKAGE_SMOKE_COMMIT:-deadbeef}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="${BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x "$ROOT/bin/jenkins-mcp" ]]; then
    BIN="$ROOT/bin/jenkins-mcp"
  fi
fi

if [[ -z "$BIN" || ! -f "$BIN" ]]; then
  # Tiny dummy binary keeps smoke fast and independent of full go build when
  # package-smoke is not preceded by make build (direct script invocation).
  BIN="$WORK/jenkins-mcp"
  cat >"$BIN" <<'EOF'
#!/bin/sh
echo "jenkins-mcp package-smoke dummy"
EOF
  chmod 0755 "$BIN"
  echo "using dummy binary: $BIN"
else
  echo "using binary: $BIN"
fi

DIST="$WORK/dist"
mkdir -p "$DIST"

# Portable offline path: never require dpkg-deb / rpmbuild.
export SKIP_DEB=1
export SKIP_RPM=1
export PACKAGE_ARCH="${PACKAGE_ARCH:-amd64}"
export GO_VERSION="${GO_VERSION:-go-test}"
export BUILDTIME="${BUILDTIME:-2026-01-01T00:00:00Z}"

echo "== package-linux.sh (SKIP_DEB=1 SKIP_RPM=1) =="
"$SCRIPT" "$BIN" "$DIST" "$VERSION" "$COMMIT"

fail=0
assert() {
  local msg="$1"
  shift
  if "$@"; then
    echo "PASS: $msg"
  else
    echo "FAIL: $msg" >&2
    fail=1
  fi
}

# --- Artifact presence ---
TARBALL="$DIST/jenkins-mcp_${VERSION}_linux_${PACKAGE_ARCH}.tar.gz"
assert "tarball exists" test -f "$TARBALL"
assert "SHA256SUMS exists" test -f "$DIST/SHA256SUMS"
assert "BUILD_INFO exists" test -f "$DIST/BUILD_INFO"

# --- SHA256SUMS lists tarball ---
if [[ -f "$DIST/SHA256SUMS" ]]; then
  assert "SHA256SUMS lists tarball basename" \
    grep -q "jenkins-mcp_${VERSION}_linux_${PACKAGE_ARCH}.tar.gz" "$DIST/SHA256SUMS"
fi

# --- BUILD_INFO metadata (no secrets) ---
if [[ -f "$DIST/BUILD_INFO" ]]; then
  assert "BUILD_INFO has version=" grep -q "^version=${VERSION}$" "$DIST/BUILD_INFO"
  assert "BUILD_INFO has commit=" grep -q "^commit=${COMMIT}$" "$DIST/BUILD_INFO"
  assert "BUILD_INFO has arch=" grep -q "^arch=linux/" "$DIST/BUILD_INFO"
  # UI-008: package records admin SPA presence without failing when dist missing.
  assert "BUILD_INFO has admin_ui=" grep -qE '^admin_ui=(present|missing)$' "$DIST/BUILD_INFO"
  assert "BUILD_INFO has admin_ui_path=" grep -q '^admin_ui_path=/usr/share/jenkins-mcp/admin-ui$' "$DIST/BUILD_INFO"
  # Secret canaries in BUILD_INFO text
  if grep -Eiq '(password|api[_-]?token|authorization:|private[_-]?key|BEGIN (RSA |OPENSSH )?PRIVATE|client_secret)' "$DIST/BUILD_INFO"; then
    echo "FAIL: BUILD_INFO contains secret-like material" >&2
    fail=1
  else
    echo "PASS: BUILD_INFO has no secret-like material"
  fi
fi

# --- Tarball contents layout + secret canaries ---
EXTRACT="$WORK/extract"
mkdir -p "$EXTRACT"
if [[ -f "$TARBALL" ]]; then
  tar -C "$EXTRACT" -xzf "$TARBALL"
  assert "tarball has usr/bin/jenkins-mcp" test -f "$EXTRACT/usr/bin/jenkins-mcp"
  assert "tarball has BUILD_INFO under doc" test -f "$EXTRACT/usr/share/doc/jenkins-mcp/BUILD_INFO"

  # Canary: package must not ship .env with secrets or key material.
  # Search staged tree for forbidden names and content patterns.
  forbidden_names=0
  while IFS= read -r -d '' f; do
    base="$(basename -- "$f")"
    case "$base" in
      .env|.env.*|*.pem|*.key|id_rsa|id_ed25519|*.p12|*.pfx)
        echo "FAIL: forbidden package member: $f" >&2
        forbidden_names=1
        ;;
    esac
  done < <(find "$EXTRACT" -type f -print0 2>/dev/null)

  if [[ "$forbidden_names" -eq 0 ]]; then
    echo "PASS: no forbidden .env/key filenames in package"
  else
    fail=1
  fi

  # Content canary on staged docs only (not the Go binary: it embeds redaction
  # regexes and example strings like BEGIN PRIVATE KEY / client_secret=).
  # Look for literal PEM blocks or assignment-style secrets in text docs.
  DOC_ROOT="$EXTRACT/usr/share/doc/jenkins-mcp"
  if [[ -d "$DOC_ROOT" ]]; then
    if grep -REiq '-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----' "$DOC_ROOT" 2>/dev/null \
      || grep -REq '(^|[[:space:]])(client_secret|API_TOKEN)=[^[:space:]]+' "$DOC_ROOT" 2>/dev/null; then
      echo "FAIL: package docs match secret-like content canary" >&2
      fail=1
    else
      echo "PASS: package docs have no secret-like content canary"
    fi
  fi

  # Explicit canary: ensure a planted .env would have been caught by name scan
  # (package must not ship .env — already covered by forbidden_names above).
fi

# --- Negative: missing binary must fail ---
if "$SCRIPT" "$WORK/does-not-exist" "$WORK/dist-missing" "0.0.0" "x" 2>/dev/null; then
  echo "FAIL: expected missing-binary to fail" >&2
  fail=1
else
  echo "PASS: missing binary fails closed"
fi

# --- Negative: secret-looking path must fail ---
FAKE_SECRET="$WORK/.env"
echo "API_TOKEN=super-secret-value-not-for-package" >"$FAKE_SECRET"
if "$SCRIPT" "$FAKE_SECRET" "$WORK/dist-secret" "0.0.0" "x" 2>/dev/null; then
  echo "FAIL: expected secret-looking path to be refused" >&2
  fail=1
else
  echo "PASS: secret-looking path refused"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "package-linux_test: FAILED" >&2
  exit 1
fi
echo "package-linux_test: OK (version=${VERSION} commit=${COMMIT})"
