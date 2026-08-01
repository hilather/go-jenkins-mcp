#!/usr/bin/env bash
# Package Tier-1 Linux artifacts for Rocky Linux and Ubuntu (PKG-001 / FND-002).
#
# Produces:
#   - Portable tarball: jenkins-mcp_<version>_linux_<arch>.tar.gz
#   - DEB when dpkg-deb is available
#   - RPM when rpmbuild is available (else documented skip)
#   - SHA256SUMS + BUILD_INFO under dist/
#
# Usage:
#   package-linux.sh <binary> <dist_dir> <version> [commit]
#
# Environment (optional):
#   PACKAGE_ARCH  — amd64|arm64 (default: host uname -m mapped)
#   GO_VERSION    — recorded in BUILD_INFO
#   BUILDTIME     — ISO-8601 UTC build time
#   SKIP_DEB=1    — skip DEB even if dpkg-deb exists
#   SKIP_RPM=1    — skip RPM even if rpmbuild exists
#
# Signing residual: this script never embeds private keys and never runs
# rpmsign / dpkg-sig / cosign. Signed releases are a release-pipeline step
# only (rpm --addsign / dpkg-sig / cosign). Offline smoke: make package-smoke.
# See docs/packaging.md § Code signing.
#
# Windows packages are out of scope (architecture §19 / ADR 0008).
set -euo pipefail

BINARY="${1:?binary path}"
DIST="${2:?dist dir}"
VERSION="${3:-dev}"
COMMIT="${4:-unknown}"
NAME="jenkins-mcp"

if [[ -n "${PACKAGE_ARCH:-}" ]]; then
  ARCH="$PACKAGE_ARCH"
else
  ARCH="$(uname -m)"
fi
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

if [[ ! -f "$BINARY" ]]; then
  echo "error: binary not found: $BINARY" >&2
  exit 1
fi
if [[ ! -r "$BINARY" ]]; then
  echo "error: binary not readable: $BINARY" >&2
  exit 1
fi
if [[ -d "$BINARY" ]]; then
  echo "error: binary path is a directory, not a file: $BINARY" >&2
  exit 1
fi

# Refuse packaging paths that look like credential/token material rather than
# a built binary (fail closed; operators should pass bin/jenkins-mcp).
_bin_base="$(basename -- "$BINARY")"
_bin_path_lc="$(printf '%s' "$BINARY" | tr '[:upper:]' '[:lower:]')"
case "$_bin_base" in
  .env|.env.*|*.pem|*.key|*.p12|*.pfx|id_rsa|id_ed25519|*.token)
    echo "error: refusing to package path that looks like secret material: $BINARY" >&2
    exit 1
    ;;
esac
case "$_bin_path_lc" in
  */.env|*/.env.*|*/secrets/*|*/credentials/*|*token*secret*|*/*api*token*)
    echo "error: refusing to package path that looks like secret material: $BINARY" >&2
    exit 1
    ;;
esac
# Basename containing only secret-ish names (not jenkins-mcp with token in path).
case "$_bin_base" in
  *secret*|*password*|*credential*)
    echo "error: refusing to package basename that looks like secret material: $BINARY" >&2
    exit 1
    ;;
esac

if [[ ! -x "$BINARY" ]]; then
  chmod +x "$BINARY" || true
fi

# Normalize version for package managers (strip leading v; empty → 0.0.0-dev).
PKG_VERSION="${VERSION#v}"
if [[ -z "$PKG_VERSION" || "$PKG_VERSION" == "unknown" ]]; then
  PKG_VERSION="0.0.0-dev"
fi
# Debian/RPM disallow some git describe characters; sanitize lightly.
DEB_VERSION="${PKG_VERSION//+/-}"
DEB_VERSION="${DEB_VERSION//\//-}"
# RPM Version: replace remaining problematic characters with dots.
RPM_VERSION="${DEB_VERSION//-/.}"

BUILDTIME="${BUILDTIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
if command -v go >/dev/null 2>&1; then
  GO_VERSION="${GO_VERSION:-$(go version 2>/dev/null | awk '{print $3}')}"
else
  GO_VERSION="${GO_VERSION:-unknown}"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$DIST"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Stage layout (tarball root and package payload share the same tree).
install -D -m 0755 "$BINARY" "$STAGE/usr/bin/$NAME"
mkdir -p "$STAGE/usr/share/doc/$NAME"
for f in README.md LICENSE NOTICE; do
  if [[ -f "$ROOT/$f" ]]; then
    install -D -m 0644 "$ROOT/$f" "$STAGE/usr/share/doc/$NAME/$f"
  fi
done
if [[ -f "$ROOT/docs/packaging.md" ]]; then
  install -D -m 0644 "$ROOT/docs/packaging.md" "$STAGE/usr/share/doc/$NAME/packaging.md"
fi

# UI-008: optional admin SPA assets (fresh install without npm on target).
# Build with: make admin-ui && make package  (does not fail package if missing).
ADMIN_UI_SRC="${ADMIN_UI_SRC:-$ROOT/web/admin/dist}"
ADMIN_UI_DST="usr/share/jenkins-mcp/admin-ui"
ADMIN_UI_STATUS="missing"
ADMIN_UI_BUILD=""
if [[ -d "$ADMIN_UI_SRC" && -f "$ADMIN_UI_SRC/index.html" ]]; then
  mkdir -p "$STAGE/$ADMIN_UI_DST"
  # Copy tree; never ship node_modules (dist is production build only).
  cp -a "$ADMIN_UI_SRC"/. "$STAGE/$ADMIN_UI_DST/"
  # Stamp package version into UI_BUILD when SPA did not write one.
  if [[ ! -f "$STAGE/$ADMIN_UI_DST/UI_BUILD" ]]; then
    printf '%s\n' "${VERSION}" >"$STAGE/$ADMIN_UI_DST/UI_BUILD"
  fi
  ADMIN_UI_STATUS="present"
  ADMIN_UI_BUILD="$(tr -d '\r\n' <"$STAGE/$ADMIN_UI_DST/UI_BUILD" | head -c 128 || true)"
  echo "admin-ui: packaged $ADMIN_UI_SRC → /$ADMIN_UI_DST (ui_build=${ADMIN_UI_BUILD})"
else
  echo "admin-ui: residual — $ADMIN_UI_SRC missing; package without SPA assets (run make admin-ui first for full console)"
fi

# Version / commit metadata (no secrets).
cat >"$STAGE/usr/share/doc/$NAME/BUILD_INFO" <<EOF
name=${NAME}
version=${VERSION}
package_version=${PKG_VERSION}
commit=${COMMIT}
arch=linux/${ARCH}
built=${BUILDTIME}
go=${GO_VERSION}
admin_ui=${ADMIN_UI_STATUS}
admin_ui_path=/${ADMIN_UI_DST}
admin_ui_build=${ADMIN_UI_BUILD}
# Install: binary at /usr/bin/${NAME} (or extract tarball under a prefix).
# Admin SPA: /usr/share/jenkins-mcp/admin-ui when admin_ui=present (UI-008).
# Config/data: XDG paths under \$XDG_CONFIG_HOME/${NAME}, \$XDG_DATA_HOME/${NAME}
# Credentials: OS Secret Service (Linux) — never in config files or Cursor args.
# Docs: docs/packaging.md
# Admin console: docs/admin/README.md (admin serve is default-off).
EOF

TARBALL="$DIST/${NAME}_${VERSION}_linux_${ARCH}.tar.gz"
tar -C "$STAGE" -czf "$TARBALL" .
echo "wrote $TARBALL"

# ---------------------------------------------------------------------------
# DEB (Ubuntu / Debian tools)
# ---------------------------------------------------------------------------
if [[ "${SKIP_DEB:-}" == "1" ]]; then
  echo "skip deb: SKIP_DEB=1"
elif command -v dpkg-deb >/dev/null 2>&1; then
  DEB_ROOT="$(mktemp -d)"
  mkdir -p "$DEB_ROOT/DEBIAN" "$DEB_ROOT/usr/bin" "$DEB_ROOT/usr/share/doc/$NAME"
  cp "$BINARY" "$DEB_ROOT/usr/bin/$NAME"
  chmod 0755 "$DEB_ROOT/usr/bin/$NAME"
  cp -a "$STAGE/usr/share/doc/$NAME/." "$DEB_ROOT/usr/share/doc/$NAME/" 2>/dev/null || true
  # UI-008: include admin SPA when staged.
  if [[ -d "$STAGE/usr/share/jenkins-mcp" ]]; then
    mkdir -p "$DEB_ROOT/usr/share"
    cp -a "$STAGE/usr/share/jenkins-mcp" "$DEB_ROOT/usr/share/"
  fi
  DEB_ARCH="$ARCH"
  cat >"$DEB_ROOT/DEBIAN/control" <<EOF
Package: $NAME
Version: ${DEB_VERSION}
Section: utils
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: go-jenkins-mcp maintainers <maintainers@localhost>
Description: Enterprise Jenkins MCP server (local stdio)
 Local per-user Jenkins MCP for Cursor on Tier-1 Linux (Rocky/Ubuntu).
 Credentials use OS Secret Service; profiles use XDG paths. No Windows package.
 Optional admin console assets under /usr/share/jenkins-mcp/admin-ui (UI-008).
Homepage: https://github.com/simonfxr/go-jenkins-mcp
Recommends: libsecret-1-0
EOF
  DEB_OUT="$DIST/${NAME}_${VERSION}_${DEB_ARCH}.deb"
  dpkg-deb --build "$DEB_ROOT" "$DEB_OUT"
  rm -rf "$DEB_ROOT"
  echo "wrote $DEB_OUT"
else
  echo "skip deb: dpkg-deb not installed (install dpkg-dev on Ubuntu to produce .deb)"
fi

# ---------------------------------------------------------------------------
# RPM (Rocky Linux / RHEL-family)
# ---------------------------------------------------------------------------
if [[ "${SKIP_RPM:-}" == "1" ]]; then
  echo "skip rpm: SKIP_RPM=1"
elif command -v rpmbuild >/dev/null 2>&1; then
  RPM_TOP="$(mktemp -d)"
  mkdir -p "$RPM_TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
  PAYLOAD_NAME="${NAME}-${RPM_VERSION}"
  PAYLOAD="$RPM_TOP/SOURCES/${PAYLOAD_NAME}"
  mkdir -p "$PAYLOAD"
  cp -a "$STAGE/." "$PAYLOAD/"
  tar -C "$RPM_TOP/SOURCES" -czf "$RPM_TOP/SOURCES/${PAYLOAD_NAME}.tar.gz" "${PAYLOAD_NAME}"

  RPM_ARCH="$ARCH"
  case "$ARCH" in
    amd64) RPM_ARCH=x86_64 ;;
    arm64) RPM_ARCH=aarch64 ;;
  esac

  # UI-008: optional admin-ui path in %files only when staged.
  RPM_ADMIN_UI_FILE=""
  if [[ -d "$STAGE/usr/share/jenkins-mcp/admin-ui" ]]; then
    RPM_ADMIN_UI_FILE="/usr/share/jenkins-mcp/admin-ui"
  fi

  SPEC="$RPM_TOP/SPECS/${NAME}.spec"
  cat >"$SPEC" <<EOF
Name:           ${NAME}
Version:        ${RPM_VERSION}
Release:        1%{?dist}
Summary:        Enterprise Jenkins MCP server (local stdio)
License:        MIT
URL:            https://github.com/simonfxr/go-jenkins-mcp
Source0:        %{name}-%{version}.tar.gz
BuildArch:      ${RPM_ARCH}

%description
Local per-user Jenkins MCP for Cursor on Tier-1 Linux (Rocky/Ubuntu).
Credentials use OS Secret Service; profiles use XDG paths.
Windows packages are out of scope. Optional FUSE (fuse3) is only needed for
future L2 mount inspection; native Go log paths work without FUSE.
Optional admin console assets under /usr/share/jenkins-mcp/admin-ui (UI-008).

%prep
%setup -q

%build
# Pre-built Go binary; nothing to compile in the SPEC.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a usr %{buildroot}/

%files
/usr/bin/%{name}
/usr/share/doc/%{name}
${RPM_ADMIN_UI_FILE}

%changelog
* $(date -u +'%a %b %d %Y') go-jenkins-mcp maintainers <maintainers@localhost> - ${RPM_VERSION}-1
- Automated package from commit ${COMMIT}
EOF

  if rpmbuild \
      --define "_topdir $RPM_TOP" \
      --define "_build_id_links none" \
      -bb "$SPEC"; then
    find "$RPM_TOP/RPMS" -type f -name '*.rpm' -exec cp -v {} "$DIST/" \;
    echo "wrote rpm under $DIST"
  else
    echo "warn: rpmbuild failed; tarball still available" >&2
  fi
  rm -rf "$RPM_TOP"
else
  cat <<'EOF'
skip rpm: rpmbuild not installed
  Rocky/RHEL: install rpm-build (and rpm-sign for signed releases)
  Documented skip is intentional for Ubuntu-only CI runners without rpm tools.
  Portable tarball above is the universal Tier-1 artifact.
EOF
fi

# ---------------------------------------------------------------------------
# Integrity: SHA256SUMS for package artifacts
# ---------------------------------------------------------------------------
(
  cd "$DIST"
  : >SHA256SUMS.tmp
  shopt -s nullglob
  for f in "${NAME}_"*.tar.gz "${NAME}_"*.deb "${NAME}-"*.rpm; do
    if [[ -f "$f" ]]; then
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$f" >>SHA256SUMS.tmp
      elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$f" >>SHA256SUMS.tmp
      fi
    fi
  done
  if [[ -s SHA256SUMS.tmp ]]; then
    # Deduplicate lines (re-runs may accumulate).
    sort -u SHA256SUMS.tmp >SHA256SUMS
    rm -f SHA256SUMS.tmp
    echo "wrote $DIST/SHA256SUMS"
  else
    rm -f SHA256SUMS.tmp
  fi
)

cp -f "$STAGE/usr/share/doc/$NAME/BUILD_INFO" "$DIST/BUILD_INFO" 2>/dev/null || true

ls -la "$DIST"
echo "package complete: version=${VERSION} commit=${COMMIT} arch=linux/${ARCH}"
echo "note: code signing is not performed here — see docs/packaging.md (signed releases placeholder)"
