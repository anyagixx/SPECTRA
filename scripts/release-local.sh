#!/usr/bin/env bash
#
# Build local SPECTRA release archives into ./dist.
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
fatal() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist"
VERSION="$(sed -n 's/^const Version = "\(.*\)"/\1/p' "${PROJECT_DIR}/internal/buildinfo/version.go")"

[[ -n "$VERSION" ]] || fatal "Cannot detect version from internal/buildinfo/version.go"
command -v go >/dev/null 2>&1 || fatal "Go is required to build release archives."

build_archive() {
  local goos="$1"
  local goarch="$2"
  local name="spectra-v${VERSION}-${goos}-${goarch}"
  local stage="${DIST_DIR}/.stage/${name}"

  info "Building ${name}..."
  rm -rf "$stage"
  mkdir -p "$stage"

  (
    cd "$PROJECT_DIR"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "${stage}/spectra-server" ./cmd/spectra-server
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "${stage}/spectra-client" ./cmd/spectra-client
  )

  cp -R "${PROJECT_DIR}/configs" "$stage/"
  cp -R "${PROJECT_DIR}/deployments" "$stage/"
  cp -R "${PROJECT_DIR}/scripts" "$stage/"
  cp "${PROJECT_DIR}/README.md" "$stage/"
  cp "${PROJECT_DIR}/HOW_TO_RU.md" "$stage/"
  cp "${PROJECT_DIR}/CHANGELOG.md" "$stage/"
  cp "${PROJECT_DIR}/go.mod" "$stage/"
  cp "${PROJECT_DIR}/go.sum" "$stage/"
  find "${stage}/scripts" -type f -name '*.sh' -exec chmod +x {} +

  (
    cd "${DIST_DIR}/.stage"
    tar -czf "${DIST_DIR}/${name}.tar.gz" "$name"
  )
  ok "Created dist/${name}.tar.gz"
}

build_source_archive() {
  local name="spectra-v${VERSION}-source"
  info "Creating source archive..."
  (
    cd "$PROJECT_DIR"
    tar \
      --exclude='.git' \
      --exclude='dist' \
      --exclude='spectra-server' \
      --exclude='spectra-client' \
      --exclude='certs' \
      --exclude='*.pem' \
      -czf "${DIST_DIR}/${name}.tar.gz" \
      --transform "s,^\.,${name}," \
      .
  )
  ok "Created dist/${name}.tar.gz"
}

mkdir -p "$DIST_DIR"
rm -rf "${DIST_DIR:?}/"*

build_archive linux amd64
build_archive linux arm64
build_source_archive
rm -rf "${DIST_DIR}/.stage"

echo ""
ok "Local release v${VERSION} is ready in ${DIST_DIR}"
ls -lh "$DIST_DIR"
