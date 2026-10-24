#!/usr/bin/env bash
# =========================================================================
# Sentinel Multi-Platform Release Artifact Builder
# Builds binaries for Linux, macOS, and Windows (amd64 + arm64) & generates checksums
# =========================================================================
set -euo pipefail

VERSION="${1:-1.0.1}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE=$(date -u +'%Y-%m-%d')
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

echo "🔨 Building Sentinel release artifacts for version ${VERSION}..."

for target in "${TARGETS[@]}"; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  EXT=""
  if [ "${GOOS}" = "windows" ]; then
    EXT=".exe"
  fi

  ARCHIVE_NAME="sentinel_${VERSION}_${GOOS}_${GOARCH}"
  STAGE_DIR="${DIST_DIR}/${ARCHIVE_NAME}"
  mkdir -p "${STAGE_DIR}"

  echo "  📦 Building ${GOOS}/${GOARCH}..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath -ldflags="${LDFLAGS}" -o "${STAGE_DIR}/sentinel${EXT}" "${ROOT_DIR}/cmd/sentinel"
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath -ldflags="-s -w" -o "${STAGE_DIR}/sentinel-agent${EXT}" "${ROOT_DIR}/cmd/sentinel-agent"

  cp "${ROOT_DIR}/README.md" "${ROOT_DIR}/LICENSE" "${ROOT_DIR}/SECURITY.md" "${STAGE_DIR}/"

  cd "${DIST_DIR}"
  if [ "${GOOS}" = "windows" ]; then
    if command -v zip >/dev/null 2>&1; then
      zip -q -r "${ARCHIVE_NAME}.zip" "${ARCHIVE_NAME}"
    elif command -v python >/dev/null 2>&1; then
      python -m zipfile -c "${ARCHIVE_NAME}.zip" "${ARCHIVE_NAME}"
    elif command -v powershell.exe >/dev/null 2>&1; then
      powershell.exe -NoProfile -Command "Compress-Archive -Path '${ARCHIVE_NAME}/*' -DestinationPath '${ARCHIVE_NAME}.zip' -Force"
    else
      tar -czf "${ARCHIVE_NAME}.tar.gz" "${ARCHIVE_NAME}"
    fi
  else
    tar -czf "${ARCHIVE_NAME}.tar.gz" "${ARCHIVE_NAME}"
  fi
  rm -rf "${STAGE_DIR}"
done

echo "🔐 Generating release checksums.txt..."
cd "${DIST_DIR}"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum sentinel_* > checksums.txt
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 sentinel_* > checksums.txt
fi

echo "✅ Release build complete! Artifacts in ${DIST_DIR}:"
ls -la "${DIST_DIR}"
