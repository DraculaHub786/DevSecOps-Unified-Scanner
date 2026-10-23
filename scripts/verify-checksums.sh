#!/usr/bin/env bash
# Verify consistency of scanner versions and SHA-256 checksums
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECKSUMS_FILE="$ROOT_DIR/plugins/checksums.txt"
VERSIONS_FILE="$ROOT_DIR/plugins/versions.env"

echo "🔍 Validating scanner checksum integrity in $CHECKSUMS_FILE against $VERSIONS_FILE..."

if [ ! -f "$VERSIONS_FILE" ]; then
    echo "❌ Missing versions.env: $VERSIONS_FILE"
    exit 1
fi

if [ ! -f "$CHECKSUMS_FILE" ]; then
    echo "❌ Missing checksums.txt: $CHECKSUMS_FILE"
    exit 1
fi

. "$VERSIONS_FILE"

ERRORS=0

# 1. Format check: verify all non-comment non-empty lines are valid sha256 checksum lines
while IFS= read -r line || [ -n "$line" ]; do
    trimmed="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -z "$trimmed" ] || [[ "$trimmed" =~ ^# ]]; then
        continue
    fi

    if [[ ! "$trimmed" =~ ^[0-9a-fA-F]{64}[[:space:]]+[^[:space:]]+$ ]]; then
        echo "❌ Invalid checksum line format: '$line'"
        ERRORS=$((ERRORS + 1))
    fi
done < "$CHECKSUMS_FILE"

# 2. Check that each pinned tool version has checksum entries
check_file_checksum() {
    local filename="$1"
    local count
    count="$(grep -E "^[0-9a-fA-F]{64}[[:space:]]+${filename}$" "$CHECKSUMS_FILE" | wc -l)"
    if [ "$count" -eq 0 ]; then
        echo "❌ Missing checksum entry for: $filename"
        ERRORS=$((ERRORS + 1))
    else
        echo "  ✓ $filename verified in checksums.txt"
    fi
}

echo "Checking pinned Gitleaks (v${GITLEAKS_VERSION})..."
check_file_checksum "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
check_file_checksum "gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"
check_file_checksum "gitleaks_${GITLEAKS_VERSION}_darwin_x64.tar.gz"
check_file_checksum "gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz"
check_file_checksum "gitleaks_${GITLEAKS_VERSION}_windows_x64.zip"

echo "Checking pinned OSV-Scanner (v${OSV_VERSION})..."
check_file_checksum "osv-scanner_linux_amd64"
check_file_checksum "osv-scanner_linux_arm64"
check_file_checksum "osv-scanner_darwin_amd64"
check_file_checksum "osv-scanner_darwin_arm64"
check_file_checksum "osv-scanner_windows_amd64.exe"

echo "Checking pinned Trivy (v${TRIVY_VERSION})..."
check_file_checksum "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
check_file_checksum "trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"
check_file_checksum "trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz"
check_file_checksum "trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz"
check_file_checksum "trivy_${TRIVY_VERSION}_windows-64bit.zip"

echo "Checking pinned Nuclei (v${NUCLEI_VERSION})..."
check_file_checksum "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
check_file_checksum "nuclei_${NUCLEI_VERSION}_linux_arm64.zip"
check_file_checksum "nuclei_${NUCLEI_VERSION}_macOS_amd64.zip"
check_file_checksum "nuclei_${NUCLEI_VERSION}_macOS_arm64.zip"
check_file_checksum "nuclei_${NUCLEI_VERSION}_windows_amd64.zip"

if [ "$ERRORS" -gt 0 ]; then
    echo "❌ Checksum verification failed with $ERRORS error(s)."
    exit 1
fi

echo "✅ All pinned tools and supported platforms have verified checksum entries."
exit 0
