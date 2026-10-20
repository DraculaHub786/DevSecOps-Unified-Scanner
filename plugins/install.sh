#!/usr/bin/env bash
# Pinned scanner vendor script for Linux / macOS CI runners
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

echo "🛡️ Installing pinned scanner binaries for $OS-$ARCH to $PLUGIN_DIR..."

# 1. Gitleaks v8.18.4
GITLEAKS_VER="8.18.4"
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_${OS}_${ARCH}.tar.gz" | tar -xz -C "$PLUGIN_DIR" gitleaks

# 2. OSV-Scanner v1.8.2
OSV_VER="1.8.2"
curl -sSL -o "$PLUGIN_DIR/osv-scanner" "https://github.com/google/osv-scanner/releases/download/v${OSV_VER}/osv-scanner_${OS}_${ARCH}"
chmod +x "$PLUGIN_DIR/osv-scanner"

# 3. Trivy v0.51.0
TRIVY_VER="0.51.0"
curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_${OS}-${ARCH}.tar.gz" | tar -xz -C "$PLUGIN_DIR" trivy

echo "✅ All scanner binaries successfully pinned."
