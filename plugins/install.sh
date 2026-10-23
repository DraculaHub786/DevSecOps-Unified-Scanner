#!/usr/bin/env bash
# Pinned scanner vendor script with SHA-256 integrity verification
set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$PLUGIN_DIR/versions.env"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
    ARCH_ALT="x64"
    TRIVY_ARCH="64bit"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
    ARCH_ALT="arm64"
    TRIVY_ARCH="ARM64"
fi

echo "🛡️ Installing pinned scanner binaries for $OS-$ARCH to $PLUGIN_DIR..."

fetch_and_verify() {
    local url="$1"
    local dest="$2"
    local filename="$3"

    echo "⬇️ Downloading $filename..."
    curl -fsSL -o "$dest" "$url"

    local expected_hash
    expected_hash="$(grep -F "  $filename" "$PLUGIN_DIR/checksums.txt" | awk '{print $1}' || true)"

    if [ -n "$expected_hash" ]; then
        echo "🔍 Verifying SHA-256 for $filename..."
        local actual_hash
        if command -v sha256sum >/dev/null 2>&1; then
            actual_hash="$(sha256sum "$dest" | awk '{print $1}')"
        else
            actual_hash="$(shasum -a 256 "$dest" | awk '{print $1}')"
        fi

        if [ "$actual_hash" != "$expected_hash" ]; then
            echo "❌ Checksum verification failed for $filename!"
            echo "Expected: $expected_hash"
            echo "Got:      $actual_hash"
            rm -f "$dest"
            exit 1
        fi
        echo "✅ Checksum verified."
    else
        echo "❌ No checksum entry for $filename; refusing to install an unverified binary."
        rm -f "$dest"
        exit 1
    fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# 1. Gitleaks
GITLEAKS_FILE="gitleaks_${GITLEAKS_VERSION}_${OS}_${ARCH_ALT}.tar.gz"
GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GITLEAKS_FILE}"
fetch_and_verify "$GITLEAKS_URL" "$TMP_DIR/$GITLEAKS_FILE" "$GITLEAKS_FILE"
tar -xzf "$TMP_DIR/$GITLEAKS_FILE" -C "$PLUGIN_DIR" gitleaks
chmod +x "$PLUGIN_DIR/gitleaks"

# 2. OSV-Scanner
OSV_FILE="osv-scanner_${OS}_${ARCH}"
OSV_URL="https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/${OSV_FILE}"
fetch_and_verify "$OSV_URL" "$PLUGIN_DIR/osv-scanner" "$OSV_FILE"
chmod +x "$PLUGIN_DIR/osv-scanner"

# 3. Trivy
if [ "$OS" = "darwin" ]; then
    TRIVY_FILE="trivy_${TRIVY_VERSION}_macOS-${TRIVY_ARCH}.tar.gz"
else
    TRIVY_FILE="trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"
fi
TRIVY_URL="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_FILE}"
fetch_and_verify "$TRIVY_URL" "$TMP_DIR/$TRIVY_FILE" "$TRIVY_FILE"
tar -xzf "$TMP_DIR/$TRIVY_FILE" -C "$PLUGIN_DIR" trivy
chmod +x "$PLUGIN_DIR/trivy"

# 4. Nuclei
if [ "$OS" = "darwin" ]; then
    NUCLEI_FILE="nuclei_${NUCLEI_VERSION}_macOS_${ARCH}.zip"
else
    NUCLEI_FILE="nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip"
fi
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${NUCLEI_FILE}"
fetch_and_verify "$NUCLEI_URL" "$TMP_DIR/$NUCLEI_FILE" "$NUCLEI_FILE"
unzip -qo "$TMP_DIR/$NUCLEI_FILE" -d "$PLUGIN_DIR" nuclei || true
chmod +x "$PLUGIN_DIR/nuclei" 2>/dev/null || true

# 5. Semgrep (via pipx or pip3 if present)
if command -v pipx >/dev/null 2>&1; then
    echo "📦 Installing pinned Semgrep via pipx..."
    pipx install --force "semgrep==${SEMGREP_VERSION}" || true
elif command -v pip3 >/dev/null 2>&1; then
    pip3 install --quiet "semgrep==${SEMGREP_VERSION}" || true
fi

# 6. govulncheck (Go vulnerability reachability engine)
if command -v go >/dev/null 2>&1; then
    echo "📦 Installing pinned govulncheck v${GOVULNCHECK_VERSION}..."
    GOBIN="$PLUGIN_DIR" go install "golang.org/x/vuln/cmd/govulncheck@v${GOVULNCHECK_VERSION}" || true
fi

echo "🎉 All scanner binaries successfully installed and checksum-verified in $PLUGIN_DIR"


