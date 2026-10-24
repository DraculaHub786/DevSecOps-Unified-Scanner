#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "🛡️  Running Sentinel E2E Full Gate Suite"
echo "=========================================================="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BIN="${BIN:-./bin/sentinel}"
if [[ ! -x "$BIN" ]]; then
    echo "⚙️ Building sentinel binary..."
    go build -o "$BIN" ./cmd/sentinel
fi

echo "--- 1. Engine Diagnostics Check ---"
"$BIN" doctor

echo "--- 2. End-to-End Test Suite Execution ---"
go test -v ./cmd/sentinel -run TestE2E

echo "--- 3. Direct CLI Scan against Safe Fixture ---"
SAFE_REPORT="$("$BIN" scan testdata/safe-app --format=terminal)"
if echo "$SAFE_REPORT" | grep -q "No security flaws or secrets identified"; then
    echo "✅ Safe fixture verified clean (0 findings)"
else
    echo "❌ Safe fixture produced unexpected findings:"
    echo "$SAFE_REPORT"
    exit 1
fi

echo "--- 4. Detection Quality Benchmark Check (bench-detect) ---"
"$BIN" bench-detect

echo "=========================================================="
echo "🎉 E2E Full Gate Suite Passed Successfully!"
echo "=========================================================="
