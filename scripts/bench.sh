#!/usr/bin/env bash
# =========================================================================
# Sentinel Scanner Benchmark Suite
# Measures cold scan, warm scan, and single-file incremental performance
# =========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET="${1:-${ROOT_DIR}/testdata/vulnerable-app}"
OUTPUT_DIR="${ROOT_DIR}/dist/bench"

mkdir -p "${OUTPUT_DIR}"

SENTINEL="${ROOT_DIR}/bin/sentinel"
if [ ! -f "${SENTINEL}" ]; then
  echo "Building sentinel binary..."
  go build -o "${SENTINEL}" "${ROOT_DIR}/cmd/sentinel"
fi

echo "=========================================================="
echo "🚀 Running Sentinel Benchmark Suite"
echo "Target: ${TARGET}"
echo "Date:   $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "=========================================================="

# 1. Cold Scan Benchmark (clean cache)
echo "❄️  Running Cold Scan..."
rm -rf "${TARGET}/.sentinel"
COLD_START=$(date +%s%N)
"${SENTINEL}" scan "${TARGET}" --format json --out "${OUTPUT_DIR}/cold.json"
COLD_END=$(date +%s%N)
COLD_DURATION_MS=$(( (COLD_END - COLD_START) / 1000000 ))
echo "   Cold Scan Time: ${COLD_DURATION_MS} ms"

# 2. Warm Scan Benchmark
echo "🔥 Running Warm Scan..."
WARM_START=$(date +%s%N)
"${SENTINEL}" scan "${TARGET}" --format json --out "${OUTPUT_DIR}/warm.json"
WARM_END=$(date +%s%N)
WARM_DURATION_MS=$(( (WARM_END - WARM_START) / 1000000 ))
echo "   Warm Scan Time: ${WARM_DURATION_MS} ms"

# 3. Incremental Single-File Scan Benchmark
echo "⚡ Running Incremental Single-File Scan..."
INC_START=$(date +%s%N)
"${SENTINEL}" scan "${TARGET}" --changed-only --format json --out "${OUTPUT_DIR}/inc.json"
INC_END=$(date +%s%N)
INC_DURATION_MS=$(( (INC_END - INC_START) / 1000000 ))
echo "   Incremental Scan Time: ${INC_DURATION_MS} ms"

# 4. Compare and Deduplication Verification
echo ""
PYTHON_BIN="python3"
if ! "${PYTHON_BIN}" --version &>/dev/null; then
  PYTHON_BIN="python"
fi
"${PYTHON_BIN}" "${SCRIPT_DIR}/compare.py" "${OUTPUT_DIR}/cold.json"

