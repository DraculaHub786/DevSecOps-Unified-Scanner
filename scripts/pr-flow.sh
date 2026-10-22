#!/usr/bin/env bash
# Sentinel PR Baseline and Gating Verification Flow
set -euo pipefail

echo "🛡️ Sentinel PR Flow Verification"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${REPO_ROOT}/bin/sentinel"

# Compile Sentinel binary if not present
if [ ! -f "${BIN_PATH}" ]; then
  echo "Building Sentinel binary..."
  mkdir -p "${REPO_ROOT}/bin"
  go build -o "${BIN_PATH}" "${REPO_ROOT}/cmd/sentinel"
fi

TEST_SANDBOX="$(mktemp -d /tmp/sentinel-pr-test-XXXXXX 2>/dev/null || mktemp -d -t 'sentinel-pr-test')"
trap 'rm -rf "${TEST_SANDBOX}"' EXIT

cd "${TEST_SANDBOX}"
git init -b main
git config user.email "ci@sentinel.local"
git config user.name "Sentinel CI"

# Initialize starter project
echo 'console.log("Safe application code");' > app.js
git add app.js
git commit -m "feat: initial commit"

echo "1. Generating baseline on main..."
"${BIN_PATH}" baseline .

if [ ! -f ".sentinel/baseline.json" ]; then
  echo "❌ Baseline file .sentinel/baseline.json was not created"
  exit 1
fi

git add .sentinel/baseline.json
git commit -m "chore: commit baseline"

echo "2. Simulating PR introducing a new high-severity finding..."
git checkout -b feature/vulnerable-change
cat << 'EOF' > app.js
const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEEXAMPLEEXAMPLE";
console.log("Compromised key:", AWS_SECRET_KEY);
EOF

git add app.js

echo "3. Running CI gating with baseline..."
set +e
"${BIN_PATH}" scan . --ci --offline --baseline --fail-on=high
CI_EXIT_CODE=$?
set -e

if [ "${CI_EXIT_CODE}" -ne 1 ]; then
  echo "❌ Expected Sentinel CI gate to exit 1 on new finding, got ${CI_EXIT_CODE}"
  exit 1
fi
echo "✅ Sentinel successfully blocked PR with exit code 1"

echo "4. Reverting vulnerability..."
git checkout main -- app.js
git add app.js

echo "5. Verifying clean state passes CI gate..."
"${BIN_PATH}" scan . --ci --offline --baseline --fail-on=high
CLEAN_EXIT_CODE=$?

if [ "${CLEAN_EXIT_CODE}" -ne 0 ]; then
  echo "❌ Expected clean repo to exit 0, got ${CLEAN_EXIT_CODE}"
  exit 1
fi

echo "✅ PR baseline gating verification successfully passed!"
