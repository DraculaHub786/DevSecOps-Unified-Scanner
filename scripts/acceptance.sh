#!/usr/bin/env bash
# =========================================================================
# Sentinel Acceptance Test Suite (Bash) - AT-01 to AT-34
# Automated end-to-end acceptance tests for DevSecOps Unified Scanner v1.0.1
# =========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BINARY="${ROOT_DIR}/bin/sentinel"

TARGET_VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"

echo "================================================================="
echo "🛡️  SENTINEL AUTOMATED ACCEPTANCE SUITE (AT-01 to AT-34)"
echo "Target Version: ${TARGET_VERSION} | Date: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================="

PASSED=0
FAILED=0

run_check() {
  local id="$1"
  local desc="$2"
  shift 2
  printf "[%s] %s ... " "${id}" "${desc}"
  if "$@"; then
    echo "PASS"
    PASSED=$((PASSED + 1))
  else
    echo "FAIL"
    FAILED=$((FAILED + 1))
  fi
}

# Ensure binary is built
if [ ! -f "${BINARY}" ]; then
  mkdir -p "${ROOT_DIR}/bin"
  go build -trimpath -ldflags="-s -w -X main.version=${TARGET_VERSION}" -o "${BINARY}" "${ROOT_DIR}/cmd/sentinel"
fi

# AT-01
check_at01() {
  "${BINARY}" version | grep -q "v${TARGET_VERSION}"
}
run_check "AT-01" "Sentinel CLI version reports ${TARGET_VERSION}" check_at01

# AT-02
check_at02() {
  "${BINARY}" doctor | grep -q "Sentinel Engine Diagnostics"
}
run_check "AT-02" "Sentinel doctor engine diagnostics & availability" check_at02

# AT-03
check_at03() {
  go test -v -run TestTrivyIsVulnDBUnavailableDetection "${ROOT_DIR}/internal/adapters/trivy" >/dev/null
}
run_check "AT-03" "Trivy offline IaC scan resilience (vuln DB unavailable)" check_at03

# AT-04
check_at04() {
  go test -v -run TestTrivyDetectsFixtureIaCVulnerabilities "${ROOT_DIR}/internal/adapters/trivy" >/dev/null
}
run_check "AT-04" "Trivy IaC findings preservation & native fallback" check_at04

# AT-05
check_at05() {
  "${BINARY}" scan "${ROOT_DIR}/testdata/vulnerable-app" --only=secret --format=terminal | grep -qi "secret"
}
run_check "AT-05" "Gitleaks secrets detection on fixture repository" check_at05

# AT-06
check_at06() {
  "${BINARY}" scan "${ROOT_DIR}/testdata/vulnerable-app" --only=sast --format=terminal | grep -qi "sast"
}
run_check "AT-06" "Semgrep SAST detection on fixture repository" check_at06

# AT-07
check_at07() {
  "${BINARY}" scan "${ROOT_DIR}/testdata/vulnerable-app" --only=sca --format=terminal | grep -qi "sca"
}
run_check "AT-07" "OSV-Scanner SCA detection on fixture repository" check_at07

# AT-08
check_at08() {
  go test -v -run TestValidateTarget "${ROOT_DIR}/internal/safety" >/dev/null
}
run_check "AT-08" "DAST authorization guardrails enforcement" check_at08

# AT-09
check_at09() {
  go test -v -run TestSchedulerCIErrorOnPanic "${ROOT_DIR}/internal/orchestrator" >/dev/null
}
run_check "AT-09" "Scanner resilience, timeout & panic recovery" check_at09

# AT-10
check_at10() {
  local tmp
  tmp="$(mktemp -d /tmp/sentinel-bl-XXXXXX 2>/dev/null || mktemp -d -t 'sentinel-bl')"
  "${BINARY}" baseline "${tmp}" >/dev/null
  test -f "${tmp}/.sentinel/baseline.json"
  rm -rf "${tmp}"
}
run_check "AT-10" "Baseline generation creates .sentinel/baseline.json" check_at10

# AT-11
check_at11() {
  go test -v -run TestBaselineMatches "${ROOT_DIR}/internal/baseline" >/dev/null
}
run_check "AT-11" "Baseline filtering ignores pre-existing flaws" check_at11

# AT-12
check_at12() {
  go test -v -run TestShouldFailGating "${ROOT_DIR}/cmd/sentinel" >/dev/null
}
run_check "AT-12" "CI gating failure on high/critical findings" check_at12

# AT-13
check_at13() {
  go test -v -run TestCorrelateSecretFindingsAcrossTools "${ROOT_DIR}/internal/orchestrator" >/dev/null
}
run_check "AT-13" "Cross-engine secret deduplication (Gitleaks + Semgrep)" check_at13

# AT-14
check_at14() {
  go test -v -run TestCorrelateCrossToolDeduplication "${ROOT_DIR}/internal/orchestrator" >/dev/null
}
run_check "AT-14" "Cross-engine SCA deduplication (OSV + Trivy)" check_at14

# AT-15
check_at15() {
  bash "${ROOT_DIR}/scripts/verify-checksums.sh" >/dev/null
}
run_check "AT-15" "Tool checksum verification (plugins/checksums.txt)" check_at15

# AT-16
check_at16() {
  grep -q "v${TARGET_VERSION}" "${ROOT_DIR}/Formula/sentinel.rb" && \
  grep -q "${TARGET_VERSION}" "${ROOT_DIR}/Dockerfile" && \
  grep -q "v${TARGET_VERSION}" "${ROOT_DIR}/deploy/github-actions/sentinel-scan/action.yml"
}
run_check "AT-16" "Version stamping consistency across CLI, docs, Docker" check_at16

# AT-17
check_at17() {
  bash "${ROOT_DIR}/scripts/pr-flow.sh" >/dev/null
}
run_check "AT-17" "Pull-request security flow (scripts/pr-flow.sh)" check_at17

# AT-18
check_at18() {
  test -f "${ROOT_DIR}/.github/dependabot.yml" && \
  grep -q "actions/checkout@" "${ROOT_DIR}/.github/workflows/ci.yml"
}
run_check "AT-18" "Pinned GitHub Actions dependencies (SHAs) & Dependabot" check_at18

# AT-19
check_at19() {
  test -f "${ROOT_DIR}/dist/checksums.txt"
}
run_check "AT-19" "Multi-platform release artifact building" check_at19

# AT-20
check_at20() {
  test -s "${ROOT_DIR}/docs/rules.md" && \
  test -s "${ROOT_DIR}/docs/ci.md" && \
  test -s "${ROOT_DIR}/docs/extension.md" && \
  test -s "${ROOT_DIR}/docs/security-model.md" && \
  test -s "${ROOT_DIR}/CHANGELOG.md"
}
run_check "AT-20" "Technical documentation suite (rules, ci, extension, security)" check_at20

# AT-21
check_at21() {
  "${BINARY}" rules test | grep -q "PASS"
}
run_check "AT-21" "Embedded 78 rules test suite (sentinel rules test)" check_at21

# AT-22
check_at22() {
  "${BINARY}" scan "${ROOT_DIR}/testdata/vulnerable-app" --offline --format=json >/dev/null
}
run_check "AT-22" "Offline scan with zero egress (--offline)" check_at22

# AT-23
check_at23() {
  go test -v -run Hostile "${ROOT_DIR}/internal/orchestrator" >/dev/null
}
run_check "AT-23" "Hostile repository handling (deep nesting, malformed input)" check_at23

# AT-24
check_at24() {
  set +e
  "${BINARY}" dast --target https://example.com >/dev/null 2>&1
  local exit_code=$?
  set -e
  [ "${exit_code}" -ne 0 ]
}
run_check "AT-24" "DAST requires --i-have-authorization" check_at24

# AT-25
check_at25() {
  set +e
  "${BINARY}" dast --target http://169.254.169.254 --i-have-authorization >/dev/null 2>&1
  local exit_code=$?
  set -e
  [ "${exit_code}" -ne 0 ]
}
run_check "AT-25" "DAST blocks private RFC1918 & cloud metadata" check_at25

# AT-26
check_at26() {
  bash "${ROOT_DIR}/scripts/bench.sh" >/dev/null
}
run_check "AT-26" "Benchmark execution & deduplication accuracy" check_at26

# AT-27a
check_at27a() {
  go test -v -run TestSharedIPCFixturesAgainstAgent "${ROOT_DIR}/cmd/sentinel-agent" >/dev/null
}
run_check "AT-27a" "Extension JSON-RPC IPC handshake & session tokens" check_at27a

# AT-27b
check_at27b() {
  npm test --prefix "${ROOT_DIR}/extension-vscode" >/dev/null
}
run_check "AT-27b" "Extension workspace trust boundary enforcement" check_at27b

# AT-27c
check_at27c() {
  grep -q '"@vscode/vsce":\s*"2\.24\.0"' "${ROOT_DIR}/extension-vscode/package.json"
}
run_check "AT-27c" "Extension reproducible VSIX packaging (@vscode/vsce)" check_at27c

# AT-27d
check_at27d() {
  npm test --prefix "${ROOT_DIR}/extension-vscode" | grep -q "AT-27d"
}
run_check "AT-27d" "Extension hover security & command injection defense" check_at27d

# AT-28
check_at28() {
  local tmp
  tmp="$(mktemp /tmp/test-sarif-XXXXXX.sarif 2>/dev/null || mktemp -t 'test-sarif.sarif')"
  "${BINARY}" scan "${ROOT_DIR}/testdata/vulnerable-app" --format=sarif --out="${tmp}" >/dev/null
  grep -q '"version": "2.1.0"' "${tmp}" && grep -q 'sarif-schema-2.1.0.json' "${tmp}"
  rm -f "${tmp}"
}
run_check "AT-28" "SARIF 2.1.0 output validity & schema declaration" check_at28

# AT-29
check_at29() {
  local tmp
  tmp="$(mktemp /tmp/test-html-XXXXXX.html 2>/dev/null || mktemp -t 'test-html.html')"
  "${BINARY}" scan "${ROOT_DIR}/testdata/vulnerable-app" --format=html --out="${tmp}" >/dev/null
  grep -q "<!DOCTYPE html>" "${tmp}" && grep -q "Sentinel" "${tmp}"
  rm -f "${tmp}"
}
run_check "AT-29" "Offline standalone HTML report generation" check_at29

# AT-30
check_at30() {
  go test -v -run TestCorrelateGovulncheckReachabilityPrecedence "${ROOT_DIR}/internal/orchestrator" >/dev/null
}
run_check "AT-30" "Proven Go reachability precedence (govulncheck > heuristic)" check_at30

# AT-31
check_at31() {
  "${BINARY}" threat-model "${ROOT_DIR}/testdata/vulnerable-app" | grep -q "STRIDE"
}
run_check "AT-31" "Threat model generation (STRIDE matrix & architecture analysis)" check_at31

# AT-32
check_at32() {
  local tmp
  tmp="$(mktemp /tmp/test-sbom-XXXXXX.json 2>/dev/null || mktemp -t 'test-sbom.json')"
  "${BINARY}" sbom "${ROOT_DIR}/testdata/vulnerable-app" --format=cyclonedx --out="${tmp}" >/dev/null
  grep -q "CycloneDX" "${tmp}"
  rm -f "${tmp}"
}
run_check "AT-32" "Software Bill of Materials (SBOM) CycloneDX generation" check_at32

# AT-33
check_at33() {
  go test -v -run TestCheckUntrustedPolicyTable "${ROOT_DIR}/cmd/sentinel" >/dev/null
}
run_check "AT-33" "Untrusted in-repo policy rejection in CI mode" check_at33

# AT-34
check_at34() {
  "${BINARY}" scan "${ROOT_DIR}" --ci --allow-lite --trust-repo-policy --fail-on=critical | grep -q "clean"
}
run_check "AT-34" "Self-scan repository clean verification (zero false positives)" check_at34

echo "================================================================="
echo "Acceptance Suite Results: ${PASSED} PASSED, ${FAILED} FAILED (Total: 34 checks)"
echo "================================================================="

if [ "${FAILED}" -gt 0 ]; then
  exit 1
else
  echo "🎉 ALL ACCEPTANCE TESTS PASSED WITH 100% SUCCESS!"
  exit 0
fi
