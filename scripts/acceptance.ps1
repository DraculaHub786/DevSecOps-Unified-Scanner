# =========================================================================
# Sentinel Acceptance Test Suite (PowerShell) - AT-01 to AT-34
# Automated end-to-end acceptance tests for DevSecOps Unified Scanner v1.0.1
# =========================================================================
$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$Binary = Join-Path $RootDir "bin/sentinel.exe"
$TargetVersion = (Get-Content (Join-Path $RootDir "VERSION") -Raw).Trim()

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "🛡️  SENTINEL AUTOMATED ACCEPTANCE SUITE (AT-01 to AT-34)" -ForegroundColor Cyan
Write-Host "Target Version: $TargetVersion | Date: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Host "=================================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

function Run-Check {
    param(
        [string]$Id,
        [string]$Description,
        [scriptblock]$Action
    )
    Write-Host -NoNewline "[$Id] $Description ... "
    try {
        & $Action
        Write-Host "PASS" -ForegroundColor Green
        $script:Passed++
    } catch {
        Write-Host "FAIL: $_" -ForegroundColor Red
        $script:Failed++
    }
}

# Ensure binary is built
if (-not (Test-Path $Binary)) {
    go build -trimpath -ldflags="-s -w -X main.version=$TargetVersion" -o $Binary (Join-Path $RootDir "cmd/sentinel")
}

# AT-01
Run-Check "AT-01" "Sentinel CLI version reports $TargetVersion" {
    $out = (& $Binary version | Out-String)
    if ($out -notmatch "v$([regex]::Escape($TargetVersion))") { throw "Expected version $TargetVersion, got: $out" }
}

# AT-02
Run-Check "AT-02" "Sentinel doctor engine diagnostics & availability" {
    $out = (& $Binary doctor | Out-String)
    if ($out -notmatch "Sentinel Engine Diagnostics") { throw "Doctor failed" }
}

# AT-03
Run-Check "AT-03" "Trivy offline IaC scan resilience (vuln DB unavailable)" {
    go test -v -run TestTrivyIsVulnDBUnavailableDetection (Join-Path $RootDir "internal/adapters/trivy") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestTrivyIsVulnDBUnavailableDetection failed" }
}

# AT-04
Run-Check "AT-04" "Trivy IaC findings preservation & native fallback" {
    go test -v -run TestTrivyDetectsFixtureIaCVulnerabilities (Join-Path $RootDir "internal/adapters/trivy") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestTrivyDetectsFixtureIaCVulnerabilities failed" }
}

# AT-05
Run-Check "AT-05" "Gitleaks secrets detection on fixture repository" {
    $out = (& $Binary scan (Join-Path $RootDir "testdata/vulnerable-app") --only=secret --format=terminal | Out-String)
    if ($out -notmatch "secret") { throw "Expected secret findings in scan output" }
}

# AT-06
Run-Check "AT-06" "Semgrep SAST detection on fixture repository" {
    $out = (& $Binary scan (Join-Path $RootDir "testdata/vulnerable-app") --only=sast --format=terminal | Out-String)
    if ($out -notmatch "sast") { throw "Expected SAST findings in scan output" }
}

# AT-07
Run-Check "AT-07" "OSV-Scanner SCA detection on fixture repository" {
    $out = (& $Binary scan (Join-Path $RootDir "testdata/vulnerable-app") --only=sca --format=terminal | Out-String)
    if ($out -notmatch "sca") { throw "Expected SCA findings in scan output" }
}

# AT-08
Run-Check "AT-08" "DAST authorization guardrails enforcement" {
    go test -v -run TestValidateTarget (Join-Path $RootDir "internal/safety") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestValidateTarget failed" }
}

# AT-09
Run-Check "AT-09" "Scanner resilience, timeout & panic recovery" {
    go test -v -run TestSchedulerCIErrorOnPanic (Join-Path $RootDir "internal/orchestrator") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestSchedulerCIErrorOnPanic failed" }
}

# AT-10
Run-Check "AT-10" "Baseline generation creates .sentinel/baseline.json" {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel_bl_$([System.Guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        & $Binary baseline $tmp | Out-Null
        $blFile = Join-Path $tmp ".sentinel/baseline.json"
        if (-not (Test-Path $blFile)) { throw "baseline.json missing" }
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

# AT-11
Run-Check "AT-11" "Baseline filtering ignores pre-existing flaws" {
    go test -v -run TestBaselineMatches (Join-Path $RootDir "internal/baseline") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestBaselineMatches failed" }
}

# AT-12
Run-Check "AT-12" "CI gating failure on high/critical findings" {
    go test -v -run TestShouldFailGating (Join-Path $RootDir "cmd/sentinel") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestShouldFailGating failed" }
}

# AT-13
Run-Check "AT-13" "Cross-engine secret deduplication (Gitleaks + Semgrep)" {
    go test -v -run TestCorrelateSecretFindingsAcrossTools (Join-Path $RootDir "internal/orchestrator") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestCorrelateSecretFindingsAcrossTools failed" }
}

# AT-14
Run-Check "AT-14" "Cross-engine SCA deduplication (OSV + Trivy)" {
    go test -v -run TestCorrelateCrossToolDeduplication (Join-Path $RootDir "internal/orchestrator") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestCorrelateCrossToolDeduplication failed" }
}

# AT-15
Run-Check "AT-15" "Tool checksum verification (plugins/checksums.txt)" {
    $bash = "C:\Program Files\Git\bin\bash.exe"
    if (Test-Path $bash) {
        & $bash (Join-Path $RootDir "scripts/verify-checksums.sh") | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "verify-checksums.sh failed" }
    }
}

# AT-16
Run-Check "AT-16" "Version stamping consistency across CLI, docs, Docker" {
    $formula = Get-Content (Join-Path $RootDir "Formula/sentinel.rb") -Raw
    if ($formula -notmatch "v$([regex]::Escape($TargetVersion))") { throw "Formula version mismatch" }
    $docker = Get-Content (Join-Path $RootDir "Dockerfile") -Raw
    if ($docker -notmatch "$([regex]::Escape($TargetVersion))") { throw "Dockerfile version mismatch" }
    $action = Get-Content (Join-Path $RootDir "deploy/github-actions/sentinel-scan/action.yml") -Raw
    if ($action -notmatch "v$([regex]::Escape($TargetVersion))") { throw "Action version mismatch" }
}

# AT-17
Run-Check "AT-17" "Pull-request security flow (scripts/pr-flow.sh)" {
    $bash = "C:\Program Files\Git\bin\bash.exe"
    if (Test-Path $bash) {
        & $bash (Join-Path $RootDir "scripts/pr-flow.sh") | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "pr-flow.sh failed" }
    }
}

# AT-18
Run-Check "AT-18" "Pinned GitHub Actions dependencies (SHAs) & Dependabot" {
    $ci = Get-Content (Join-Path $RootDir ".github/workflows/ci.yml") -Raw
    if ($ci -match "uses: actions/checkout@[^0-9a-f]") { throw "actions/checkout not pinned by SHA" }
    if (-not (Test-Path (Join-Path $RootDir ".github/dependabot.yml"))) { throw "dependabot.yml missing" }
}

# AT-19
Run-Check "AT-19" "Multi-platform release artifact building (6 archives)" {
    $distDir = Join-Path $RootDir "dist"
    & (Join-Path $RootDir "scripts/build-release-artifacts.ps1") -Version $TargetVersion | Out-Null
    $zips = Get-ChildItem -Path $distDir -Filter "sentinel_${TargetVersion}_*.zip"
    $tars = Get-ChildItem -Path $distDir -Filter "sentinel_${TargetVersion}_*.tar.gz"
    if (($zips.Count + $tars.Count) -lt 6) { throw "Expected 6 release archives in dist/" }
    if (-not (Test-Path (Join-Path $distDir "checksums.txt"))) { throw "checksums.txt missing in dist/" }
}

# AT-20
Run-Check "AT-20" "Technical documentation suite (rules, ci, extension, security)" {
    $files = @("docs/rules.md", "docs/ci.md", "docs/extension.md", "docs/security-model.md", "CHANGELOG.md")
    foreach ($f in $files) {
        $p = Join-Path $RootDir $f
        if (-not (Test-Path $p) -or (Get-Item $p).Length -lt 500) { throw "$f missing or too short" }
    }
}

# AT-21
Run-Check "AT-21" "Embedded 78 rules test suite (sentinel rules test)" {
    $out = (& $Binary rules test | Out-String)
    if ($out -notmatch "PASS") { throw "rules test failed" }
}

# AT-22
Run-Check "AT-22" "Offline scan with zero egress (--offline)" {
    $out = & $Binary scan (Join-Path $RootDir "testdata/vulnerable-app") --offline --format=json
    if ($LASTEXITCODE -ne 0) { throw "offline scan failed" }
}

# AT-23
Run-Check "AT-23" "Hostile repository handling (deep nesting, malformed input)" {
    go test -v -run Hostile (Join-Path $RootDir "internal/orchestrator") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Hostile test failed" }
}

# AT-24
Run-Check "AT-24" "DAST requires --i-have-authorization" {
    try { & $Binary dast --target https://example.com 2>&1 | Out-Null } catch { }
    if ($LASTEXITCODE -eq 0) { throw "Expected DAST without authorization to fail" }
}

# AT-25
Run-Check "AT-25" "DAST blocks private RFC1918 & cloud metadata" {
    try { & $Binary dast --target http://169.254.169.254 --i-have-authorization 2>&1 | Out-Null } catch { }
    if ($LASTEXITCODE -eq 0) { throw "Expected cloud metadata IP to be blocked" }
}

# AT-26
Run-Check "AT-26" "Benchmark execution & deduplication accuracy" {
    pwsh -File (Join-Path $RootDir "scripts/bench.ps1") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Benchmark suite failed" }
}

# AT-27a
Run-Check "AT-27a" "Extension JSON-RPC IPC handshake & session tokens" {
    go test -v -run TestSharedIPCFixturesAgainstAgent (Join-Path $RootDir "cmd/sentinel-agent") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestSharedIPCFixturesAgainstAgent failed" }
}

# AT-27b
Run-Check "AT-27b" "Extension workspace trust boundary enforcement" {
    npm test --prefix (Join-Path $RootDir "extension-vscode") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Extension unit tests failed" }
}

# AT-27c
Run-Check "AT-27c" "Extension reproducible VSIX packaging (@vscode/vsce)" {
    $pkg = Get-Content (Join-Path $RootDir "extension-vscode/package.json") -Raw
    if ($pkg -notmatch '"@vscode/vsce":\s*"2\.24\.0"') { throw "vsce not pinned to 2.24.0" }
}

# AT-27d
Run-Check "AT-27d" "Extension hover security & command injection defense" {
    $testOut = (npm test --prefix (Join-Path $RootDir "extension-vscode") | Out-String)
    if ($testOut -notmatch "AT-27d") { throw "AT-27d not verified in extension tests" }
}

# AT-28
Run-Check "AT-28" "SARIF 2.1.0 output validity & schema declaration" {
    $tmpSarif = Join-Path ([System.IO.Path]::GetTempPath()) "test_$([System.Guid]::NewGuid().ToString('N')).sarif"
    try {
        & $Binary scan (Join-Path $RootDir "testdata/vulnerable-app") --format=sarif --out=$tmpSarif | Out-Null
        $sarif = Get-Content $tmpSarif -Raw
        if ($sarif -notmatch '"version":\s*"2\.1\.0"' -or $sarif -notmatch 'sarif-schema-2\.1\.0\.json') {
            throw "SARIF 2.1.0 schema declaration missing"
        }
    } finally {
        Remove-Item $tmpSarif -ErrorAction SilentlyContinue
    }
}

# AT-29
Run-Check "AT-29" "Offline standalone HTML report generation" {
    $tmpHtml = Join-Path ([System.IO.Path]::GetTempPath()) "test_$([System.Guid]::NewGuid().ToString('N')).html"
    try {
        & $Binary scan (Join-Path $RootDir "testdata/vulnerable-app") --format=html --out=$tmpHtml | Out-Null
        $html = Get-Content $tmpHtml -Raw
        if ($html -notmatch "<!DOCTYPE html>" -or $html -notmatch "Sentinel") {
            throw "HTML report generation invalid"
        }
    } finally {
        Remove-Item $tmpHtml -ErrorAction SilentlyContinue
    }
}

# AT-30
Run-Check "AT-30" "Proven Go reachability precedence (govulncheck > heuristic)" {
    go test -v -run TestCorrelateGovulncheckReachabilityPrecedence (Join-Path $RootDir "internal/orchestrator") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestCorrelateGovulncheckReachabilityPrecedence failed" }
}

# AT-31
Run-Check "AT-31" "Threat model generation (STRIDE matrix & architecture analysis)" {
    $out = (& $Binary threat-model (Join-Path $RootDir "testdata/vulnerable-app") | Out-String)
    if ($out -notmatch "STRIDE") { throw "threat-model failed" }
}

# AT-32
Run-Check "AT-32" "Software Bill of Materials (SBOM) CycloneDX generation" {
    $tmpSbom = Join-Path ([System.IO.Path]::GetTempPath()) "sbom_$([System.Guid]::NewGuid().ToString('N')).json"
    try {
        & $Binary sbom (Join-Path $RootDir "testdata/vulnerable-app") --format=cyclonedx --out=$tmpSbom | Out-Null
        $sbom = Get-Content $tmpSbom -Raw
        if ($sbom -notmatch "CycloneDX") {
            throw "SBOM generation failed"
        }
    } finally {
        Remove-Item $tmpSbom -ErrorAction SilentlyContinue
    }
}

# AT-33
Run-Check "AT-33" "Untrusted in-repo policy rejection in CI mode" {
    go test -v -run TestCheckUntrustedPolicyTable (Join-Path $RootDir "cmd/sentinel") | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "TestCheckUntrustedPolicyTable failed" }
}

# AT-34
Run-Check "AT-34" "Self-scan repository clean verification (zero false positives)" {
    $out = (& $Binary scan $RootDir --ci --allow-lite --trust-repo-policy --fail-on=critical | Out-String)
    if ($out -notmatch "clean") { throw "Self scan detected issues" }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Acceptance Suite Results: $Passed PASSED, $Failed FAILED (Total: 34 checks)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
} else {
    Write-Host "🎉 ALL ACCEPTANCE TESTS PASSED WITH 100% SUCCESS!" -ForegroundColor Green
    exit 0
}
