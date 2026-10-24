$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🛡️  Running Sentinel E2E Full Gate Suite (PowerShell)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$rootDir = (Get-Item $scriptDir).Parent.FullName
Set-Location $rootDir

$bin = Join-Path $rootDir "bin\sentinel.exe"
if (-not (Test-Path $bin)) {
    Write-Host "⚙️ Building sentinel binary..." -ForegroundColor Yellow
    go build -o $bin ./cmd/sentinel
}

Write-Host "--- 1. Engine Diagnostics Check ---" -ForegroundColor Blue
& $bin doctor

Write-Host "--- 2. End-to-End Test Suite Execution ---" -ForegroundColor Blue
go test -v ./cmd/sentinel -run TestE2E
if ($LASTEXITCODE -ne 0) {
    Write-Error "TestE2E failed with exit code $LASTEXITCODE"
}

Write-Host "--- 3. Direct CLI Scan against Safe Fixture ---" -ForegroundColor Blue
$safeReport = & $bin scan testdata/safe-app --format=terminal
if ($safeReport -match "No security flaws or secrets identified") {
    Write-Host "✅ Safe fixture verified clean (0 findings)" -ForegroundColor Green
} else {
    Write-Host "❌ Safe fixture produced unexpected findings:" -ForegroundColor Red
    Write-Host $safeReport
    exit 1
}

Write-Host "--- 4. Detection Quality Benchmark Check (bench-detect) ---" -ForegroundColor Blue
& $bin bench-detect
if ($LASTEXITCODE -ne 0) {
    Write-Error "bench-detect failed with exit code $LASTEXITCODE"
}

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "🎉 E2E Full Gate Suite Passed Successfully!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
