# =========================================================================
# Sentinel Scanner Benchmark Suite (PowerShell)
# Measures cold scan, warm scan, and single-file incremental performance
# =========================================================================
param(
    [string]$Target = ""
)

$ErrorActionPreference = "Stop"
$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = Join-Path $RootDir "testdata/vulnerable-app"
}

$OutputDir = Join-Path $RootDir "dist/bench"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$SentinelBin = Join-Path $RootDir "bin/sentinel.exe"
if (-not (Test-Path $SentinelBin)) {
    Write-Host "Building sentinel.exe..." -ForegroundColor Cyan
    go build -o $SentinelBin (Join-Path $RootDir "cmd/sentinel")
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🚀 Running Sentinel Benchmark Suite" -ForegroundColor Cyan
Write-Host "Target: $Target"
Write-Host "Date:   $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Cold Scan
Write-Host "❄️  Running Cold Scan..." -ForegroundColor Yellow
$sentinelCache = Join-Path $Target ".sentinel"
if (Test-Path $sentinelCache) {
    Remove-Item -Recurse -Force $sentinelCache
}

$coldOut = Join-Path $OutputDir "cold.json"
$coldWatch = [System.Diagnostics.Stopwatch]::StartNew()
& $SentinelBin scan $Target --format json --out $coldOut
$coldWatch.Stop()
Write-Host "   Cold Scan Time: $($coldWatch.ElapsedMilliseconds) ms" -ForegroundColor Green

# 2. Warm Scan
Write-Host "🔥 Running Warm Scan..." -ForegroundColor Yellow
$warmOut = Join-Path $OutputDir "warm.json"
$warmWatch = [System.Diagnostics.Stopwatch]::StartNew()
& $SentinelBin scan $Target --format json --out $warmOut
$warmWatch.Stop()
Write-Host "   Warm Scan Time: $($warmWatch.ElapsedMilliseconds) ms" -ForegroundColor Green

# 3. Incremental Scan
Write-Host "⚡ Running Incremental Scan..." -ForegroundColor Yellow
$incOut = Join-Path $OutputDir "inc.json"
$incWatch = [System.Diagnostics.Stopwatch]::StartNew()
& $SentinelBin scan $Target --changed-only --format json --out $incOut
$incWatch.Stop()
Write-Host "   Incremental Scan Time: $($incWatch.ElapsedMilliseconds) ms" -ForegroundColor Green

# 4. Compare Engine
Write-Host ""
$comparePy = Join-Path $PSScriptRoot "compare.py"
python $comparePy $coldOut
