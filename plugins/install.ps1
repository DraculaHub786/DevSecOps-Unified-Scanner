# Sentinel Pinned Scanner Binary Downloader (Windows)
# Pins exact vendor versions for reproducible, supply-chain safe scanning

$ErrorActionPreference = "Stop"
$PluginDir = "$PSScriptRoot"
New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null

Write-Host "🛡️ Fetching pinned scanner binaries to $PluginDir..." -ForegroundColor Cyan

# 1. Gitleaks (v8.18.4)
$GitleaksVer = "8.18.4"
Write-Host "Downloading Gitleaks v$GitleaksVer..."
$GitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVer/gitleaks_${GitleaksVer}_windows_x64.zip"
$GitleaksZip = "$PluginDir\gitleaks.zip"
try {
    Invoke-WebRequest -Uri $GitleaksUrl -OutFile $GitleaksZip
    Expand-Archive -Path $GitleaksZip -DestinationPath $PluginDir -Force
    Remove-Item $GitleaksZip -Force
    Write-Host "✅ Gitleaks pinned successfully." -ForegroundColor Green
} catch {
    Write-Host "Note: Network download failed or blocked. Sentinel fallback engine will be used." -ForegroundColor Yellow
}

# 2. OSV-Scanner (v1.8.2)
$OsvVer = "1.8.2"
Write-Host "Downloading OSV-Scanner v$OsvVer..."
$OsvUrl = "https://github.com/google/osv-scanner/releases/download/v$OsvVer/osv-scanner_windows_amd64.exe"
try {
    Invoke-WebRequest -Uri $OsvUrl -OutFile "$PluginDir\osv-scanner.exe"
    Write-Host "✅ OSV-Scanner pinned successfully." -ForegroundColor Green
} catch {
    Write-Host "Note: Network download failed or blocked. Sentinel fallback engine will be used." -ForegroundColor Yellow
}

Write-Host "Vendor plugin setup complete." -ForegroundColor Cyan
