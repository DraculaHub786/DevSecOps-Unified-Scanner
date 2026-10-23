# =========================================================================
# Sentinel Multi-Platform Release Artifact Builder (PowerShell)
# Builds binaries for Linux, macOS, and Windows (amd64 + arm64) & generates checksums
# =========================================================================
param(
    [string]$Version = "1.0.1"
)

$ErrorActionPreference = "Stop"

$Commit = try { (git rev-parse --short HEAD).Trim() } catch { "none" }
$BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
$LdFlags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$BuildDate"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$DistDir = Join-Path $RootDir "dist"

if (Test-Path $DistDir) {
    Remove-Item -Recurse -Force $DistDir
}
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$Targets = @(
    @{ OS = "linux"; Arch = "amd64"; Ext = "" },
    @{ OS = "linux"; Arch = "arm64"; Ext = "" },
    @{ OS = "darwin"; Arch = "amd64"; Ext = "" },
    @{ OS = "darwin"; Arch = "arm64"; Ext = "" },
    @{ OS = "windows"; Arch = "amd64"; Ext = ".exe" },
    @{ OS = "windows"; Arch = "arm64"; Ext = ".exe" }
)

Write-Host "🔨 Building Sentinel release artifacts for version $Version..." -ForegroundColor Cyan

foreach ($target in $Targets) {
    $goos = $target.OS
    $goarch = $target.Arch
    $ext = $target.Ext

    $archiveName = "sentinel_${Version}_${goos}_${goarch}"
    $stageDir = Join-Path $DistDir $archiveName
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

    Write-Host "  📦 Compiling for $goos/$goarch..." -ForegroundColor Yellow

    $env:CGO_ENABLED = "0"
    $env:GOOS = $goos
    $env:GOARCH = $goarch

    $sentinelOut = Join-Path $stageDir "sentinel$ext"
    $agentOut = Join-Path $stageDir "sentinel-agent$ext"

    go build -trimpath -ldflags $LdFlags -o $sentinelOut (Join-Path $RootDir "cmd/sentinel")
    go build -trimpath -ldflags "-s -w" -o $agentOut (Join-Path $RootDir "cmd/sentinel-agent")

    Copy-Item (Join-Path $RootDir "README.md") $stageDir
    Copy-Item (Join-Path $RootDir "LICENSE") $stageDir
    Copy-Item (Join-Path $RootDir "SECURITY.md") $stageDir

    $zipPath = Join-Path $DistDir "$archiveName.zip"
    Compress-Archive -Path "$stageDir/*" -DestinationPath $zipPath -Force
    Remove-Item -Recurse -Force $stageDir
}

# Reset environment variables
$env:GOOS = $null
$env:GOARCH = $null

Write-Host "🔐 Generating release checksums.txt..." -ForegroundColor Cyan
$checksumFile = Join-Path $DistDir "checksums.txt"
$files = Get-ChildItem -Path $DistDir -Filter "sentinel_*.zip"

$checksumLines = @()
foreach ($file in $files) {
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
    $checksumLines += "$hash  $($file.Name)"
}
$checksumLines | Set-Content -Path $checksumFile -Encoding ASCII

Write-Host "✅ Release artifacts created successfully in $DistDir" -ForegroundColor Green
Get-ChildItem -Path $DistDir | Select-Object Name, Length
