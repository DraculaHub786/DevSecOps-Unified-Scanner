# Sentinel Pinned Scanner Binary Downloader (Windows)
# Pins exact vendor versions with SHA-256 integrity verification
$ErrorActionPreference = "Stop"
$PluginDir = "$PSScriptRoot"
New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null

$ChecksumFile = Join-Path $PluginDir "checksums.txt"
$ChecksumMap = @{}
if (Test-Path $ChecksumFile) {
    Get-Content $ChecksumFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#")) {
            $parts = -split $line
            if ($parts.Length -ge 2) {
                $ChecksumMap[$parts[1].Trim()] = $parts[0].Trim()
            }
        }
    }
}

function Fetch-And-Verify {
    param(
        [string]$Url,
        [string]$Dest,
        [string]$Filename
    )

    Write-Host "⬇️ Downloading $Filename..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $Url -OutFile $Dest

    if ($ChecksumMap.ContainsKey($Filename)) {
        $expected = $ChecksumMap[$Filename]
        $actual = (Get-FileHash -Algorithm SHA256 -Path $Dest).Hash.ToLower()
        if ($actual -ne $expected.ToLower()) {
            Remove-Item $Dest -Force
            throw "❌ Checksum verification failed for $Filename! Expected: $expected, Got: $actual"
        }
        Write-Host "✅ Checksum verified for $Filename" -ForegroundColor Green
    }
}

Write-Host "🛡️ Fetching pinned scanner binaries to $PluginDir..." -ForegroundColor Cyan

# 1. Gitleaks (v8.18.4)
$GitleaksFile = "gitleaks_8.18.4_windows_x64.zip"
$GitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/$GitleaksFile"
$GitleaksZip = Join-Path $PluginDir $GitleaksFile
try {
    Fetch-And-Verify -Url $GitleaksUrl -Dest $GitleaksZip -Filename $GitleaksFile
    Expand-Archive -Path $GitleaksZip -DestinationPath $PluginDir -Force
    Remove-Item $GitleaksZip -Force
} catch {
    Write-Warning "Failed to install Gitleaks: $_"
}

# 2. OSV-Scanner (v1.8.2)
$OsvFile = "osv-scanner_1.8.2_windows_amd64.exe"
$OsvUrl = "https://github.com/google/osv-scanner/releases/download/v1.8.2/$OsvFile"
$OsvDest = Join-Path $PluginDir "osv-scanner.exe"
try {
    Fetch-And-Verify -Url $OsvUrl -Dest $OsvDest -Filename $OsvFile
} catch {
    Write-Warning "Failed to install OSV-Scanner: $_"
}

# 3. Trivy (v0.51.0)
$TrivyFile = "trivy_0.51.0_windows-64bit.zip"
$TrivyUrl = "https://github.com/aquasecurity/trivy/releases/download/v0.51.0/$TrivyFile"
$TrivyZip = Join-Path $PluginDir $TrivyFile
try {
    Fetch-And-Verify -Url $TrivyUrl -Dest $TrivyZip -Filename $TrivyFile
    Expand-Archive -Path $TrivyZip -DestinationPath $PluginDir -Force
    Remove-Item $TrivyZip -Force
} catch {
    Write-Warning "Failed to install Trivy: $_"
}

Write-Host "🎉 Scanner binaries setup complete." -ForegroundColor Green
