# Sentinel Pinned Scanner Binary Downloader (Windows)
# Pins exact vendor versions with SHA-256 integrity verification
$ErrorActionPreference = "Stop"
$PluginDir = "$PSScriptRoot"
New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null

$VersionsFile = Join-Path $PluginDir "versions.env"
$Versions = @{}
if (Test-Path $VersionsFile) {
    Get-Content $VersionsFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line.Split("=", 2)
            $Versions[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
}
$GitleaksVer = if ($Versions.ContainsKey("GITLEAKS_VERSION")) { $Versions["GITLEAKS_VERSION"] } else { "8.30.1" }
$OsvVer = if ($Versions.ContainsKey("OSV_VERSION")) { $Versions["OSV_VERSION"] } else { "2.7.0" }
$TrivyVer = if ($Versions.ContainsKey("TRIVY_VERSION")) { $Versions["TRIVY_VERSION"] } else { "0.76.0" }
$NucleiVer = if ($Versions.ContainsKey("NUCLEI_VERSION")) { $Versions["NUCLEI_VERSION"] } else { "3.3.8" }
$SemgrepVer = if ($Versions.ContainsKey("SEMGREP_VERSION")) { $Versions["SEMGREP_VERSION"] } else { "1.182.0" }
$GovulncheckVer = if ($Versions.ContainsKey("GOVULNCHECK_VERSION")) { $Versions["GOVULNCHECK_VERSION"] } else { "1.1.4" }

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
    else {
        Remove-Item $Dest -Force -ErrorAction SilentlyContinue
        throw "❌ No checksum entry for $Filename; refusing to install an unverified binary."
    }
}

Write-Host "🛡️ Fetching pinned scanner binaries to $PluginDir..." -ForegroundColor Cyan

# 1. Gitleaks
$GitleaksFile = "gitleaks_${GitleaksVer}_windows_x64.zip"
$GitleaksUrl = "https://github.com/gitleaks/gitleaks/releases/download/v${GitleaksVer}/$GitleaksFile"
$GitleaksZip = Join-Path $PluginDir $GitleaksFile
try {
    Fetch-And-Verify -Url $GitleaksUrl -Dest $GitleaksZip -Filename $GitleaksFile
    Expand-Archive -Path $GitleaksZip -DestinationPath $PluginDir -Force
    Remove-Item $GitleaksZip -Force
} catch {
    Write-Warning "Failed to install Gitleaks: $_"
}

# 2. OSV-Scanner
$OsvFile = "osv-scanner_windows_amd64.exe"
$OsvUrl = "https://github.com/google/osv-scanner/releases/download/v${OsvVer}/$OsvFile"
$OsvDest = Join-Path $PluginDir "osv-scanner.exe"
try {
    Fetch-And-Verify -Url $OsvUrl -Dest $OsvDest -Filename $OsvFile
} catch {
    Write-Warning "Failed to install OSV-Scanner: $_"
}

# 3. Trivy
$TrivyFile = "trivy_${TrivyVer}_windows-64bit.zip"
$TrivyUrl = "https://github.com/aquasecurity/trivy/releases/download/v${TrivyVer}/$TrivyFile"
$TrivyZip = Join-Path $PluginDir $TrivyFile
try {
    Fetch-And-Verify -Url $TrivyUrl -Dest $TrivyZip -Filename $TrivyFile
    Expand-Archive -Path $TrivyZip -DestinationPath $PluginDir -Force
    Remove-Item $TrivyZip -Force
} catch {
    Write-Warning "Failed to install Trivy: $_"
}

# 4. Nuclei
$NucleiFile = "nuclei_${NucleiVer}_windows_amd64.zip"
$NucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/download/v${NucleiVer}/$NucleiFile"
$NucleiZip = Join-Path $PluginDir $NucleiFile
try {
    Fetch-And-Verify -Url $NucleiUrl -Dest $NucleiZip -Filename $NucleiFile
    Expand-Archive -Path $NucleiZip -DestinationPath $PluginDir -Force
    Remove-Item $NucleiZip -Force
} catch {
    Write-Warning "Failed to install Nuclei: $_"
}

# 5. Semgrep
if (Get-Command pip -ErrorAction SilentlyContinue) {
    try {
        Write-Host "📦 Installing pinned Semgrep via pip ($SemgrepVer)..." -ForegroundColor Cyan
        pip install --quiet "semgrep==$SemgrepVer"
    } catch {
        Write-Warning "Failed to install Semgrep via pip: $_"
    }
}

# 6. govulncheck
if (Get-Command go -ErrorAction SilentlyContinue) {
    try {
        Write-Host "📦 Installing pinned govulncheck via go install (v$GovulncheckVer)..." -ForegroundColor Cyan
        $env:GOBIN = $PluginDir
        go install "golang.org/x/vuln/cmd/govulncheck@v$GovulncheckVer"
    } catch {
        Write-Warning "Failed to install govulncheck via go install: $_"
    }
}

Write-Host "🎉 Scanner binaries setup complete." -ForegroundColor Green

