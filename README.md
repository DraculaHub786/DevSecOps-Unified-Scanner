# 🛡️ Sentinel — DevSecOps Unified Scanner

A unified CLI + IDE security scanner orchestrating SAST, SCA, Secrets, IaC, DAST, and resilience scanning with cross-tool deduplication, reachability-based risk scoring, and inline auto-remediation.

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENTS                              │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────┐ │
│  │     CLI      │   │ VS Code Extension│   │  CI / Action │ │
│  └──────┬───────┘   └────────┬─────────┘   └──────┬───────┘ │
└─────────┼────────────────────┼────────────────────┼─────────┘
          │                    │                    │
          └─────────────┬──────┴────────────────────┘
                        ▼
         ┌──────────────────────────────┐
         │  Orchestration Engine (Core) │
         │  • Job Scheduler             │
         │  • Multi-Scanner Adapters    │
         │  • Deduplication & Fusion    │
         │  • Contextual Risk Scoring   │
         │  • Auto-Remediation Engine   │
         └──────────────┬───────────────┘
                        │
         ┌──────────────┴──────────────┐
         ▼                             ▼
  Scanner Adapters              Storage & Reports
  • Semgrep (SAST)              • SARIF 2.1.0 Standard
  • Gitleaks (Secrets)          • SQLite (.sentinel/history.db)
  • OSV-Scanner (SCA)           • Markdown PR Comments
  • Trivy (IaC/Containers)      • Machine-Readable JSON
  • Nuclei (DAST Passive)       • Terminal ANSI Dashboards
  • Resilience/DoS Engine
```

---

## ⚡ Key Highlights

- **100% Local-First by Default**: Scans execute locally in your terminal or editor. No source code or decrypted secrets ever leave your environment.
- **Cross-Scanner Deduplication**: Correlates alerts across tools (e.g. Trivy and OSV flagging the same CVE), merging duplicates and prioritizing the highest severity.
- **Contextual Risk Scoring (0–100)**: Adjusts base CVSS severity with reachability analysis (is the vulnerable package called in your code?), exposure heuristic (public API vs internal test), and exploitability.
- **Actionable Remediation**: Generates instant dependency version bump diffs, `.gitignore` entries, and security refactorings.
- **Native VS Code Integration**: Squiggles in the Problems panel, lightbulb Quick Fixes, an interactive severity tree view, and live status bar tracking.
- **CI/CD Ready**: Exits with code `1` when findings exceed your `--fail-on` threshold, with native SARIF 2.1.0 export for GitHub/GitLab Code Scanning.

---

## 🚀 Quick Start

### 1. Build Binaries
```bash
# Build CLI and Agent daemon
go build -o bin/sentinel ./cmd/sentinel
go build -o bin/sentinel-agent ./cmd/sentinel-agent
```

### 2. Run a Scan
```bash
# Scan current repository (auto-detects languages and frameworks)
./bin/sentinel scan

# Fail build if High or Critical findings exist
./bin/sentinel scan --fail-on=high --ci

# Output SARIF 2.1.0 for GitHub Code Scanning
./bin/sentinel scan --format=sarif --out=results.sarif

# Passive DAST scan against staging endpoint
./bin/sentinel scan --target https://staging.myapp.com --dast
```

### 3. Explain & Auto-Fix Findings
```bash
# Inspect rule explanation, CWE link, and remediation steps
./bin/sentinel explain SENT-531c1ae4dd0f

# Preview auto-generated patch diff
./bin/sentinel fix SENT-531c1ae4dd0f

# Apply the patch diff directly to your source file
./bin/sentinel fix SENT-531c1ae4dd0f --apply
```

### 4. Watch Mode (Live Re-scan on Save)
```bash
./bin/sentinel watch
```

### 5. Git Pre-Commit Hook
```bash
./bin/sentinel install-hooks
```

---

## 🧩 VS Code Extension

The extension in `extension-vscode/` connects to `sentinel-agent` over local IPC:

```bash
cd extension-vscode
npm install
npm run compile
```

Features:
- **Native Diagnostics**: Underlines security flaws directly in the editor.
- **Quick Fix (💡)**: One-click preview and apply for dependency bumps.
- **Sidebar Tree View**: Grouped by Critical, High, Medium, and Low.
- **Hover Information**: Shows CVSS, CWE reference, and rationale on hover.

---

## ⚙️ Configuration (`.sentinel.yml`)

```yaml
version: 1
scanners:
  sast:
    enabled: true
    ruleset: "auto"
    extra_rules:
      - "rules/sast-rules.yml"
  secrets:
    enabled: true
    scan_history: false
  sca:
    enabled: true
    fail_on_license: ["GPL-3.0"]
  iac:
    enabled: true
  dast:
    enabled: false
    target: "https://staging.myapp.com"
  resilience:
    enabled: true

ignore:
  paths:
    - "vendor/**"
    - "node_modules/**"
    - "dist/**"
    - "**/*_test.go"
  findings: []

thresholds:
  fail_on: "high" # critical | high | medium | low

output:
  formats: ["terminal", "sarif", "markdown"]
  path: ".sentinel/reports/"
```

---

## 🧪 Verification & Evidence

Run unit and integration tests:
```bash
go test -v ./...
```
Output:
```
=== RUN   TestCorrelateAndDeduplicate
--- PASS: TestCorrelateAndDeduplicate (0.00s)
=== RUN   TestCalculateRiskScore
--- PASS: TestCalculateRiskScore (0.00s)
=== RUN   TestGenerateSARIF
--- PASS: TestGenerateSARIF (0.00s)
PASS
```

Scan the intentionally vulnerable test fixture:
```bash
./bin/sentinel scan testdata/vulnerable-app --format=terminal
```
Detects secrets (Gitleaks), command injection & TLS misconfiguration (Semgrep), vulnerable dependencies (OSV), container root user & open ingress (Trivy), and unbounded body reads / missing timeouts (Resilience) in **under 30 milliseconds**.
