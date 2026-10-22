# 🛡️ Sentinel — DevSecOps Unified Scanner

[![CI](https://github.com/DraculaHub786/DevSecOps-Unified-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/DraculaHub786/DevSecOps-Unified-Scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/DraculaHub786/DevSecOps-Unified-Scanner)](https://goreportcard.com/report/github.com/DraculaHub786/DevSecOps-Unified-Scanner)

A unified local-first DevSecOps security scanner orchestrating industry-standard engines (**Semgrep**, **Gitleaks**, **OSV-Scanner**, **Trivy**, **Nuclei**) behind a single interface. Sentinel correlates alerts, eliminates cross-tool duplicate findings, calculates contextual risk scores, and suggests actionable remediations without sending your code to any third party.

---

## 🧭 Documentation & Architecture

- 📐 **[Architecture & Build Guide](docs/architecture.md)** — Core pipelines, engine adapters, and design principles.
- 🧮 **[Contextual Risk Scoring](docs/risk-scoring.md)** — Mathematical formula and weighting models.
- 🔒 **[Security Policy](SECURITY.md)** — Vulnerability reporting and network safety invariants.
- 🤝 **[Contributing Guide](CONTRIBUTING.md)** — Development standards and commit conventions.

---

## ⚡ Key Highlights

- **100% Local-First by Default**: Scans execute locally in your terminal or IDE daemon. Zero code, lockfiles, or decrypted secrets leave your machine.
- **Honest Engine Provenance (Full vs. Lite Mode)**:
  - **Full Mode**: Uses external production tools (`Semgrep`, `Gitleaks`, `OSV-Scanner`, `Trivy`, `Nuclei`) with separate stdout/stderr execution and exit code checks.
  - **Embedded Lite Mode**: Built-in fallback engines run when external tools are absent, transparently tagged as `engine: embedded` / `lite` in all reports.
  - **CI Lite Gating**: Running in `--ci` mode halts with exit code `2` if missing engines fall back to lite mode, unless `--allow-lite` is explicitly permitted.
- **Cross-Scanner Deduplication**: Fuses overlapping findings (e.g. Trivy and OSV-Scanner flagging the same CVE), preserving the highest severity and richest remediation.
- **Contextual Risk Scoring (0–100)**: Weights base CVSS severity against reachability (is the vulnerable package called in your code?), exposure heuristic (public route vs internal test file), and exploitability.
- **Safe & Guarded DAST**: Dynamic web tests are strictly passive by default and require legal authorization acknowledgment (`--i-have-authorization`), domain allowlists, and private IP blocks.
- **Baseline & History Tracking**: Accept existing flaws into a baseline (`sentinel baseline`) so subsequent runs only fail on new findings. Query and diff past scans via local SQLite store (`sentinel history`, `sentinel diff`).
- **Software Bill of Materials (SBOM)**: Native generation in CycloneDX and SPDX format via `sentinel sbom`.

---

## 🛡️ Operational Modes (Full vs. Lite)

Sentinel is architected around transparent engine provenance: **Production security tools are the product; embedded fallbacks are a clearly labeled "lite mode".**

| Feature | Full Mode (Recommended) | Embedded Lite Mode |
| :--- | :--- | :--- |
| **Engine Used** | External CLI (`semgrep`, `gitleaks`, `osv-scanner`, `trivy`, `nuclei`) | Built-in zero-dependency regex and heuristic rule checkers |
| **Finding Tag** | `engine: external` | `engine: embedded` (labeled as `lite` in terminal) |
| **Rule Breadth** | Comprehensive community and vendor rule catalogs | Focused subset of common CVEs and security signatures |
| **CI Behavior** | Standard CI gating | Fails CI (`exit 2`) unless `--allow-lite` is passed |

Check your workstation or runner engine status at any time:
```bash
sentinel doctor
```

---

## ⚖️ Authorized Use & DAST Safety Guardrails

> [!CAUTION]
> Dynamic Application Security Testing (DAST) interacts directly with networked HTTP services. You must only scan services and hosts that you own or have explicit, prior written authorization to assess.

Sentinel enforces strict guardrails before any network request is issued:
1. **Mandatory Authorization Flag**: You must pass `--i-have-authorization`.
2. **Explicit Hostname Allowlist**: Targets must be declared in `.sentinel.yml` under `scanners.dast.allowlist`.
3. **Private Subnet & Cloud Metadata Guard**: Sentinel validates DNS responses and checks the connected socket IP, blocking loopback (`127.0.0.1`), private RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`) unless `allow_private: true` is explicitly configured.
4. **Passive Only**: Nuclei tests run with `-passive` to avoid denial-of-service or active payload disruption.

---


## 🛠️ Command Reference

| Command | Purpose |
| :--- | :--- |
| `sentinel scan [path]` | Full unified scan (`--only`, `--skip`, `--changed-only`, `--baseline`, `--allow-lite`) |
| `sentinel doctor` | Inspect external engine availability, versions, and full vs lite status |
| `sentinel baseline [path]` | Accept current findings into `.sentinel/baseline.json` |
| `sentinel history` | View chronological scan history from `.sentinel/history.db` |
| `sentinel diff <a> <b>` | Compare two historical scans (identifies new, fixed, and unchanged flaws) |
| `sentinel report <id> --format` | Re-render a stored scan in `sarif`, `html`, `markdown`, or `json` |
| `sentinel suppress <id> --reason` | Suppress a finding in `.sentinel.yml` with mandatory justification |
| `sentinel sbom [path]` | Generate CycloneDX or SPDX Software Bill of Materials |
| `sentinel image <name>` | Scan container images for vulnerabilities via Trivy |
| `sentinel dast --target URL` | Passive DAST scanning with mandatory authorization check |
| `sentinel threat-model [path]`| Discover entry points, ports, data stores, and STRIDE threat matrix |
| `sentinel secrets [path]` | Shortcut: Secrets scanning |
| `sentinel deps [path]` | Shortcut: Dependency vulnerability scanning (SCA) |
| `sentinel sast [path]` | Shortcut: Static application security testing (SAST) |
| `sentinel iac [path]` | Shortcut: Infrastructure as Code & Dockerfile misconfiguration |
| `sentinel explain <id>` | View rule rationale, CWE advisory links, and guidance |
| `sentinel fix <id> [--apply]` | Preview or apply automated code patch / dependency bump |
| `sentinel watch [path]` | Incremental scan on file modifications |
| `sentinel install-hooks` | Install pre-commit hook preventing commits with high/critical flaws |

---

## 🚀 Quick Start

### 1. Build Binaries
```bash
go build -o bin/sentinel ./cmd/sentinel
go build -o bin/sentinel-agent ./cmd/sentinel-agent
```

### 2. Check Engine Status
```bash
./bin/sentinel doctor
```

### 3. Run a Scan
```bash
# Scan workspace with terminal output
./bin/sentinel scan

# Fail CI build on high or critical severity
./bin/sentinel scan --ci --fail-on=high

# Output SARIF 2.1.0 and offline self-contained HTML report
./bin/sentinel scan --format=terminal,sarif,html --out=report.html

# Only scan modified uncommitted files in git
./bin/sentinel scan --changed-only
```

### 4. DAST Scanning Guardrails
```bash
# Authorized passive DAST scan against allowlisted staging target
./bin/sentinel dast --target https://staging.example.com --i-have-authorization
```

> [!NOTE]
> Targets must be declared in `.sentinel.yml` under `scanners.dast.allowlist`. Targets resolving to private (`10.0.0.0/8`, `192.168.0.0/16`) or loopback (`127.0.0.1`) addresses are refused unless `allow_private: true` is explicitly configured.

---

## ⚙️ Configuration (`.sentinel.yml`)

```yaml
version: 1
engine: "auto" # auto | external | embedded

thresholds:
  fail_on: "high" # critical | high | medium | low
  risk_score_max: 80.0

scanners:
  sast:
    enabled: true
    ruleset: "auto"
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
    allowlist:
      - staging.example.com
    allow_private: false
  resilience:
    enabled: true

ignore:
  paths:
    - "vendor/**"
    - "node_modules/**"
    - "dist/**"
  findings:
    - id: "SENT-0119773a7723"
      reason: "Synthetic test token used in fixture"
      expires: "2099-01-01"

output:
  formats: ["terminal", "sarif", "html"]
  path: ".sentinel/reports/"
```

---

## 🧩 VS Code Extension

The extension in `extension-vscode/` connects to `sentinel-agent` over local IPC authenticated via cryptographic session tokens:

```bash
cd extension-vscode
npm install
npm run compile
```

- **Inline Diagnostics**: Highlighting flaws with severity and engine provenance (`[Sentinel SAST (external)]` vs `[Sentinel SAST (embedded)]`).
- **Status Bar Indicator**: Live display of scan status and operational mode (`Sentinel [Full]: Clean` or `Sentinel [Lite]: 2 🚨 3 ⚠️`).
- **Interactive Hover**: Displays STRIDE category, CVSS, and external tool verification status.

---

## 🧪 Verification

Run the comprehensive unit test suite:
```bash
go test -v ./...
```

Scan the intentionally vulnerable test fixture:
```bash
./bin/sentinel scan testdata/vulnerable-app --format=terminal
```

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for full details.
