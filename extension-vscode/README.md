# 🛡️ Sentinel DevSecOps Unified Scanner for VS Code
 
[![Visual Studio Marketplace](https://img.shields.io/badge/VS%20Code-Extension-blue.svg)](https://marketplace.visualstudio.com)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Sentinel** is a developer-first, unified DevSecOps security scanner that runs inside VS Code. It orchestrates industry-standard engines (**Semgrep**, **Gitleaks**, **OSV-Scanner**, **Trivy**, and **Nuclei**) plus transparently labelled embedded lite fallback engines to provide instant, 100% offline-capable security feedback directly inside your editor. Zero source code leaves your local environment.

---

## Features

- **Inline Security Diagnostics**: Real-time editor squiggles for secrets, SAST flaws, vulnerable dependencies (SCA), IaC misconfigurations, and resilience gaps.
- **Explain Webview Panel**: Rich visual panel detailing the vulnerability, CWE/OWASP references, risk score (0-100), and auto-remediation diff preview.
- **Engine Provenance**: Explicitly labels findings from full external engines (`🔬 External Tool`) vs built-in heuristics (`⚡ Embedded Lite Engine`).
- **Interactive Security Sidebar**: Group findings by **Severity**, **Category**, or **File** with real-time category coverage indicators.
- **1-Click Auto-Remediation**: Preview diffs and apply fixes, dependency version bumps (`package.json`, `requirements.txt`, `go.mod`), and suppressions directly from Code Actions.
- **Status Bar Indicator**: Real-time status bar showing scanner mode (`[Full]` or `[Lite]`), scan spinner, and severity counts. Focuses findings sidebar on click.
- **Incremental & On-Save Scanning**: Debounced scans of only changed files upon saving to guarantee sub-second editor feedback.
- **Workspace Trust Enforced**: Scans are strictly blocked in untrusted workspaces to protect against malicious repositories.

---

## Extension Commands

| Command | Title | Description |
|---|---|---|
| `sentinel.scanWorkspace` | **Sentinel: Scan Workspace** | Run a comprehensive security scan over the entire workspace |
| `sentinel.scanFile` | **Sentinel: Scan Current File** | Scan the currently active file for vulnerabilities |
| `sentinel.showFindingDetails` | **Sentinel: Explain Finding** | Open dedicated Webview Explain Panel with CWE, OWASP, and diff preview |
| `sentinel.applyFix` | **Sentinel: Apply Suggested Fix** | Preview modal diff and apply automated code remediation |
| `sentinel.threatModel` | **Sentinel: Generate Threat Model** | Map workspace entry points and STRIDE threats to a Markdown report |
| `sentinel.sbom` | **Sentinel: Generate SBOM** | Export CycloneDX or SPDX Software Bill of Materials |
| `sentinel.doctor` | **Sentinel: Tool Availability & Status** | Check availability and versions of all 5 security scanning engines |
| `sentinel.createBaseline` | **Sentinel: Accept Findings into Baseline** | Accept existing flaws into baseline so subsequent runs only alert on new flaws |
| `sentinel.suppressFinding` | **Sentinel: Suppress Security Finding** | Suppress finding with a mandatory justification reason and optional expiry |
| `sentinel.openReport` | **Sentinel: Open Scan Report** | Open standalone HTML report |
| `sentinel.dastScan` | **Sentinel: Run Authorized DAST Scan** | Execute targeted Nuclei DAST scan with explicit authorization check |
| `sentinel.toggleSidebarGrouping` | **Sentinel: Toggle Findings Grouping** | Cycle sidebar grouping between Severity, Category, and File |

---

## Configuration Settings

| Setting | Type | Default | Description |
|---|---|---|---|
| `sentinel.scanOnSave` | boolean | `true` | Automatically scan modified files on save |
| `sentinel.debounceMs` | number | `500` | Delay in milliseconds before triggering on-save incremental scan |
| `sentinel.agentPort` | number | `48921` | TCP port of local authenticated `sentinel-agent` IPC daemon |
| `sentinel.binaryPath` | string | `""` | Optional path to `sentinel` or `sentinel-agent` binary executable |
| `sentinel.offline` | boolean | `false` | Disable external network lookups (strict offline operation) |
| `sentinel.engineMode` | enum | `"auto"` | Engine mode: `auto` (external with lite fallback), `full`, or `lite` |
| `sentinel.policyPath` | string | `""` | Path to custom `.sentinel.yml` policy file |
| `sentinel.severityFilter` | enum | `"all"` | Filter inline editor diagnostics: `all`, `critical`, `high`, `medium`, `low` |
| `sentinel.cloudSync` | boolean | `false` | Sync findings metadata to Sentinel Cloud (disabled by default) |

---

## Security & Architecture

1. **Local-First Privacy**: Sentinel scans run locally. No proprietary source code, secrets, or git commit history are uploaded to external cloud endpoints.
2. **Authenticated Loopback IPC**: The `sentinel-agent` daemon binds exclusively to `127.0.0.1` and authenticates every JSON-RPC 2.0 request using a cryptographic session token stored in the user cache directory with restrictive mode `0600`.
3. **Secret Redaction**: Extension logs and diagnostic outputs automatically mask detected credential and API key values.

---

## License

Apache-2.0 © DraculaHub786
