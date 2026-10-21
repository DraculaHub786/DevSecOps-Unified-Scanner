# 🛡️ Sentinel DevSecOps Unified Scanner for VS Code
 
[![Visual Studio Marketplace](https://img.shields.io/badge/VS%20Code-Extension-blue.svg)](https://marketplace.visualstudio.com)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Sentinel** is a developer-first, unified security scanner that runs inside VS Code. It orchestrates industry-standard engines (**Semgrep**, **Gitleaks**, **OSV-Scanner**, **Trivy**, and **Nuclei**) plus embedded fallback engines to provide instant, offline-capable security feedback directly inside your editor.

---

## Features

- **Inline Security Diagnostics**: Real-time squiggles and diagnostics for secrets, SAST flaws, vulnerable dependencies (SCA), and IaC misconfigurations.
- **Engine Provenance**: Distinguishes between full external tool scans (`engine: external`) and built-in lite regex fallback checks (`engine: embedded`).
- **Interactive Sidebar**: View, filter, and navigate all security findings organized by severity and category.
- **1-Click Auto-Remediation**: Apply safe fixes, dependency upgrades, and config patches directly from Code Actions (Quick Fix).
- **Status Bar Indicator**: Real-time status bar showing scanner mode (`[Full]` or `[Lite]`) and local agent IPC connection status.
- **Incremental & On-Save Scanning**: Scans only changed files upon saving to guarantee sub-second editor feedback.

---

## Extension Commands

| Command | Title | Description |
|---|---|---|
| `sentinel.scanWorkspace` | **Sentinel: Scan Workspace** | Run a comprehensive security scan over the open workspace |
| `sentinel.scanFile` | **Sentinel: Scan Current File** | Scan the currently active file for vulnerabilities |
| `sentinel.showFindingDetails` | **Sentinel: Explain Finding** | Open detailed remediation guidance, CWE, and CVSS info |
| `sentinel.applyFix` | **Sentinel: Apply Suggested Fix** | Preview and apply automated code patches |

---

## Configuration Settings

- `sentinel.scanOnSave` (default: `true`): Automatically scan modified files on save.
- `sentinel.agentPort` (default: `48921`): TCP port of the local authenticated `sentinel-agent` IPC daemon.
- `sentinel.cloudSync` (default: `false`): Sync findings to optional Sentinel SaaS backend.

---

## Prerequisites

Start the local Sentinel daemon:
```bash
sentinel-agent --port 48921
```
The extension automatically reads the cryptographic session token from your user cache directory to authenticate all IPC requests over loopback.

---

## License

Apache-2.0 © DraculaHub786
