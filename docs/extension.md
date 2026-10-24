# Sentinel VS Code Extension — Specification & Guide

The Sentinel VS Code extension provides unified real-time SAST, SCA, secrets, IaC, and resilience security diagnostics directly inside your IDE. Scans execute 100% locally on your machine with zero source code leaving your environment.

---

## 1. Architecture Overview

```mermaid
graph TD
    IDE[VS Code Extension Host] -->|JSON-RPC 2.0 over TCP (127.0.0.1)| Agent[sentinel-agent IPC Daemon]
    Agent --> Sched[Orchestrator Scheduler]
    Sched --> Gitleaks[Gitleaks (Secrets)]
    Sched --> Semgrep[Semgrep / Ast-Grep (SAST)]
    Sched --> OSV[OSV-Scanner (SCA)]
    Sched --> Govuln[govulncheck (Go Reachability)]
    Sched --> Trivy[Trivy (IaC & Misconfig)]
    Sched --> Nuclei[Nuclei (Passive DAST)]
    Sched --> Resilience[Resilience Analyzer]
    Sched --> Correlate[Correlation & Risk Engine]
    Correlate --> Agent
    Agent --> IDE
```

1. **Host-Agent Boundary**: The VS Code extension connects over local loopback (`127.0.0.1:48921`) to `sentinel-agent`.
2. **Cryptographic Session Authentication**: On daemon launch, `sentinel-agent` generates a cryptographically random 192-bit hex token, saves it with restrictive permissions (`0600`) in the user cache directory (`%LOCALAPPDATA%\sentinel\agent.token` on Windows or `~/.cache/sentinel/agent.token` on POSIX), and automatically deletes the token on shutdown.
3. **Dual Security Model**:
   - **Per-request authentication**: Every incoming JSON-RPC 2.0 message must include the valid `token`.
   - **Protocol Handshake**: On startup, the extension initiates `agent.handshake` to negotiate protocol capabilities and verify version parity.

---

## 2. IPC Protocol Specification (JSON-RPC 2.0)

### 2.1 Request Envelope Format
```json
{
  "jsonrpc": "2.0",
  "id": 101,
  "token": "<cryptographic_session_token>",
  "method": "<method_name>",
  "params": { ... }
}
```

### 2.2 Response Envelope Format
```json
{
  "jsonrpc": "2.0",
  "id": 101,
  "result": { ... },
  "error": null
}
```

### 2.3 Method Catalog

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `agent.handshake` | `{ client: string, version: string }` | `{ status, serverVersion, protocolVersion, capabilities }` | Handshake & capability negotiation |
| `agent.ping` | `{}` | `{ status: "ok", version: string }` | Daemon liveness check |
| `scan.run` | `{ repoPath, paths?, incremental?, offline?, policyPath? }` | `{ scanId: string }` | Dispatches asynchronous security scan |
| `scan.status` | `{ scanId: string }` | `{ state: "running"\|"done"\|"error", progress: number }` | Queries scan state |
| `findings.list` | `{ scanId: string, file?: string }` | `Finding[]` | Returns normalized finding objects |
| `fix.preview` | `{ repoPath: string, findingId: string }` | `{ diff: string, description: string }` | Previews unified diff for automated fix |
| `fix.apply` | `{ repoPath: string, findingId: string }` | `{ success: boolean, appliedDiff: string }` | Applies code remediation to workspace file |
| `doctor.run` | `{}` | `EngineStatus[]` | Checks local availability of scanning tools |
| `agent.coverage` | `{}` | `CoverageReport` | Returns scanner engine coverage breakdown |
| `baseline.create` | `{ repoPath: string }` | `{ success: boolean, count: number, path: string }` | Accepts current findings into baseline |
| `suppress.add` | `{ repoPath, findingId, reason, expires? }` | `{ success: boolean, findingId: string, file: string }` | Suppresses finding with mandatory justification |
| `threatmodel.run` | `{ repoPath: string }` | `ThreatModelResult` | Generates STRIDE threat model |
| `sbom.generate` | `{ repoPath, format: "cyclonedx"\|"spdx", out: string }` | `{ success: boolean, format, out }` | Generates SBOM file |
| `dast.run` | `{ target: string, authorized: boolean, allowPrivate?: boolean }` | `Finding[]` | Executes authorized passive DAST scan |

---

## 3. Extension Security Hardening

### 3.1 Secure Finding Hover Messages (Chunk 13 / AT-27d)
The extension strictly blocks command injection vulnerabilities in hover messages:
1. **No Blanket Trust**: `md.isTrusted = true` is prohibited. The extension strictly whitelists permitted commands:
   ```typescript
   md.isTrusted = {
       enabledCommands: ['sentinel.showFindingDetails', 'sentinel.applyFix']
   };
   ```
2. **HTML Injection Disabled**: `md.supportHtml = false`.
3. **Untrusted String Sanitization**: Finding messages, snippets, and rule IDs from scanned repositories are sanitized and appended via `md.appendText()`. Embedded URI schemes (`command:`, `javascript:`, `data:`) are disarmed to `command_disarmed:`.

### 3.2 Workspace Trust Gating
Sentinel enforces VS Code's Workspace Trust API (`vscode.workspace.isTrusted`):
- When an untrusted workspace or folder is opened, scanning tools and agent daemon spawn operations are **strictly disabled**.
- When trust is granted by the user, Sentinel automatically initializes and runs an initial scan.

---

## 4. UI Features & Workflows

### 4.1 Inline Diagnostics & Quick Fixes
- Findings appear inline in the editor with squiggly underlines colored by severity (Critical & High = Error, Medium = Warning, Low = Info).
- Quick Fix menu (`Ctrl+.` or `Cmd+.`) provides:
  - **Apply Suggested Fix**: Applies automated patch directly to the file.
  - **Preview Diff**: Opens unified diff in a side-by-side diff preview.
  - **Explain Flaw**: Opens Sentinel Explain Webview with remediation guidance, CWE, OWASP, and reachability proof.
  - **Suppress Finding**: Prompts for mandatory justification and records suppression in `.sentinel.yml`.

### 4.2 Sidebar Findings Explorer
The Sentinel activity bar icon provides a tree view of all active findings with three grouping modes (toggleable via the grouping button):
1. **Group by Severity**: Critical 🚨, High ⚠️, Medium 🟡, Low ℹ️.
2. **Group by Category**: SAST, SCA, Secret, IaC, Resilience, DAST.
3. **Group by File**: Relative file path with count badge.

### 4.3 Status Bar Indicators
- `$(shield) Sentinel [Full]: Clean`: Zero critical or high issues.
- `$(shield) Sentinel [Full]: 2 🚨 1 ⚠️`: Findings count badge. Clicking triggers an instant workspace rescan.
- `$(sync~spin) Sentinel: Scanning...`: Scan in progress.
- `$(alert) Sentinel: Scan Error`: Tool execution error. Click to view Output channel logs.

---

## 5. Configuration Reference

Configure settings in `.vscode/settings.json` or VS Code User Settings (`sentinel.*`):

| Setting | Type | Default | Description |
|---|---|---|---|
| `sentinel.binaryPath` | `string` | `""` | Custom absolute path to `sentinel` or `sentinel-agent` binary. If empty, searches system PATH. |
| `sentinel.engineMode` | `enum` | `"auto"` | `"auto"` (prefer external CLI, fallback to lite embedded), `"full"` (require external CLI), or `"lite"` (embedded only). |
| `sentinel.scanOnSave` | `boolean` | `true` | Automatically run fast incremental scans on file save. |
| `sentinel.debounceMs` | `number` | `500` | Debounce delay in milliseconds for incremental on-save scans. |
| `sentinel.severityFilter`| `enum` | `"all"` | Filter inline diagnostics by minimum threshold: `"all"`, `"critical"`, `"high"`, `"medium"`, `"low"`. |
| `sentinel.offline` | `boolean` | `false` | Strict offline mode; disables network requests during scans. |
| `sentinel.policyPath` | `string` | `""` | Custom path to `.sentinel.yml` configuration policy. |
| `sentinel.cloudSync` | `boolean` | `false` | Cloud backend synchronization (default: disabled, 100% local). |

---

## 6. Packaging & Installation

### Reproducible Packaging (Chunk 15 / AT-27c)
The extension package relies on pinned `@vscode/vsce` in `devDependencies`:
```bash
cd extension-vscode
npm install
npm test
npm run package
```
This generates `sentinel-vscode-1.0.1.vsix`.

### Installing into VS Code
```bash
code --install-extension sentinel-vscode-1.0.1.vsix
```

---

## 7. Troubleshooting & FAQ

### Agent Connection Refused
- **Symptom**: `Failed to connect to sentinel-agent on 127.0.0.1:48921`.
- **Resolution**: Verify `sentinel-agent` is running or that the Sentinel binary is discoverable in PATH. You can manually launch the daemon with:
  ```bash
  sentinel-agent --port 48921
  ```

### Unauthorized Error (-32001)
- **Symptom**: `Unauthorized: invalid or missing session token`.
- **Resolution**: Check that the token file in your cache directory (`%LOCALAPPDATA%\sentinel\agent.token` or `~/.cache/sentinel/agent.token`) has appropriate read permissions for your user account.

### External Engine Missing
- Run **Sentinel: Tool Availability & Status (Doctor)** from the Command Palette (`Ctrl+Shift+P` -> `Sentinel: Doctor`) to inspect installed scanner binaries. If an engine is missing, install it using `plugins/install.sh` or switch `sentinel.engineMode` to `auto` or `lite`.
