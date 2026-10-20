# DevSecOps Unified Scanner — Architecture & Build Guide

A CLI + IDE extension for unified SAST, SCA, secrets, DAST, and resilience scanning

## 1. Concept

**Name idea:** `SentinelDev` (or `GuardRail`, `SecForge`) — pick anything; referred to as *Sentinel* below.

**Core idea:** Don't rebuild vulnerability detection engines — orchestrate the best open-source ones (Semgrep, Trivy, OSV-Scanner, Gitleaks, Nuclei, ZAP) behind one interface, correlate and de-duplicate their output, score real risk, and surface fixes inline in the terminal or the IDE. The differentiator is the **unification layer, developer experience, and auto-remediation**, not the detection engines themselves.

**What it covers:**

- SAST (code-level flaws: injection, XSS, insecure deserialization, etc.)
- SCA (vulnerable dependencies, license risk)
- Secrets detection (leaked keys, tokens, credentials)
- IaC scanning (Terraform/K8s/Dockerfile misconfig)
- DAST (runtime scanning against a running instance/staging URL)
- Basic resilience/DDoS posture checks (rate-limiting, timeout config, resource-exhaustion patterns — see §9 for scope limits)
- Auto-generated remediation (patch diffs, dependency bumps, config fixes)

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENTS                                │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────┐  │
│  │  CLI (Go/TS) │   │ VS Code Extension │   │   CI Plugin   │  │
│  └──────┬───────┘   └────────┬──────────┘   └──────┬───────┘  │
└─────────┼────────────────────┼──────────────────────┼─────────┘
          │                    │                       │
          └─────────────┬──────┴───────────────────────┘
                         ▼
          ┌──────────────────────────────┐
          │   Orchestration Engine (core) │
          │  - job scheduler              │
          │  - scanner adapters           │
          │  - correlation/dedup          │
          │  - risk scoring               │
          │  - remediation generator      │
          └──────┬────────────────┬───────┘
                 │                │
     ┌───────────▼─────┐   ┌──────▼───────────┐
     │  Scanner Plugins │   │  Report/Storage   │
     │  (wrapped tools) │   │  (SARIF, SQLite,  │
     │  Semgrep, Trivy, │   │   Postgres cloud) │
     │  Gitleaks,       │   └───────────────────┘
     │  OSV-Scanner,    │
     │  Nuclei/ZAP      │
     └──────────────────┘
                 │
     ┌───────────▼─────────────┐
     │  Optional Cloud Backend  │
     │  (SaaS mode, team view,  │
     │   history, dashboards)   │
     └──────────────────────────┘
```

**Two deployment modes:**

1. **Local-first (default):** everything runs on the dev's machine or CI runner — no code ever leaves the environment. This is the mode most developers and security-conscious teams will actually trust and adopt.
2. **Cloud/SaaS (optional, opt-in):** a control plane for teams — aggregated dashboards, trend lines, policy enforcement, PR gating — the scan execution itself can still stay local/CI-side and only upload *results*, not code.

## 3. Repository / File Structure

```
sentinel/
├── cmd/
│   ├── sentinel/                 # CLI entrypoint (Go, using Cobra)
│   │   └── main.go
│   └── sentinel-agent/           # lightweight daemon for IDE <-> engine IPC
│       └── main.go
├── internal/
│   ├── orchestrator/
│   │   ├── scheduler.go          # parallel job scheduling, timeouts
│   │   ├── correlate.go          # dedup + merge findings across scanners
│   │   ├── riskscore.go          # CVSS + reachability + exploitability scoring
│   │   └── remediate.go          # fix-suggestion generation
│   ├── adapters/
│   │   ├── semgrep/               # wraps semgrep CLI, parses SARIF
│   │   ├── trivy/                 # SCA + container + IaC
│   │   ├── osv/                   # dependency CVEs
│   │   ├── gitleaks/              # secrets
│   │   ├── nuclei/                # DAST templates
│   │   └── zap/                   # optional deep DAST
│   ├── config/
│   │   ├── schema.go              # .sentinel.yml schema + validation
│   │   └── loader.go
│   ├── report/
│   │   ├── sarif.go                # SARIF 2.1.0 output (industry standard)
│   │   ├── json.go
│   │   ├── markdown.go             # human-readable PR comment format
│   │   └── sqlite.go               # local history store
│   └── telemetry/                 # opt-in, anonymized, off by default
├── plugins/                        # scanner binaries fetched/pinned here
├── extension-vscode/                # separate npm package
│   ├── src/
│   │   ├── extension.ts            # activation, commands
│   │   ├── diagnostics.ts          # maps findings -> VS Code Diagnostics API
│   │   ├── codeActions.ts          # "Quick Fix" providers (auto-remediation)
│   │   ├── sidebar/                # Tree view: findings grouped by severity
│   │   ├── statusBar.ts            # live scan status
│   │   └── ipc/                    # talks to sentinel-agent over local socket
│   ├── package.json
│   └── syntaxes/                   # inline decoration styling
├── web/                             # optional cloud dashboard (React)
│   ├── apps/dashboard/
│   └── apps/api/                    # BFF for dashboard
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.cli
│   │   └── Dockerfile.api
│   ├── helm/sentinel-cloud/         # Helm chart for the optional SaaS backend
│   ├── terraform/                   # cloud infra as code (see §8)
│   └── github-actions/sentinel-scan/action.yml
├── rules/                           # custom Semgrep/Nuclei rule packs
├── docs/
├── .sentinel.yml.example
├── go.mod
└── README.md
```

## 4. Core Engine Design

### 4.1 Orchestration flow

1. **Discover** — detect languages, frameworks, manifest files (package.json, go.mod, requirements.txt, Dockerfile, \*.tf) in the repo.
2. **Plan** — select applicable scanner adapters based on discovery (don't run a Python linter on a Go repo).
3. **Execute** — run adapters in parallel, each in a sandboxed subprocess with resource/time limits (prevents a hung scanner from blocking the pipeline).
4. **Normalize** — every adapter's output is converted to a common internal `Finding` struct:

   ```go
   type Finding struct {
       ID          string
       Source      string   // "semgrep", "trivy", etc.
       Rule        string
       Severity    string   // critical/high/medium/low/info
       CWE         string
       File        string
       Line        int
       Message     string
       CVSS        float64
       Reachable   bool     // is the vulnerable code path actually called?
       FixSuggestion *Fix
   }
   ```
5. **Correlate** — the same underlying issue often gets flagged by two tools (e.g., Trivy and OSV both flag the same CVE). Dedup by CVE ID / file+line+rule fingerprint.
6. **Score** — base severity from the tool, adjusted by:
   - reachability analysis (is the vulnerable function actually called in your code, or just present in an unused dependency?)
   - exposure (is this in a public-facing API path vs. internal tooling?)
   - exploit maturity (known public exploit vs. theoretical)
7. **Remediate** — generate concrete fixes:
   - dependency CVEs → suggested version bump + changelog diff
   - SAST findings → suggested code patch (can call an LLM here for context-aware fixes, clearly labeled as AI-suggested, always require human review/approval)
   - secrets → instructions to rotate + `.gitignore`/pre-commit hook suggestion
   - IaC misconfig → corrected Terraform/K8s snippet
8. **Report** — emit SARIF (for GitHub/GitLab native integration), JSON, Markdown (for PR comments), and store history locally (SQLite) or in the cloud backend.

### 4.2 Why wrap existing engines instead of writing your own

Writing a new SAST/DAST engine from scratch is a multi-year effort (this is why Semgrep, CodeQL, ZAP have taken years of dedicated engineering). Wrapping them:

- gets you production-grade detection from day one
- lets you focus engineering effort on the actually novel part: correlation, reachability scoring, developer UX, and remediation
- keeps you compatible with each tool's rule ecosystem (thousands of community rules you don't have to write)

You can still add your *own* custom rules (Semgrep supports custom YAML rules, Nuclei supports custom templates) for org-specific policies.

## 5. CLI Design

```bash
# Install
curl -sSL https://get.sentinel.dev | sh

# Scan current repo (auto-detects stack)
sentinel scan

# Scan specific categories
sentinel scan --only sast,secrets

# Scan a running app (DAST)
sentinel scan --target https://staging.myapp.com --dast

# CI mode — fail build on critical/high, output SARIF for GitHub code scanning
sentinel scan --ci --fail-on=high --format sarif --out results.sarif

# Watch mode — rescans changed files on save (used by the IDE extension under the hood)
sentinel watch

# Explain + fix a specific finding
sentinel explain SENT-0423
sentinel fix SENT-0423 --apply

# Resilience/DDoS posture check (static config + load-pattern analysis, not an active attack — see §9)
sentinel scan --resilience
```

Design principles: fast default scan (<30s for a mid-size repo via parallel execution + incremental caching on unchanged files), sensible defaults, progressive disclosure (summary first, `--verbose` for detail), machine-readable output always available for CI.

## 6. IDE Extension (VS Code) — UI/UX

**Architecture:** the extension is a thin client. It talks to a local `sentinel-agent` background process over a Unix socket/named pipe (keeps the heavy scanning logic in one place, shared between CLI and IDE, and avoids bundling scanner binaries inside the extension itself).

**UX surfaces:**

- **Inline squiggles** — findings appear as native VS Code Diagnostics (red/yellow underlines), so they show up in Problems panel, minimap, and gutter — no custom UI needed for this part, just correct API usage.
- **Quick Fix (lightbulb)** — click a finding → "Sentinel: Apply suggested fix" → shows a diff preview → one-click apply (via `CodeAction` API). Never auto-applies without preview.
- **Sidebar tree view** — findings grouped by Severity → File, with icons per category (lock icon for secrets, bug for SAST, package icon for SCA). Clicking jumps to the line.
- **Status bar item** — shows live scan state ("Sentinel: scanning…", "Sentinel: 3 critical, 12 medium") and last-scan timestamp; click to open the sidebar.
- **Hover provider** — hovering a flagged line shows: rule explanation, CWE link, CVSS score, and a "why this matters" one-liner, so junior devs learn the issue instead of just dismissing it.
- **On-save scanning** for changed files only (incremental), full-repo scan on demand or pre-commit.
- **Secrets never get sent anywhere** — the extension explicitly shows a one-time trust banner on first scan explaining exactly what runs locally vs. what (if anything) is uploaded, with a toggle.

**Design philosophy:** the extension should feel like ESLint/Pylint, not like a separate dashboard you have to context-switch to. Friction kills adoption for security tools — the entire value proposition is "security feedback at the speed of a type error."

## 7. Data Model & Reporting

- **SARIF 2.1.0** as the canonical interchange format — this is what GitHub/GitLab/Azure DevOps all natively render in PR views, so you get free integration with existing code-review UX instead of building your own.
- **Local history**: SQLite file in `.sentinel/history.db` for trend tracking (is this repo getting more or less risky over time) without requiring a cloud account.
- **Cloud mode** (optional): Postgres-backed API, uploads only the normalized `Finding` records (no source code), powers a team dashboard, Slack/Jira integration, and policy-as-code gating ("block merge if any critical finding is unresolved").

## 8. Cloud-Native, Production-Grade Deployment (for the optional SaaS backend)

**Stack:**

- **API:** Go (or Node/TypeScript) stateless service, horizontally scalable
- **DB:** managed Postgres (RDS/Cloud SQL) with read replicas for dashboard queries
- **Queue:** for async scan jobs triggered via CI webhook — Redis/SQS
- **Scan workers:** run in ephemeral, sandboxed containers (gVisor or Firecracker microVMs) — critical because you're executing scanners against untrusted customer code; never share a worker between tenants
- **Object storage:** S3/GCS for SARIF artifacts and scan logs, encrypted at rest
- **Secrets management:** Vault or cloud-native KMS for any tokens the backend holds (GitHub App credentials, etc.) — never store customer secrets found by the scanner itself; those should only ever be referenced by location + redacted hash, never the raw value
- **Auth:** OAuth via GitHub/GitLab App install flow, short-lived scoped tokens
- **Observability:** OpenTelemetry traces, Prometheus metrics, structured logs shipped to Loki/Datadog
- **Infra as code:** Terraform modules per environment (dev/staging/prod), Helm chart for k8s deploy, GitHub Actions for CI/CD with required SAST/SCA/secrets gates on Sentinel's own codebase (dogfood it)
- **Multi-tenancy isolation:** namespace-per-tenant in k8s, network policies denying cross-tenant traffic, strict RBAC

```
GitHub/GitLab Webhook → API Gateway → Queue → Worker Pool (sandboxed, ephemeral)
                                                      │
                                              Postgres + S3
                                                      │
                                          Dashboard API → React Dashboard
```

**Production checklist:**

- Rate limiting + WAF in front of the public API
- Signed webhook verification (GitHub/GitLab signatures)
- Automated dependency/container scanning of Sentinel's own image (via itself)
- Blue/green or canary deploys
- Backups + point-in-time recovery for Postgres
- SOC2-style audit logging for any cloud mode actions, since this product handles security-sensitive metadata

## 9. Important Scope Note on "DDoS/Exploitation"

Two things in your brief are worth separating clearly, since they imply different engineering (and legal) scope:

- **Resilience/posture checks** (in scope, straightforward): static analysis of rate-limiting middleware presence, timeout configs, unbounded-loop/resource-exhaustion patterns, missing request-size limits, absent circuit breakers. This is pattern-matching against config and code — safe, legal, useful, and exactly what tools like Nuclei's misconfiguration templates already do.
- **Active exploitation / live DDoS testing** (needs explicit boundaries): actually firing exploit payloads or load-testing a target for real is only appropriate against infrastructure you own or have explicit written authorization to test (this is what separates legitimate DAST/pentesting from unauthorized attacks under laws like the CFAA). If you want this capability, scope it the way ZAP and Nuclei do: opt-in, require an explicit `--i-have-authorization` style flag, default to safe/passive checks, and never target anything outside a user-declared allowlist. This is standard practice in every legitimate DAST tool and worth keeping as a hard architectural boundary, not an afterthought.

## 10. Build Roadmap

**Phase 1 — CLI MVP (4–6 weeks)** Wrap Semgrep + OSV-Scanner + Gitleaks, build the correlation/dedup layer, SARIF + Markdown output, basic CI GitHub Action.

**Phase 2 — VS Code extension (3–4 weeks)** Diagnostics integration, Quick Fix actions for the simplest categories (dependency bumps, secret rotation reminders), sidebar tree view.

**Phase 3 — DAST + IaC (3–4 weeks)** Add Trivy (containers/IaC) and Nuclei (passive DAST templates only at first), reachability scoring.

**Phase 4 — Remediation + resilience checks (4 weeks)** Auto-fix diff generation, resilience/posture rule pack, pre-commit hook mode.

**Phase 5 — Cloud/team mode (ongoing)** API + dashboard, GitHub App install flow, policy gating, Slack/Jira integrations.

## 11. Immediate Next Steps

1. Pick the orchestrator language (Go is the strongest fit — fast startup, single static binary, great CLI ecosystem via Cobra, easy cross-compilation for the CLI distribution).
2. Stand up adapters for Semgrep + Gitleaks + OSV-Scanner first — these three alone already cover SAST + secrets + SCA and are the fastest path to a genuinely useful MVP.
3. Get SARIF output correct early — it's what makes the tool feel "native" in GitHub/GitLab PRs for free.
4. Build the VS Code extension against a local JSON-RPC/socket API from day one, so CLI and IDE always share one source of truth.
5. Dogfood continuously: run Sentinel on its own repo in CI from commit one.

---

# Master Blueprint — Build-in-One-Go Specification

This section is the exhaustive, implementation-ready spec. Everything above is the "why and shape"; everything below is the "exact what," detailed enough that a single focused build pass (or a small team) can go from empty repo to working v1 without re-deriving decisions mid-build.

## A. Product Definition

**One-line pitch:** Sentinel is a unified security scanner that runs SAST, SCA, secrets, IaC, and DAST checks through one CLI and one IDE extension, correlates the results, scores real risk, and suggests concrete fixes, all without sending source code off the developer's machine by default.

**Primary user:** an individual developer or small team that wants security feedback inside their existing workflow (terminal plus editor plus PR) instead of a separate dashboard they have to remember to check.

**v1 success criteria (what done means for the first buildable release):**

1. `sentinel scan` run on a real multi-language repo completes in under 60 seconds on a warm cache and correctly surfaces at least SAST (Semgrep), secrets (Gitleaks), and SCA (OSV-Scanner) findings, deduplicated.
2. Output is valid SARIF 2.1.0 that GitHub correctly renders in its code-scanning UI.
3. The VS Code extension shows the same findings as inline diagnostics within 2 seconds of a scan completing, with at least one working Quick Fix action (dependency version bump).
4. `sentinel scan --ci --fail-on=high` correctly exits non-zero in a GitHub Actions workflow and blocks a PR via branch protection.
5. No source code or secret values leave the local machine in default mode, verified by a network-egress test in CI.

Everything beyond this is Phase 2+ and explicitly deferred (see Roadmap below for sequencing).

## B. Functional Requirements (detailed)

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-1 | Auto-detect project languages/frameworks from manifest files (package.json, go.mod, requirements.txt/pyproject.toml, pom.xml, Dockerfile, terraform files) | P0 |
| FR-2 | Run Semgrep with the default auto ruleset plus org-custom rules from rules/ | P0 |
| FR-3 | Run Gitleaks against full git history (not just working tree) with an allowlist for known false positives | P0 |
| FR-4 | Run OSV-Scanner against all detected lockfiles | P0 |
| FR-5 | Normalize all adapter output into the shared Finding schema | P0 |
| FR-6 | Deduplicate findings that reference the same CVE/CWE at the same file and line across tools | P0 |
| FR-7 | Compute a risk score per finding (severity times reachability times exposure) | P1 |
| FR-8 | Emit SARIF, JSON, and Markdown report formats | P0 |
| FR-9 | CLI exit codes: 0 = clean/below threshold, 1 = findings above fail-on threshold, 2 = scanner execution error | P0 |
| FR-10 | `sentinel explain <id>` prints rule rationale, CWE reference, and remediation guidance for one finding | P1 |
| FR-11 | `sentinel fix <id> --apply` applies an auto-generated patch after showing a diff and requiring confirmation | P1 |
| FR-12 | VS Code extension surfaces findings as native Diagnostics with correct severity mapping | P0 |
| FR-13 | VS Code Quick Fix for dependency bumps and secret-rotation reminders | P1 |
| FR-14 | Incremental scanning: only re-scan changed files on save, full scan on demand | P1 |
| FR-15 | Trivy adapter for container images and IaC (Dockerfile, Terraform, Kubernetes manifests) | P1 |
| FR-16 | Nuclei adapter for passive DAST templates against a user-specified target URL | P2 |
| FR-17 | Resilience/posture static checks (rate-limit middleware presence, timeout configs, unbounded loops) as a Semgrep custom rule pack, not live traffic generation | P2 |
| FR-18 | `.sentinel.yml` config file for per-repo overrides (ignore paths, severity thresholds, enabled scanners) | P0 |
| FR-19 | Pre-commit hook mode (`sentinel install-hooks`) | P2 |
| FR-20 | Optional cloud sync of findings (never raw code) for team dashboards | P3 |

## C. Non-Functional Requirements

- **Performance:** cold scan of a 50k-LOC repo under 90s; warm/incremental scan under 10s for a single changed file.
- **Privacy:** zero network calls during a local scan except scanner-binary version checks (opt-out-able via `--offline`).
- **Reliability:** a single scanner adapter crashing must not fail the whole run, partial results plus a clear warning instead.
- **Portability:** single static CLI binary for macOS (amd64/arm64), Linux (amd64/arm64), Windows (amd64).
- **Extensibility:** adding a new scanner adapter should require implementing one Go interface (Adapter) and registering it, no changes to the orchestrator core.
- **Security of the tool itself:** the CLI must never shell out with unsanitized user-controlled strings; all subprocess invocations use argument arrays, never string-concatenated shell commands.

## D. Core Data Schema

```go
// internal/orchestrator/finding.go
type Finding struct {
    ID            string    // stable hash of Source+Rule+File+Line
    Source        string    // "semgrep" | "trivy" | "osv" | "gitleaks" | "nuclei"
    Category      string    // "sast" | "sca" | "secret" | "iac" | "dast" | "resilience"
    Rule          string
    Severity      string    // critical | high | medium | low | info
    CWE           string
    CVE           string    // empty if not applicable
    CVSS          float64
    File          string
    LineStart     int
    LineEnd       int
    Message       string
    Reachable     *bool     // nil = unknown/not computed
    Exposed       *bool     // nil = unknown
    RiskScore     float64   // computed, 0-100
    FixSuggestion *Fix
    FirstSeen     time.Time
    Fingerprint   string    // for cross-scan dedup/tracking over time
}

type Fix struct {
    Kind        string // "dependency-bump" | "code-patch" | "config-patch" | "manual-action"
    Description string
    Diff        string // unified diff, empty for manual-action
    Confidence  string // "high" | "medium" | "low"
}
```

**SQLite local history schema (`.sentinel/history.db`):**

```sql
CREATE TABLE scans (
  id INTEGER PRIMARY KEY,
  started_at TIMESTAMP,
  finished_at TIMESTAMP,
  commit_sha TEXT,
  total_findings INTEGER,
  critical_count INTEGER,
  high_count INTEGER
);
CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id INTEGER REFERENCES scans(id),
  fingerprint TEXT,
  category TEXT,
  severity TEXT,
  file TEXT,
  line_start INTEGER,
  risk_score REAL,
  status TEXT -- "open" | "fixed" | "ignored" | "false_positive"
);
```

## E. Config File Spec (.sentinel.yml)

```yaml
version: 1
scanners:
  sast: { enabled: true, ruleset: auto, extra_rules: ["rules/org-policies.yml"] }
  secrets: { enabled: true, scan_history: true }
  sca: { enabled: true, fail_on_license: ["GPL-3.0"] }
  iac: { enabled: true }
  dast: { enabled: false, target: null }
  resilience: { enabled: false }
ignore:
  paths: ["vendor/", "**/*_test.go", "testdata/"]
  findings: ["SENT-legacy-001"] # explicit suppressions with required justification comment
thresholds:
  fail_on: high  # critical | high | medium | low
output:
  formats: [sarif, markdown]
  path: ".sentinel/reports/"
cloud:
  enabled: false
  endpoint: null
```

## F. CLI to IDE IPC Contract

The VS Code extension never re-implements scanning logic; it talks to the local `sentinel-agent` daemon over a Unix domain socket (named pipe on Windows) using JSON-RPC 2.0:

- `scan.run({ paths: string[], incremental: bool }) -> { scanId: string }`
- `scan.status({ scanId }) -> { state: "running"|"done"|"error", progress: number }`
- `findings.list({ scanId, file?: string }) -> Finding[]`
- `fix.preview({ findingId }) -> { diff: string }`
- `fix.apply({ findingId }) -> { success: bool, appliedDiff: string }`
- `events.subscribe()` — server-push stream for live diagnostics updates as incremental scans complete

This same IPC surface is what a future JetBrains/Neovim extension would reuse — keep IDE-specific code limited to translating this contract into each editor's native diagnostics API.

## G. VS Code Extension — package.json Contribution Points

```jsonc
{
  "contributes": {
    "commands": [
      { "command": "sentinel.scanWorkspace", "title": "Sentinel: Scan Workspace" },
      { "command": "sentinel.scanFile", "title": "Sentinel: Scan Current File" },
      { "command": "sentinel.showFindingDetails", "title": "Sentinel: Explain Finding" }
    ],
    "views": {
      "sentinel-sidebar": [{ "id": "sentinel.findings", "name": "Findings" }]
    },
    "viewsContainers": {
      "activitybar": [{ "id": "sentinel-sidebar", "title": "Sentinel", "icon": "media/shield.svg" }]
    },
    "configuration": {
      "properties": {
        "sentinel.scanOnSave": { "type": "boolean", "default": true },
        "sentinel.cloudSync": { "type": "boolean", "default": false }
      }
    }
  }
}
```

## H. Testing Strategy

- **Unit tests:** every adapter's output parser tested against recorded real tool output fixtures (golden files) — catches upstream format changes without needing to run the actual scanner in CI.
- **Integration tests:** a small corpus of intentionally-vulnerable sample repos (one per language) checked into `testdata/`, asserting expected finding counts per category.
- **Golden SARIF tests:** validate emitted SARIF against the official schema on every build.
- **Extension tests:** `@vscode/test-electron` headless runs verifying diagnostics appear correctly for a fixture workspace.
- **Security self-tests:** CI step that runs Sentinel against its own codebase and fails the build on any new critical/high finding (dogfooding as a gate, not just a demo).
- **Egress test:** a CI job that runs a default scan inside a network-namespace with only loopback allowed, asserting it still completes — proves the "no code leaves the machine" claim rather than just asserting it in docs.

## I. CI/CD Pipeline (for Sentinel's own repo)

```
on: [push, pull_request]
jobs:
  lint-and-unit:   go vet, go test ./..., npm test (extension)
  build-matrix:    cross-compile CLI for darwin/linux/windows x amd64/arm64
  integration:     run build output against testdata/ fixtures, diff expected findings
  self-scan:       sentinel scan --ci --fail-on=high (gate)
  release (tag):   goreleaser -> GitHub Releases + Homebrew tap + extension VSIX -> VS Code Marketplace
```

## J. Deployment Runbook (step-by-step, CLI + optional cloud)

1. `git init sentinel && cd sentinel` — scaffold per the file structure earlier in this doc.
2. `go mod init github.com/<you>/sentinel`; add Cobra for the CLI command tree.
3. Vendor scanner binaries via a `plugins/install.sh` that pins exact versions (Semgrep, Gitleaks, OSV-Scanner, Trivy) — never fetch "latest" at runtime, to keep scans reproducible and supply-chain-safe.
4. Implement adapters one at a time, each with `Run(ctx, repoPath) ([]Finding, error)` plus a golden-file parser test, in this order: Gitleaks, then OSV-Scanner, then Semgrep (ascending complexity of output parsing).
5. Implement the correlation/dedup layer and the SARIF writer; validate output with the official SARIF validator.
6. Build the CLI command tree (`scan`, `explain`, `fix`, `watch`) wired to the orchestrator.
7. Package as a single static binary with `goreleaser`; publish to a Homebrew tap and a plain curl-installer script.
8. Scaffold the VS Code extension (`yo code` generator), implement the IPC client against `sentinel-agent`, wire Diagnostics plus sidebar.
9. Publish the extension to the VS Code Marketplace (free, just needs a publisher account plus `vsce publish`).
10. Wire the GitHub Action (`deploy/github-actions/sentinel-scan`) and document the branch-protection setup for `--fail-on`.
11. Only once local mode is solid: stand up the optional cloud backend — Terraform apply for VPC/DB/compute, Helm install for the API, GitHub App registration for webhook-triggered scans.
12. Add monitoring (Prometheus plus Grafana or a managed equivalent) before accepting real external traffic to the cloud backend.

## K. Milestone Timeline (solo/small-team pace)

| Week | Deliverable |
| --- | --- |
| 1 | Repo scaffold, CLI skeleton, Gitleaks adapter working end-to-end |
| 2 | OSV-Scanner + Semgrep adapters, Finding schema, dedup logic |
| 3 | SARIF + Markdown output, GitHub Action, first self-scan passing in CI |
| 4 | sentinel-agent daemon + IPC contract, VS Code extension skeleton with Diagnostics |
| 5 | Quick Fix actions (dependency bump), sidebar tree view, incremental scan-on-save |
| 6 | Trivy (IaC/containers) adapter, risk scoring (reachability heuristic v1) |
| 7 | Polish, docs, Homebrew/Marketplace publishing, public v1 release |
| 8+ | Phase 3/4 items from the earlier roadmap (DAST, resilience rules, cloud mode) |

## L. Risk Register

| Risk | Mitigation |
| --- | --- |
| Scanner binary upstream breaking changes | Pin exact versions, golden-file tests catch output-format drift |
| False positives eroding developer trust | Confidence field on every Fix, easy one-click suppression with required justification, track suppression rate as a product metric |
| Auto-fix applying a bad patch | Always preview-before-apply, never auto-commit, confidence threshold before even suggesting |
| Scope creep into active exploitation/DDoS testing | Hard architectural boundary — passive checks only by default, explicit opt-in flag for anything active, documented authorization requirement |
| Cloud backend becoming a juicy target (aggregates vuln data across many repos) | Local-first default, minimal data retention, encrypt at rest, strict tenant isolation |

This is the complete build-ready spec. The natural next step once code exists: feed real scan output back into the Finding schema to validate the dedup/scoring logic against actual noisy multi-tool output, since that correlation layer is the part no off-the-shelf tool does for you.
