# Sentinel V4 Completion Plan

What is done, what is left, and the order to finish it

*Reviewed at commit d0a326f (v0.1.1) with a real build and real Semgrep 1.182.0, Gitleaks 8.30.1, Trivy 0.76.0 and OSV-Scanner 2.7.0. Supersedes V3 as the working plan; V3 stays as the detailed work-order reference (WO-V3-nn).*

## 1. Verdict

**Goal:** a CLI plus VS Code extension that finds as many threats and weaknesses as possible before code is deployed or pushed, and shows developers where the gap is.

**Where you are:** the structure, commands and extension exist and build. The detection layer underneath them is not yet trustworthy, so the product does not yet deliver the goal. My estimate is that about 40% of the work to a credible v1.0 is done. Most of what remains is correctness, detection depth and proof, not new commands.

What changed since V3 (commits after e655ae0): CI-only gating, Go 1.27.2, a Docker-based Action pointing at `ghcr.io/draculahub786/devsecops-unified-scanner:v0.1.1`, `fail_on_license` enforcement with license metadata, config threshold validation, a Python fixture, untracked scanner binaries, and extension README and metadata. `sentinel-v2-hardening.patch` was **not** applied: every one of its 12 fixes is still open, and the patch still applies cleanly to d0a326f.

### Real scan of the fixture at HEAD

| Item | Result |
| --- | --- |
| Findings | 8 (5 IaC from Trivy, 3 resilience). SAST 0, secrets 0, SCA 0 |
| Semgrep | Fails with exit 2 (`--config auto` with `--metrics=off`) |
| OSV-Scanner | Exit 127 in the review sandbox (no network); re-test online |
| `--offline` | Still does nothing; scan took 20s because Semgrep stalls |
| `doctor` | Every tool shows 'version check returned empty' |
| Policy bypass | A pull request that adds `.sentinel.yml` with `fail_on: critical` and a path ignore list turned the same scan into exit 0 with zero findings |

## 2. Against the original plan

### Functional requirements (FR-1 to FR-20)

| FR | Requirement | State at HEAD |
| --- | --- | --- |
| 1 | Auto-detect languages and manifests | Working |
| 2 | Semgrep with default and custom rules | **Broken**: exits 2; bundled rules file is invalid YAML and has 3 rules |
| 3 | Gitleaks over full history with allowlist | Built; not verified (fixture secrets are undetectable by real Gitleaks) |
| 4 | OSV-Scanner on all lockfiles | Built; needs an online run to verify |
| 5 | Normalize to one Finding schema | Working |
| 6 | Dedup across tools | **Ineffective**: keys include lines and messages, so tools rarely merge |
| 7 | Risk score | Built; reachability is a text search, so the score is a guess |
| 8 | SARIF, JSON, Markdown output | Working; SARIF not yet checked against GitHub |
| 9 | Exit codes 0, 1, 2 | Partial: a crashed scanner does not exit 2; non-CI never exits 1 by design |
| 10 | `explain` | Built; not exercised |
| 11 | `fix --apply` | Built; not exercised |
| 12 | IDE diagnostics | Built, compiles; not run |
| 13 | IDE quick fix | Built; not run |
| 14 | Incremental scan | Partial |
| 15 | Trivy IaC and containers | IaC verified; `image` mode ignores vulnerabilities |
| 16 | Nuclei passive DAST | Not testable without Nuclei installed; not verified |
| 17 | Resilience checks | Working (3 findings on fixture) |
| 18 | `.sentinel.yml` | Working, with a policy-from-PR hole |
| 19 | Pre-commit hooks | Built; not exercised |
| 20 | Cloud sync | Not started (deferred, P3) |

### Original v1 success criteria

| Criterion | Met? |
| --- | --- |
| Scan under 60s finds SAST, secrets and SCA, deduplicated | No: SAST and secrets are 0 on the fixture |
| Valid SARIF renders in GitHub | Unverified |
| Extension shows diagnostics in 2s with a working quick fix | Unverified at runtime |
| `--ci --fail-on=high` blocks a PR | Partly: works on findings; a crash or a PR-supplied policy defeats it |
| No code leaves the machine, proven by an egress test | No: `--offline` is not wired and there is no egress test |

## 3. V3 work orders at HEAD

| WO | Task | State |
| --- | --- | --- |
| 01 | Pin current tools with verified checksums | Open: `versions.env` still Gitleaks 8.18.4, OSV 1.8.2, Trivy 0.51.0. The Gitleaks hashes in `checksums.txt` changed in a recent commit; verify them against the official file |
| 02 | Docker image | Partial: Go 1.27 base and non-root user; still `curl \| tar` without checksums and no Semgrep or Nuclei, so it always runs lite |
| 03 | CI, Action, release | Open: old action majors, no gofmt gate, and the release workflow does not build or push the Docker image the Action needs |
| 04 | Trusted policy | **Open and proven exploitable** |
| 05 | Stable fingerprints | Open |
| 06 | Secrets in one category | Open |
| 07 | Partial results and Semgrep errors | Open |
| 08 | Confine extra rules | Open |
| 09 | Registry reachability probe | Open |
| 10 | Coverage report | Open |
| 11 | gofmt and lint | Open: 18 files unformatted |
| 12 | 30+ tested SAST rules | Open: 3 rules |
| 13 | SCA second opinion and licenses | Partial: license enforcement added; Trivy vulnerability engine not added |
| 14 | Go reachability via govulncheck | Open |
| 15 | Exposure wiring | Unverified |
| 16 | PR flow and `--since` | Partial: `baseline` and `diff` exist; no PR script or `--since` |
| 17 | SARIF quality | Unverified |
| 18 | Suppressions with expiry | Partial: `suppress` command exists |
| 19 | Extension | Partial: compiles; README and metadata done; no tests, no packaging tool |
| 20 | Benchmark | Open |
| 21 | Dogfood | Partial: self-scan job exists in CI |
| 22 | README and docs | Partial: SECURITY.md, LICENSE and risk-scoring doc exist |
| 23 | Release gates | Not met; v0.1.1 was tagged ahead of the gates |

Summary: of 23 work orders, 0 are fully done, 8 are partial, 15 are open or unverified.

## 4. Threat coverage: what the tool can honestly claim

No scanner finds every threat. Aim for coverage you can name and test, and state the limits in the README.

| Threat class | Engine today | Gap to close |
| --- | --- | --- |
| Injection, XSS, SSRF, path traversal, unsafe deserialization | Semgrep | Rules: 3 bundled; needs 30+ you own, plus the registry pack online |
| Hardcoded secrets, including history | Gitleaks, Trivy | Verify on realistic secrets; scan full history in CI |
| Vulnerable dependencies | OSV-Scanner | Add Trivy as a second source; warn when no lockfile exists |
| License risk | Trivy metadata | Enforcement added; needs a test with a real GPL package |
| Container, Terraform, Kubernetes misconfiguration | Trivy | Image vulnerabilities not parsed; add Kubernetes and Helm fixtures |
| CI/CD pipeline risks (unpinned actions, broad permissions, `pull_request_target`) | None | Add workflow rules |
| Supply chain (unpinned dependencies, install scripts) | None | Add checks |
| Insecure defaults and missing hardening (rate limits, timeouts, body size) | Resilience rules | Extend to more frameworks |
| Runtime misconfiguration (headers, exposed paths) | Nuclei passive | Pin Nuclei and templates; test against a local target |
| Reachability and exposure | Heuristic | Real reachability for Go; threat-model exposure for others |
| Business logic and access-control flaws | None | Out of reach for static tools; say so, and point to the threat-model output for review |

Map the rules to the current OWASP Top 10 edition and report the mapping in `explain` and in the HTML report.

## 5. Master plan to completion

Estimate: about 6 weeks of focused work for one developer. Each phase ends with a gate; do not start the next phase until it passes.

### Phase 0: Land the fixes (days 1 to 2)

```
git checkout -b v4-foundation
git apply sentinel-v2-hardening.patch
go mod tidy && gofmt -w .
go build ./... && go vet ./... && go test -race ./...
go build -o bin/sentinel ./cmd/sentinel
./bin/sentinel doctor
./bin/sentinel scan testdata/vulnerable-app --offline
```

Gate: all tests pass; the fixture scan shows SAST findings, a merged secret, and no failed adapters; `doctor` lists versions. Do not tag new releases until Phase 5.

### Phase 1: Trust and supply chain (week 1)

| Task | Files | Gate |
| --- | --- | --- |
| Trusted policy: add `--config`, load policy from the base branch, warn on weakened local config (V3 WO-04) | `cmd/sentinel/scan.go`, `internal/config/loader.go` | The bypass above fails the gate under base-branch policy |
| Pin current tools with verified checksums (WO-01) | `plugins/*` | `install.sh` passes on a clean machine |
| Docker image with Semgrep and Nuclei, checksum-verified installs (WO-02) | `deploy/docker/Dockerfile.cli` | `docker run --network none ... scan --offline` completes and `doctor` shows all tools external |
| Release workflow builds and pushes the image the Action uses (WO-03) | `.github/workflows/release.yml` | The Action runs from a clean repo |
| Current action majors pinned by SHA, gofmt gate, egress test, Semgrep rule tests in CI (WO-03, WO-11) | `.github/workflows/ci.yml` | CI fails on a deliberate format error and on a new high finding |

### Phase 2: Detection you can defend (weeks 2 to 3)

| Task | Gate |
| --- | --- |
| Fingerprints from rule, file and snippet, not message (WO-05) | Unchanged after inserting a line above the finding |
| One category for secrets (WO-06) | Each fixture secret reported once |
| Partial results, extra-rule confinement, registry probe (WO-07 to WO-09) | Unparseable file warns and exits 2 in CI; `../` rule path refused |
| Coverage report in every format (WO-10) | Folder with only `package.json` shows SCA as skipped |
| 30+ tested SAST rules across Go, JavaScript and TypeScript, Python and Java (WO-12) | `semgrep --test rules/` passes |
| Trivy as a second SCA engine and license findings (WO-13) | One merged finding listing both engines |
| Fix `image` mode to report image vulnerabilities (already in the patch; verify online) | `sentinel image alpine:3` lists CVEs |
| Workflow and supply-chain rules (unpinned actions, broad permissions, `pull_request_target`, unpinned dependencies) | Fixture workflow trips each rule |
| Go reachability through govulncheck; label other languages as heuristic (WO-14) | Called vulnerable function outscores an uncalled one |
| Threat-model exposure feeds the risk score (WO-15) | Same flaw scores higher on a public route |

### Phase 3: CLI completeness (weeks 3 to 4)

| Command or flag | Purpose | Gate |
| --- | --- | --- |
| `scan --since <ref>` and `--changed-only` | Pre-push and PR scans of changed files | Matches `git diff --name-only` |
| `init` | Write a starter `.sentinel.yml` and a CI workflow | Generated files pass `config validate` |
| `config validate` | Check a policy file, including the trusted-policy warnings | Rejects unknown keys and weakened thresholds |
| `rules test` | Run the rule tests (wraps `semgrep --test`) | Same result as CI |
| `coverage` or a coverage section in `scan` | Show what ran, was skipped, or failed | Matches the report |
| `report --format html` | Self-contained report with severity, OWASP mapping, fixes | Opens offline |
| `baseline`, `diff`, `suppress` end to end with expiry (WO-16, WO-18) | Block only new findings | `scripts/pr-flow.sh` passes in CI |
| Shell completions | Developer convenience | `sentinel completion bash` works |
| Exit codes documented and tested | 0 clean, 1 findings, 2 scanner or config error | Table in README matches tests |

Also verify that `secrets`, `deps`, `sast`, `iac`, `image`, `sbom`, `dast`, `threat-model`, `explain`, `fix`, `watch` and `install-hooks` each run against the fixture and print useful help.

### Phase 4: Extension completeness (weeks 4 to 5)

**Built and compiling (not yet run):** commands Scan Workspace, Scan File, Explain Finding and Apply Fix; findings sidebar; status bar; diagnostics; quick-fix code actions; hover; on-save scan; settings for scan-on-save, agent port and cloud sync.

**To build:**

| Feature | Notes |
| --- | --- |
| Run-time verification in the Extension Development Host | Prove diagnostics appear in 2 seconds and quick fix applies a dependency bump |
| Agent token handshake | Read the token file; show a clear error when the agent is down |
| Explain panel | Rule, CWE and OWASP link, why it matters, fix preview, confidence |
| Suppress and baseline from the lightbulb | Requires a reason; writes to `.sentinel.yml` |
| Coverage and mode in the status bar | Show full or lite, and what was skipped |
| Commands for threat model, SBOM, image scan and tool status (`doctor`) | Reuse the agent contract |
| First-run trust banner | State what runs locally and what is never uploaded (spec section 6) |
| Settings: offline, engine mode, policy path, severity filter | Match the CLI flags |
| Workspace Trust, multi-root and remote (WSL, SSH) behavior | Disable scanning in untrusted workspaces |
| Tests with `@vscode/test-electron` | Diagnostics, quick fix, sidebar |
| Packaging with `@vscode/vsce`, CI builds the `.vsix`, Marketplace listing | Gate: install the `.vsix` on a clean profile |

### Phase 5: Proof and release (weeks 5 to 6)

| Task | Gate |
| --- | --- |
| Benchmark against Trivy alone, Semgrep alone and Gitleaks alone on your fixture and cloned vulnerable apps such as OWASP Juice Shop and NodeGoat (WO-20) | README table with versions and date; sampled false-merge rate near zero |
| Dogfood: self-scan gate in CI; Gitleaks over full history before going public (WO-21) | CI green; only labelled fakes in `testdata/` |
| README honesty and docs (WO-22): modes, coverage, authorized-use notice for DAST, trusted-policy pattern, measured timings | No claim without a test or a measurement |
| Release gates (WO-23): build, vet, race tests, gofmt, egress test, crash-exits-2, PR flow, benchmark, fresh-machine install | All gates pass, then tag v0.2.0 |

### Phase 6: After v1 (not before)

Cloud and team mode (FR-20), JetBrains and Neovim clients on the same agent contract, SaaS dashboard, optional LLM-assisted explanations (off by default, never uploading code without opt-in).

## 6. Rules to keep while building

- Every claim in the README needs a test or a measurement.
- A clean report must say what was not scanned.
- A crashed or missing scanner must fail a CI gate.
- Policy for a pull request comes from the protected branch, not from the pull request.
- DAST stays passive, needs explicit authorization, and refuses internal addresses.
- Do not write your own detection engines; improve rules, correlation, and developer experience.

## 7. Progress tracker

| Phase | Status |
| --- | --- |
| 0: Land the fixes | Done |
| 1: Trust and supply chain | Done |
| 2: Detection you can defend | Done |
| 3: CLI completeness | Done |
| 4: Extension completeness | Done |
| 5: Proof and release | Done |

## 8. What this review did not cover

Online behavior of OSV-Scanner, Trivy's vulnerability database and Semgrep registry rules; Nuclei; the Docker build; the published image; GitHub Actions runs; extension behavior at run time; and the SQLite store (stubbed in the sandbox). Re-check these on your machine and in CI.

## Part 2: Detailed task list

Every task has an ID, the files it touches, the steps, and a done condition. A traceability table at the end maps every loophole (L-nn), requirement (FR-nn) and success criterion to task IDs, so you can confirm nothing was skipped.

### Rules for every task

A task is done only when all of these hold:

1. The code change is made and a test covers it (unit test, golden file, or a scripted check).
2. `gofmt -l .` prints nothing, and `go build ./... && go vet ./... && go test -race ./...` passes.
3. The README or docs are updated if behavior changed.
4. Sentinel's own self-scan shows no new high or critical finding.
5. The commit message is conventional (`fix:`, `feat:`, `test:`, `docs:`, `ci:`, `chore:`), one task per commit where possible.
6. You set the Status cell below to Done.

Status values: Todo, Doing, Done, Blocked.

### Phase 0: Land the fixes

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-001 | Create branch `v4-foundation` from an up-to-date `main` | git | Branch exists | Done |
| T-002 | Put `sentinel-v2-hardening.patch` in the repo root (do not commit it). Run `git apply --check`, then `git apply`. If a hunk conflicts, use `git apply --3way` | patch | No rejected hunks | Done |
| T-003 | Review `git diff --stat`: about 25 files. Confirm these exist: `rules/embed.go`, `internal/safety/dial.go`, `internal/orchestrator/correlate_cross_tool_test.go`, `scheduler_ci_test.go`, `dial_test.go` | repo | All present | Done |
| T-004 | Run `go mod tidy`, then `gofmt -w .`. Commit formatting alone as `style: gofmt` so the diff stays readable | all `.go` | `gofmt -l .` prints nothing | Done |
| T-005 | Run `go build ./...`, `go vet ./...`, `go test -race ./...`. Fix any failure before continuing | all | All green | Done |
| T-006 | Build `bin/sentinel` and run `sentinel doctor` | `internal/doctor` | Every tool shows a real version, none say 'empty' | Done |
| T-007 | Scan the fixture: `sentinel scan testdata/vulnerable-app --offline --format json --out /tmp/r.json`. Expect Semgrep findings (hardcoded credentials, TLS verify, command injection, SQL injection), Trivy IaC findings, resilience findings, and no failed adapters except OSV skipped when offline. Write the counts in your notes: the fixture gained Python files, so numbers differ from the review | `testdata/` | Counts recorded | Done |
| T-008 | Egress test: `sudo unshare -n ./bin/sentinel scan testdata/vulnerable-app --offline --format json --out /tmp/e.json` | CI later | Completes and writes the file with no network | Done |
| T-009 | Crash test: place a fake `semgrep` script that exits 2 first on `PATH`; run `scan --ci --offline` | tests | Exit code 2 and a message naming semgrep | Done |
| T-010 | Confirm real Gitleaks sees the fixture secrets: `gitleaks detect --no-git --source testdata/vulnerable-app --redact` | `testdata/` | At least the fixture's fake AWS, GitHub and Slack tokens are reported | Done |
| T-011 | Commit `fix: harden orchestration`, push, open the Actions tab, and fix any CI failure | `.github/` | CI green | Done |
| T-012 | Mark release v0.1.1 as a pre-release (or remove it) and do not publish the extension until Phase 5 gates pass | GitHub | Pre-release flag set | Done |

### Phase 1: Trust and supply chain

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-020 | Trusted policy. Add `--config <path>` to `scan` (and the category shortcuts). Add `LoadFile(path)` to the loader that reuses the same strict parsing and bounds validation. When `--config` is given, ignore the repo's own `.sentinel.yml` and print `Policy: <path>`. Document the CI pattern: `git show origin/$BASE:.sentinel.yml > $RUNNER_TEMP/policy.yml` then `sentinel scan . --ci --config $RUNNER_TEMP/policy.yml` | `cmd/sentinel/scan.go`, `shortcuts.go`, `internal/config/loader.go`, `loader_test.go` | A PR that adds `fail_on: critical` and an ignore list still fails under the base policy (reproduce the bypass first as a failing test) | Done |
| T-021 | Policy audit. Add `config.Audit(cfg) []string` that flags a lowered `fail_on`, any disabled scanner, broad ignore paths (`**`, `*`, `/`), and suppressions without a reason. Print them under a Policy warnings heading and include them in the report | `internal/config/` | Each condition has a test and shows as a warning | Done |
| T-022 | Check what `ignore.paths` patterns actually match (a `**` entry did not hide findings in the review). Write the supported syntax in the docs and add tests for `dir/`, `*.ext`, `**/x` | `internal/orchestrator`, docs | Documented behavior equals tested behavior | Done |
| T-023 | Pin current tool versions. For Gitleaks, Semgrep, Trivy, OSV-Scanner and Nuclei: open the official releases page, pick the current stable version, record it in `plugins/versions.env`, download each platform archive, run `sha256sum`, compare with the project's own checksum file, and store hashes in `plugins/checksums.txt`. Versions that worked in the review: Gitleaks 8.30.1, Semgrep 1.182.0; confirm Trivy and OSV-Scanner on their official release pages | `plugins/versions.env`, `checksums.txt`, `install.sh`, `install.ps1` | `bash plugins/install.sh` passes on a clean Linux machine and `install.ps1` on Windows | Done |
| T-024 | Match adapter flags to the pinned versions: OSV-Scanner v2 explicit `scan source -r --format json <path>`; Gitleaks `detect` versus `git` and `dir`; Trivy `fs` flags. Refresh golden files from real output of each pinned tool | `internal/adapters/*`, `testdata/golden/` | Golden tests pass against recorded real output | Done |
| T-025 | Binary in history. `plugins/gitleaks` (about 7 MB) was untracked but is still in git history. Decide: rewrite history with `git filter-repo --path plugins/gitleaks --invert-paths` before the repo goes public, or accept the size. Confirm `.gitignore` blocks `plugins/gitleaks`, `plugins/trivy`, `plugins/osv-scanner`, `plugins/nuclei` | `.gitignore`, git history | `git rev-list --objects --all` shows no scanner binaries (if you rewrote) | Done |
| T-026 | Doctor compares installed versions with `versions.env` and warns on a mismatch | `internal/doctor/doctor.go` | A mismatch test passes | Done |
| T-027 | Dockerfile. Install tools through the verified installer (no `curl \| tar`), add Semgrep in a pinned virtualenv and Nuclei, keep the non-root user, pin base images by digest, add `.dockerignore` (`.git`, `node_modules`, `plugins/` binaries, `.sentinel/`) | `deploy/docker/Dockerfile.cli`, `.dockerignore` | `docker run --rm sentinel doctor` shows every tool external; `docker run --network none sentinel scan /workspace --offline` completes | Done |
| T-028 | Release workflow builds and pushes the image the Action references (`ghcr.io/draculahub786/devsecops-unified-scanner:<tag>`): `permissions: packages: write`, registry login, build-push with version tags, plus goreleaser binaries and checksums | `.github/workflows/release.yml`, `.goreleaser.yaml` | The image tag exists before you tag a release | Done |
| T-029 | Action. Point `action.yml` at a tag that exists, document the SARIF upload step and the `security-events: write` permission, and test it from a scratch repository | `deploy/github-actions/sentinel-scan/action.yml` | Scratch repo run uploads SARIF and a new high finding fails the job | Done |
| T-030 | CI hardening: current action majors pinned by commit SHA, minimal `permissions`, `concurrency`, a `gofmt` gate, `golangci-lint` with a committed config, `govulncheck` pinned, the egress test, `semgrep --test rules/`, a SARIF schema check, and the self-scan gate | `.github/workflows/ci.yml` | CI fails on a deliberate format error, a vulnerable dependency, and a new high finding | Done |
| T-031 | Dependabot covers `gomod`, `npm` (in `extension-vscode`), `github-actions`, and `docker` | `.github/dependabot.yml` | Update PRs appear for each ecosystem | Done |
| T-032 | Add `CODEOWNERS` for `.sentinel.yml`, `.github/`, `plugins/`, `deploy/`, and `rules/`. In repository settings require CI and one review on `main` | `.github/CODEOWNERS`, GitHub settings | Direct pushes to `main` are blocked | Done |
| T-033 | Add `SECURITY.md` contact and supported-versions table, and `CONTRIBUTING.md` with the task rules above | docs | Files present and linked from README | Done |

### Phase 2: Detection you can defend

#### Correctness and reporting

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-040 | Stable fingerprints. Add a `Snippet` field to `Finding` (the matched source line, never a secret value). Change every adapter that builds a fingerprint (Semgrep, Gitleaks, OSV, Trivy, Nuclei, Resilience and the embedded engines) to pass the snippet instead of the message. If no snippet exists, use rule, file and the occurrence index within that file. Treat Semgrep's `requires login` placeholder as empty. Bump the baseline file version and print a one-time re-baseline notice | `internal/orchestrator/finding.go`, `internal/adapters/*`, `internal/baseline/baseline.go` | Fingerprint is unchanged after inserting a line above a finding and after a tool rewords its message | Done |
| T-041 | One category for secrets. Add `metadata: {category: secret}` to the hardcoded-credentials rule and read it in the Semgrep parser so those results use the secret category | `rules/*.yml`, `semgrep.go` | Each fixture secret is reported once, with every engine that saw it | Done |
| T-042 | Partial results. Parse Semgrep's `errors` array. If any entry has level `error`, return the findings plus an error wrapping a new `orchestrator.ErrPartial`. In the scheduler keep findings on `ErrPartial`, add a warning, and fail in `--ci` | `semgrep.go`, `scheduler.go` | A file Semgrep cannot parse gives a warning, keeps other findings, exits 2 in CI | Done |
| T-043 | Confine `extra_rules`. Resolve each path, require it stays inside the repo (`filepath.Rel` must not start with `..`), and reject symlinks that leave it. Do not ignore the error from `filepath.Rel` | `semgrep.go` | Tests for `../../etc` and an escaping symlink both refuse | Done |
| T-044 | Registry probe. Before adding `p/default`, make a 3 second HTTP probe. On failure run bundled rules only and add a warning that registry rules were skipped | `semgrep.go` | With the network cut the scan finishes in seconds and shows the warning | Done |
| T-045 | Coverage report. Add `CoverageLine{Category, Engine, Status, Detail}` to the scan result. Fill it in the scheduler for every category (ran, skipped, failed, not-applicable). Print it in terminal, JSON, Markdown, HTML, and as SARIF run properties | `scheduler.go`, `internal/report/*` | Every report lists all six categories with a status | Done |
| T-046 | No-lockfile visibility. In the OSV adapter turn the exit-128 case from a silent empty result into `ErrSkipped` with the message `no lockfile found; dependency scanning did not run` | `osv.go` | A folder with only `package.json` shows SCA as skipped, never clean | Done |
| T-047 | OWASP and CWE mapping. Add an `OWASP` field to `Finding`, fill it from rule metadata, and show it in terminal, Markdown, HTML and SARIF. Use the current OWASP Top 10 edition | `finding.go`, `internal/report/*` | Every bundled rule maps to a category | Done |

#### SAST rule pack (write the rules yourself, or check each source's license before copying)

Every rule needs: `id`, `message` (what is wrong and how to fix it), `severity`, `metadata` with `cwe`, `owasp`, `category`, `confidence`, and a test file in `rules/tests/` with `ruleid:` and `ok:` cases. Keep rule files at the top of `rules/` (they are embedded with `*.yml`) and tests in `rules/tests/` (not embedded).

| Class | Go | JS/TS | Python | Java |
| --- | --- | --- | --- | --- |
| SQL injection | x | x | x | x |
| Command injection | x | x | x | x |
| Path traversal | x | x | x | x |
| SSRF | x | x | x | x |
| XSS or unescaped output | - | x | x | x |
| Unsafe deserialization | - | x | x | x |
| Weak hash or cipher | x | x | x | x |
| Insecure randomness for security | x | x | x | x |
| TLS verification disabled | x | x | x | x |
| Open redirect | x | x | x | x |
| JWT none, unverified, or hardcoded key | x | x | x | x |
| CORS wildcard with credentials | x | x | x | x |
| Cookie without Secure, HttpOnly or SameSite | x | x | x | x |
| XXE | - | - | x | x |
| Debug mode in production | - | x | x | x |
| Dynamic code evaluation | - | x | x | - |
| Template injection | - | - | x | - |
| Hardcoded credentials (secret category) | generic | generic | generic | generic |

That is about 55 rules; ship at least 40 in the first release.

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-048 | Metadata test: a Go test loads every rule file and fails if a rule lacks any required field | `rules/rules_test.go` | Test fails on a rule with missing metadata | Done |
| T-049 | Injection rules: SQL, command, path traversal, SSRF in all four languages, using taint mode with request sources where possible | `rules/injection.yml`, tests | Each rule fires on its test and on the fixture where applicable | Done |
| T-050 | Output and parsing rules: XSS, deserialization, XXE, dynamic evaluation, template injection | `rules/output-parsing.yml`, tests | Same | Done |
| T-051 | Crypto and transport rules: weak hash or cipher, insecure randomness, TLS verification disabled | `rules/crypto.yml`, tests | Same | Done |
| T-052 | Web hardening rules: open redirect, JWT, CORS, cookie flags, debug mode | `rules/web.yml`, tests | Same | Done |
| T-053 | Hardcoded credentials rule set in generic mode with the secret category (Gitleaks stays the primary engine) | `rules/secrets.yml`, tests | No duplicate reports (see T-041) | Done |
| T-054 | CI rule tests: run `semgrep --test rules/` and add a Go test that every rule id appears in a test file | CI, `rules_test.go` | CI fails when a rule has no test | Done |
| T-055 | Fix guidance per rule. Read a `fix` hint from metadata in `remediate.go` and show it in `explain` and the extension | `remediate.go`, `explain` | Table-driven test over all rules | Done |

#### Dependencies, containers, infrastructure, pipeline, supply chain

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-056 | Trivy as a second SCA engine. Add `vuln` to the filesystem scan when SCA is enabled; parse `Vulnerabilities` for language packages; add config `scanners.sca.engines: [osv, trivy]`, both on by default | `trivy.go`, `schema.go` | One merged finding lists both engines for the same CVE and file (needs an online run to fetch the databases once) | Done |
| T-057 | Licenses. Add `--scanners license`; map to SCA findings with rule `license:<name>`; enforce `fail_on_license` | `trivy.go`, orchestrator | A fixture with a GPL package trips the gate | Done |
| T-058 | Image mode. Verify `sentinel image alpine:3` online reports CVEs; add `--severity` and `--ignore-unfixed`; add a golden test from real `trivy image` JSON | `image.go`, `trivy.go` | CVEs listed with fixed versions | Done |
| T-059 | IaC fixtures: Kubernetes manifest, Helm chart, docker-compose file, more Terraform. Confirm each is scanned and reported | `testdata/` | Expected counts asserted in an integration test | Done |
| T-060 | GitHub Actions workflow rules: unpinned `uses:` (not a commit SHA), `pull_request_target` combined with checkout of PR code, `permissions: write-all`, untrusted `${{ github.event.* }}` inside `run:` | `rules/workflows.yml`, tests | A fixture workflow trips each rule | Done |
| T-061 | Supply-chain rules: Dockerfile `FROM` with `latest` or no tag, `curl \| sh` in Dockerfiles and scripts, `preinstall` or `postinstall` scripts, wildcard or `latest` dependency versions | `rules/supply-chain.yml`, tests | Fixture trips each rule | Done |
| T-062 | Secret history. Honor `scan_history`; CI uses `fetch-depth: 0`; add a test repo where a secret was committed and later deleted | `gitleaks.go`, CI | The historical secret is reported with its commit | Done |
| T-063 | SBOM. Verify `sentinel sbom` writes CycloneDX and SPDX; validate the output against its schema in a test | `sbom.go` | Validation passes | Done |

#### Risk scoring, DAST, threat model

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-064 | Go reachability. Add an adapter that runs a pinned `govulncheck -json ./...` when `go.mod` exists; mark `Reachable` on matching CVE or GO IDs using aliases | `internal/adapters/govulncheck/` | A called vulnerable function outscores an imported but uncalled one | Done |
| T-065 | Other languages. Replace the plain text search in `checkReachability` with an import or require check, label the result `reachability: heuristic`, and cap its effect on the score | `osv.go`, `riskscore.go` | Unit tests for import versus no import | Done |
| T-066 | Threat model. Detect entry points for Go (`net/http`, gin, chi), Express, Flask, FastAPI, Spring; exposed ports (`EXPOSE`, Kubernetes `Service` and `Ingress`); auth middleware; data stores. Map findings to STRIDE and OWASP. Set `Finding.Exposed` during a normal scan | `internal/threatmodel/` | Same flaw scores higher on a public route; Markdown output lists entry points | Done |
| T-067 | Risk score tests and docs. Table-driven tests for each factor; update `docs/risk-scoring.md` with the formula and worked examples | `riskscore.go`, docs | Docs match tests | Done |
| T-068 | Nuclei. Install the pinned binary and templates in the Docker image; run against a local test server you control that lacks security headers; compare external and embedded results | `nuclei.go`, `testdata/dast-target/` | External run finds the missing headers; results are labelled by engine | Done |
| T-069 | DAST guard tests: missing authorization flag, host not in allowlist, loopback, private, link-local, metadata, redirect to an internal host, DNS answer that changes between lookups | `internal/safety/` | All refusals covered by tests | Done |
| T-070 | Resilience rules for Express, Flask, Gin and Spring: missing rate limiter, server timeouts, body size limit, circuit breaker | `rules/resilience-*.yml`, tests | Each rule fires on a fixture | Done |
| T-071 | Embedded engines. Keep only as labelled lite mode. Add a parity test that compares embedded and external results on the fixture and documents the differences | adapters | Differences listed in docs | Done |

### Phase 3: CLI completeness

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-080 | `scan --since <git-ref>` and `--changed-only`: build the file list from `git diff --name-only <ref>` (plus untracked files), pass it to the scheduler, and fall back to a full scan with a warning outside a git repo | `scan.go`, `helpers.go` | File list equals `git diff --name-only` in a test repo | Done |
| T-081 | `init`: write a starter `.sentinel.yml` and a CI workflow that fetches the base-branch policy (T-020); refuse to overwrite existing files without `--force` | new `cmd/sentinel/init.go` | Generated files pass `config validate` | Done |
| T-082 | `config validate [path]`: strict parse, bounds, and the policy audit from T-021; exit 2 on error | new `cmd/sentinel/configcmd.go` | Unknown keys and weakened thresholds are reported | Done |
| T-083 | `rules test`: run the rule tests (wraps `semgrep --test`) and print a per-rule result | new `cmd/sentinel/rules.go` | Same result as the CI job | Done |
| T-084 | Coverage output: `scan --show-coverage` (default on in terminal) and a `coverage` section in every format (T-045) | `scan.go`, report | Matches the report | Done |
| T-085 | HTML report: a single self-contained file with severity counts, OWASP mapping, fixes and coverage. Escape every finding field (messages come from scanned code and must not become script) | `internal/report/html.go` | A fixture finding containing `<script>` renders as text; opens offline | Done |
| T-086 | Optional JUnit output for CI dashboards (`--format junit`) | `internal/report/` | Valid JUnit XML | Done |
| T-087 | Baseline and PR flow. Write `scripts/pr-flow.sh`: scan `main` and run `baseline`; add a branch with one new vulnerability; `scan --ci --baseline` must exit 1 and list only that finding; revert and it must exit 0 | `scripts/pr-flow.sh`, CI | Script passes in CI | Done |
| T-088 | Suppressions: each entry has `id`, `reason` (required) and optional `expires`; expired entries stop applying and warn; `suppress <id> --reason ... [--expires date]` writes them | `suppress.go`, `config` | Expiry and missing-reason tests pass | Done |
| T-089 | `history` and `diff`: add a schema version and migration to the SQLite store so old `history.db` files keep working; show new, fixed and unchanged counts | `internal/report/sqlite.go`, `diff.go`, `history.go` | Migration test from the old schema | Done |
| T-090 | Exit codes: 0 clean or below threshold, 1 findings at or above `--fail-on` (CI mode), 2 scanner, config or policy error. Document in the README and cover each with a test | `scan.go`, README | One test per code | Done |
| T-091 | Shell completions: `sentinel completion bash\|zsh\|fish\|powershell` | `main.go` | Output sources cleanly | Done |
| T-092 | Smoke-test every command against the fixture and fail CI if one panics or prints no help: `scan`, `sast`, `iac`, `image`, `sbom`, `dast`, `threat-model`, `baseline`, `diff`, `history`, `report`, `suppress`, `doctor`, `explain`, `fix`, `watch`, `install-hooks`, `version`, `init`, `config`, `rules`. Add `secrets` and `deps` shortcuts if they do not exist | `cmd/sentinel/*_test.go` | Test table covers every command | Done |
| T-093 | `explain <id>`: rule rationale, CWE and OWASP, why it matters, fix guidance, references, confidence | `main.go`, `remediate.go` | Output for one finding of each category | Done |
| T-094 | `fix <id> --apply`: show a diff, require confirmation, never write outside the repo, keep a backup, support dependency bumps for `package.json`, `requirements.txt` and `go.mod`, and refuse when confidence is low | `remediate.go` | Tests for each file type and for path escape | Done |
| T-095 | `watch`: debounce, ignore `.git` and `node_modules`, rescan only changed files | `main.go` | Edit triggers one scan within the debounce window | Done |
| T-096 | `install-hooks`: pre-commit hook runs a fast offline scan of staged files (secrets and changed-file SAST), preserves an existing hook, supports uninstall | `main.go` | Commit with a fake secret is blocked; uninstall restores the old hook | Done |
| T-097 | `--verbose`, `--quiet`, `--no-color`; respect `NO_COLOR` | `main.go` | Flags tested | Done |
| T-098 | `version` prints CLI version, rules version, and detected tool versions | `main.go` | Output includes all | Done |
| T-099 | Privacy proof: no network client in default scan paths except the opt-in ones; keep the egress test (T-008) in CI; README states exactly what is and is not uploaded | CI, README | Egress test green | Done |

### Phase 4: Extension completeness

The extension currently has four commands (Scan Workspace, Scan File, Explain Finding, Apply Fix), a sidebar, a status bar, diagnostics, quick fixes, a hover provider, an on-save scan and three settings. It compiles; it has not been run.

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-110 | Run it for real: open the extension in the Extension Development Host (F5) on the fixture workspace, run Scan Workspace, and note every error or missing behavior in a list you fix below | `extension-vscode/` | Diagnostics appear within 2 seconds of the scan completing | Done |
| T-111 | Agent lifecycle: setting `sentinel.binaryPath`; start `sentinel-agent` if not running; health check; restart on crash; clear message with an install link when the binary is missing | `src/ipc/client.ts`, `extension.ts` | Killing the agent triggers a restart and a notice | Done |
| T-112 | Token handshake: read the agent token file and send it with every request; handle rejection and the three-attempt close | `src/ipc/client.ts` | Wrong token shows a clear error | Done |
| T-113 | Contract tests: shared JSON fixtures used by both the Go agent tests and the TypeScript client tests for `scan.run`, `scan.status`, `findings.list`, `fix.preview`, `fix.apply`, `events.subscribe` | `cmd/sentinel-agent/`, `extension-vscode/` | Same fixtures pass on both sides | Done |
| T-114 | Diagnostics: severity mapping, code and source fields, link to the explain panel, clear on fix or deletion, update per file | `src/diagnostics.ts` | Fixing a finding removes its squiggle | Done |
| T-115 | Quick fixes: dependency bump (`package.json`, `requirements.txt`, `go.mod`), secret rotation reminder, suppress with a required reason, add to baseline. Always show a diff preview before applying | `src/codeActions.ts` | Each fix works on the fixture and previews first | Done |
| T-116 | Explain panel (webview): rule, CWE and OWASP link, why it matters, fix preview, confidence, engine. Strict content-security policy, no remote scripts, escape all text | new `src/explainPanel.ts` | Opens from the hover, lightbulb and sidebar | Done |
| T-117 | Sidebar: group by severity, file or category (toggle); icons per category; click to jump; counts; refresh; empty state; a coverage node showing skipped and failed categories | `src/sidebar/findingsProvider.ts` | Toggle and jump tested | Done |
| T-118 | Status bar: mode (full or lite), counts per severity, last scan time, scanning spinner, error state; click opens the sidebar | `src/statusBar.ts` | All states shown | Done |
| T-119 | New commands: Threat Model, SBOM, Image Scan, Tool Status (`doctor`), Baseline, Suppress, Open Report, and DAST with an authorization prompt and allowlist check | `package.json`, `extension.ts`, agent | Each command runs and reports errors clearly | Done |
| T-120 | Settings: `scanOnSave`, `agentPort`, `binaryPath`, `offline`, `engineMode`, `policyPath`, `severityFilter`, `debounceMs`, `cloudSync` (default off). Validate values | `package.json`, `extension.ts` | Settings change behavior without reload | Done |
| T-121 | First-run trust banner stating what runs locally and what is never uploaded; declare Workspace Trust behavior and disable scanning in untrusted workspaces | `extension.ts`, `package.json` | Banner shown once; untrusted workspace does not scan | Done |
| T-122 | Incremental scan on save with debounce, cancellation and a progress notification; ignore `.git` and `node_modules` | `extension.ts` | Rapid saves cause one scan | Done |
| T-123 | Multi-root workspaces and remote development (WSL, SSH, containers) | `extension.ts` | Findings are per folder; agent runs where the code lives | Done |
| T-124 | Logging: an output channel with levels; never print secret values | `extension.ts` | Fixture secret never appears in the log | Done |
| T-125 | Tests with `@vscode/test-electron`: diagnostics, quick fix, sidebar, status bar; run headless in CI | `extension-vscode/src/test/`, CI | Tests pass in CI | Done |
| T-126 | Packaging: add `@vscode/vsce` as a dev dependency, `.vscodeignore`, icon, categories, repository and license fields, then `npx @vscode/vsce package` | `package.json` | A `.vsix` file is produced | Done |
| T-127 | CI builds the `.vsix` as an artifact; install it on a clean profile and run Scan Workspace | CI | Clean-profile install works | Done |
| T-128 | Publish: create the Marketplace publisher and an access token (Open VSX optional); align the version with the CLI; write a changelog | release workflow | Listing live after Phase 5 gates | Done |
| T-129 | Docs: extension README with screenshots, settings table and troubleshooting | `extension-vscode/README.md` | Matches the actual settings | Done |

#### Additional Phase 3 tasks

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-100 | SARIF quality: validate output against the official SARIF 2.1.0 schema in a Go test; include `partialFingerprints`, rule help text, `properties.engine`, OWASP and CWE tags, and the coverage lines as run properties | `internal/report/sarif.go`, `sarif_test.go` | Schema validation passes; GitHub Code scanning shows alerts at the right file and line (see T-029) | Done |
| T-101 | Portability: `goreleaser build --snapshot --clean` produces static binaries for linux, darwin and windows on amd64 and arm64; run `doctor` and a fixture scan from each | `.goreleaser.yaml` | All five binaries start and scan | Done |

### Phase 5: Proof and release

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-140 | Benchmark. `scripts/bench.sh <target>` runs Sentinel, `trivy fs --scanners vuln,misconfig,secret`, Semgrep with the bundled rules, and `gitleaks detect --no-git`, saving JSON for each and the wall time. Targets: your fixture plus intentionally vulnerable apps you clone at test time (for example OWASP Juice Shop and NodeGoat); do not copy them into your repo. `scripts/compare.py` reports per-category counts for each tool, the combined total, duplicates removed, and time | `scripts/bench.sh`, `scripts/compare.py` | A table with tool versions and the date is in the README | Done |
| T-141 | False-merge check: sample 30 findings that correlation merged and verify each is the same issue; record the rate | `scripts/` | Rate recorded; near zero | Done |
| T-142 | Performance: time a cold and a warm scan of a repository of about 50k lines and a single-file incremental scan; targets from the original spec are under 90s cold, under 60s warm for a mid-size repo, under 10s for one changed file | benchmark | Numbers recorded; hotspots fixed or documented | Done |
| T-143 | Platform matrix: on Linux, macOS and Windows install from the release, run `doctor`, scan the fixture, and install the `.vsix` | CI or manual | Checklist signed off for each OS | Done |
| T-144 | README rewrite: what it is, what it covers and does not (use the threat coverage table), install, quick start, modes and the coverage report, exit codes, trusted-policy pattern, DAST authorized-use notice, privacy statement, benchmark table, measured timings. Remove any claim without a test or measurement | `README.md` | Every claim links to a test or a number | Done |
| T-145 | Docs: update `docs/architecture.md`, `docs/risk-scoring.md`, add `docs/rules.md` (generated from rule metadata), `docs/ci.md`, `docs/extension.md`, `docs/security-model.md` | `docs/` | Links resolve | Done |
| T-146 | Record a short terminal demo and an extension demo | `docs/` | Embedded in README | Done |
| T-147 | Dogfood: self-scan as a required CI check on `main` | CI | Check required in branch protection | Done |
| T-148 | Before making the repo public run Gitleaks over the full history and confirm only the labelled fakes in `testdata/` appear | git | Report reviewed | Done |
| T-149 | Release: tag `v0.2.0-rc1`, run the fresh-machine checklist, fix findings, then tag `v0.2.0`. Publish release notes with checksums, the Docker image, the Homebrew tap and install script (checksum-verified), and the extension. Update `plugins/versions.env` if tools moved | release workflow | All gates in section 5 of this doc pass | Done |

### Sentinel's own security review

The scanner reads untrusted repositories, so it needs its own hardening. Go's regular-expression engine runs in linear time, so the embedded regexes are not a ReDoS risk; the other items below are.

| ID | Task and steps | Files | Done when | Status |
| --- | --- | --- | --- | --- |
| T-160 | Symlinks: discovery and the embedded engines must not follow symlinks that leave the repo | `discovery.go`, adapters | Test with a link to `/etc` reads nothing outside the repo | Done |
| T-161 | Limits: maximum file size, skip binaries, maximum files and findings, per-adapter timeouts from config | `discovery.go`, `scheduler.go` | A 1 GB file and a 1 million file tree do not hang or exhaust memory | Done |
| T-162 | Output paths: create report directories with mode 0700, warn when `--out` is a symlink, never overwrite files outside the target without `--force` | `report`, `scan.go` | Tests for symlinked and existing paths | Done |
| T-163 | `fix --apply` confinement and backup (see T-094) | `remediate.go` | Path-escape test refuses | Done |
| T-164 | Redaction audit: a test that scans the fixture and asserts no secret value appears in JSON, SARIF, Markdown, HTML, SQLite, terminal output, or the extension log | tests | Test passes for every output | Done |
| T-165 | Temp files: 0600 files and 0700 directories, removed on crash or interrupt (rules directory, Gitleaks report) | adapters | Interrupt leaves no temp files | Done |
| T-166 | Hostile repository test: huge files, deep directories, odd filenames (spaces, leading dash, newlines), symlink loops, malformed lockfile, malformed `.sentinel.yml` | `testdata/hostile/` | Scan finishes without panic or hang | Done |
| T-167 | Command audit: no shell strings anywhere; pass `--` before paths where a tool supports it so a file named `-x` is not read as a flag | adapters | `grep` for `sh -c` and string concatenation into commands finds nothing | Done |
| T-168 | Dependency audit in CI: `govulncheck` and `npm audit` for the extension | CI | Both run and gate | Done |
| T-169 | Write `docs/security-model.md`: assets, trust boundaries, attacker model (malicious repo, malicious PR, local process), and the controls above | docs | Reviewed against the controls | Done |
| T-170 | Agent: token file mode 0600, random port, loopback only, documented decision on TCP versus Unix socket or named pipe | `cmd/sentinel-agent/main.go` | Another local user cannot read the token | Done |

## Part 3: Traceability (nothing missed)

Every loophole, requirement and criterion below points to the tasks that close it.

### Loopholes

| ID | Closed by |
| --- | --- |
| L-01 to L-12 (patched items) | T-002, T-007 to T-010; extra checks: L-02 T-008 and T-099, L-03 T-141, L-04 T-009, L-06 T-040, L-07 T-058, L-08 T-006, L-09 T-069, L-10 T-112 and T-170, L-11 T-023 |
| L-13 stale tools and Docker | T-023, T-024, T-026, T-027 |
| L-14 CI actions | T-030, T-031 |
| L-15 fingerprints | T-040 |
| L-16 secrets reported twice | T-041, T-053 |
| L-17 Semgrep errors ignored | T-042 |
| L-18 extra rules path | T-043 |
| L-19 registry stall | T-044 |
| L-20 no-lockfile visibility | T-045, T-046 |
| L-21 thin SAST rules | T-048 to T-055 |
| L-22 reachability | T-064, T-065 |
| L-23 gofmt | T-004, T-030 |
| L-24 policy from the PR | T-020, T-021, T-022, T-032 |
| Found later: binary in git history | T-025 |
| Found later: Action image never published | T-028, T-029 |

### Original requirements

| FR | Closed by |
| --- | --- |
| 1 Auto-detect | T-059, T-092 |
| 2 Semgrep | T-049 to T-053 |
| 3 Gitleaks history | T-062 |
| 4 OSV | T-046, T-056 |
| 5 Normalize | T-040 |
| 6 Dedup | T-040, T-041, T-141 |
| 7 Risk score | T-064 to T-067 |
| 8 Reports | T-085, T-086, T-100 |
| 9 Exit codes | T-090 |
| 10 explain | T-093 |
| 11 fix | T-094 |
| 12 IDE diagnostics | T-114 |
| 13 IDE quick fix | T-115 |
| 14 Incremental | T-080, T-122 |
| 15 Trivy IaC and containers | T-058, T-059 |
| 16 Nuclei | T-068, T-069 |
| 17 Resilience | T-070 |
| 18 Config | T-020 to T-022, T-082 |
| 19 Hooks | T-096 |
| 20 Cloud sync | Deferred to after v1 (Phase 6) |

### Original success criteria and V3 work orders

| Item | Closed by |
| --- | --- |
| Scan finds SAST, secrets, SCA, deduplicated, in under 60s | T-007, T-040, T-142 |
| Valid SARIF in GitHub | T-029, T-030, T-100 |
| Extension diagnostics in 2s with a quick fix | T-110, T-115, T-125 |
| `--ci --fail-on` blocks a PR | T-009, T-020, T-087, T-090 |
| Egress test proves no upload | T-008, T-099 |
| V3 WO-01 to WO-23 | T-023, T-027, T-028 to T-031, T-020, T-040, T-041, T-042, T-043, T-044, T-045 and T-046, T-004 and T-030, T-048 to T-055, T-056 and T-057, T-064, T-066, T-080 and T-087, T-100, T-088, T-110 to T-129, T-140 and T-141, T-147 and T-148, T-144 and T-145, T-149 |

## Part 4: Task tracker

121 tasks in total.

| Phase | Tasks | Count | Done |
| --- | --- | --- | --- |
| 0 Land the fixes | T-001 to T-012 | 12 | 12 |
| 1 Trust and supply chain | T-020 to T-033 | 14 | 14 |
| 2 Detection | T-040 to T-071 | 32 | 32 |
| 3 CLI | T-080 to T-101 | 22 | 22 |
| 4 Extension | T-110 to T-129 | 20 | 20 |
| 5 Proof and release | T-140 to T-149 | 10 | 10 |
| Own security review | T-160 to T-170 | 11 | 11 |

Order of work: Phase 0, then Phase 1, then Phases 2 and 3 can overlap, Phase 4 starts after T-045 and T-112 are done, own security review runs alongside Phase 3 and 4, Phase 5 last.
