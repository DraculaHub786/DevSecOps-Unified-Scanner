# Sentinel V2 Master Plan

DevSecOps Unified Scanner: review of the current repo and the roadmap to a publishable v1.0

*Based on a clone of github.com/DraculaHub786/DevSecOps-Unified-Scanner. Code was read, not compiled or run (Go was not available in the review sandbox, and go.mod requires 1.27).*

## What the code actually does

**Good:**

- Every adapter calls the real tool when it is in PATH, using argument arrays, not shell strings.
- The scheduler has a 90s overall timeout and 60s per adapter.
- Nuclei runs with `-passive` and only when `--dast` and a target are given.
- The agent binds to `127.0.0.1`.

**Problems to fix before anything else:**

1. **Silent fallback hides what ran.** When a tool is not installed, an embedded regex engine runs instead, but findings are still labeled `Source: "semgrep"` or `"gitleaks"`. The OSV fallback is a hardcoded list of about 6 CVEs (lodash, axios, express, requests, urllib3). That explains the "under 30 ms" README claim, and it would mislead users.
2. **Errors are swallowed.** Semgrep parses `CombinedOutput()` (stderr mixed into the JSON), so any warning breaks parsing and drops into fallback unnoticed. Nuclei and Gitleaks ignore exit errors too, and Nuclei falls back to native checks whenever the real run finds zero issues.
3. **The GitHub Action cannot work as written.** It runs `go install github.com/DraculaHub786/DevSecOps-Unified-Scanner/...@latest`, but the module path is not the repo path, and the Action uses Go 1.24 while `go.mod` says 1.27.
4. **`go.mod` marks every dependency `// indirect`.** Run `go mod tidy`.
5. **`testdata/vulnerable-app/.sentinel/history.db` is tracked** despite the `.gitignore`.
6. **No authorization guard on DAST.** There is no `--i-have-authorization`, no allowlist and no private-IP block, which the spec promised.
7. **Thin tests and no CI.** Only 3 tests, none for adapters, no `.github/workflows`, and no LICENSE.
8. **The installer downloads with `curl | tar` and no checksum.** The pinned versions (Gitleaks 8.18.4, OSV 1.8.2, Trivy 0.51.0) look dated, so verify them before relying on them.

## V2 principle

**Real engines are the product. Embedded fallbacks are a clearly labeled "lite mode".** Every finding carries `engine: external|embedded`, and the report header states which mode ran. In `--ci` mode, a missing tool is an error (exit 2) unless the user passes `--allow-lite`.

## V2 command set

| Command | Purpose |
| --- | --- |
| `scan` | Everything applicable, with `--only`, `--skip`, `--changed-only` |
| `secrets`, `deps`, `sast`, `iac` | Single-category shortcuts |
| `image <name>` | Container image scan (`trivy image`) |
| `sbom` | CycloneDX/SPDX output |
| `dast --target URL` | Passive by default; active needs `--i-have-authorization` plus an allowlist |
| `threat-model` | Entry points, trust boundaries, STRIDE/OWASP mapping |
| `baseline` | Accept current findings, so only new ones fail |
| `diff <a> <b>`, `history` | New vs fixed findings between scans |
| `report <id> --format sarif\|md\|html\|json` | Re-render stored scans |
| `suppress <id> --reason` | Suppression with a required justification |
| `doctor` | Tool presence, versions, mode (external or lite) |
| `explain`, `fix`, `watch`, `install-hooks`, `version` | Already built |

## Phases

### Phase 0: Hygiene (days 1-2)

- Fix the module path, run `go mod tidy`, align Go versions, and `git rm --cached` the history.db.
- Add LICENSE, SECURITY.md, a repo description and topics, and move the build guide into `docs/`.
- *Done when:* `go build ./... && go test ./...` passes on a clean machine.

### Phase 1: Honest engines (week 1)

- Add the `engine` field and the labeled-fallback behavior.
- Separate stdout from stderr and check exit codes (Semgrep 0/1 are fine, 2+ is an error).
- Add `--redact` to Gitleaks, and stop falling back to native when the real tool simply found nothing.
- Add `doctor` and golden-file parser tests using recorded real tool output for all five adapters.
- *Done when:* a scan with tools installed shows only `engine: external` findings, and one without them warns loudly.

### Phase 2: Coverage (weeks 2-3)

- Trivy image and SBOM, plus license enforcement (`fail_on_license` is config-only today).
- GitHub Actions workflow rules (unpinned actions, `pull_request_target`, broad permissions).
- Basic supply-chain checks: unpinned or typosquat-looking dependencies.
- Make reachability real. Today `checkReachability` is a heuristic, so label it as one.
- *Done when:* `testdata/` has one vulnerable fixture per language and tests assert expected counts per category.

### Phase 3: Workflow (weeks 3-4)

- `baseline`, `diff` and `history` on the existing SQLite store, plus an HTML report.
- Suppressions with required reasons and optional expiry.
- A `.github/workflows` pipeline: vet, test, cross-compile, a SARIF schema check, an egress test (default scan works with network blocked), and a self-scan gate.
- *Done when:* a PR that adds one new vulnerability fails and an old one does not.

### Phase 4: Threat analysis and safety (weeks 4-5)

- `threat-model` rule-based first. Optional LLM explanation later, off by default, clearly labeled, never uploading code without opt-in.
- DAST guardrails: authorization flag, allowlist in `.sentinel.yml`, refusal on private/loopback/metadata IPs unless explicitly allowed, rate cap, and an authorized-use notice.
- Keep resilience checks static only. No load generation.

### Phase 5: Ship (weeks 5-6)

- goreleaser for releases, a Docker image with pinned and checksum-verified scanners, and a fixed Action that uses the container or release binary.
- Finish the VS Code extension and publish it, then a Homebrew tap and a GitHub Pages docs site.
- Cloud, domain and the SaaS dashboard come after v1.0, and only if people actually use local mode.

## Publish gates (all must pass)

- Gitleaks over the full git history finds no real secrets, and the fixture's fake secrets are clearly labeled.
- The README makes no claim the code does not back, including the speed number.
- CI is green and the self-scan passes.
- A fresh-machine install from the release works end to end.

## Suggested start

Phase 0 plus the Phase 1 labeling and error-handling fixes are one focused pass of roughly 300-400 lines changed. Start with the `engine` field and the Semgrep and Gitleaks error handling.

## Part 2: Work orders

Use this part while you code. Work top to bottom. Each work order (WO) lists the files, the change, and a done condition. Commit once per WO with a conventional message (`fix:`, `feat:`, `chore:`, `docs:`, `test:`). Do not start the next WO until `go build ./... && go test ./...` passes. Code for the key changes is in Part 3.

### Tech and version updates

Re-check every version on the day you pin it. The numbers below may have moved.

| Item | Now in repo | Action |
| --- | --- | --- |
| Go module path | `github.com/DraculaHub786/DevSecOps-Unified-Scanner` | Rename to `github.com/DraculaHub786/DevSecOps-Unified-Scanner` so `go install` and the Action work (WO-01). |
| Go version | `go 1.27.0` in go.mod, Go 1.24 in the Action | Set the directive to the version you build with (`go version`). In CI use `go-version-file: go.mod`. |
| Dependencies | every require is marked `// indirect` | Run `go mod tidy`. Add `govulncheck` and `golangci-lint` to CI. |
| Gitleaks | 8.18.4 in `plugins/install.*` | Bump to a current release (8.30.1 was current in spring 2026; check the releases page). Run with `--redact`. Newer releases add `gitleaks git` and `gitleaks dir`; confirm whether `detect` still works for your pinned version. |
| OSV-Scanner | 1.8.2 | Decide v1 or v2. v2 reorganised the CLI into subcommands, so compare `osv-scanner --help` with the args and JSON structs in `osv.go`. |
| Trivy | 0.51.0 | Bump to current stable. Verify the SHA-256 of every download. |
| Semgrep | not pinned; uses `--config auto` | Install a pinned version with `pipx`. `auto` downloads rules from the registry, so for offline mode use `--metrics=off` and vendored rules in `rules/`. |
| Nuclei | not pinned | Pin the binary. Update templates explicitly, not at scan time. |
| SBOM | none | Use `trivy fs --format cyclonedx`. No new dependency. |
| GitHub Actions | `setup-go@v5`, `upload-sarif@v3` | Move to current majors and pin SHAs before release. GitHub announced Node 20 removal from hosted runners for 2026-09-16, so confirm each action ships a Node 24 build. Run the Gitleaks binary, not `gitleaks-action`. |
| Agent transport | TCP `127.0.0.1:<port>`, no auth | Add a per-session token (WO-16). The spec called for a Unix socket or named pipe. |
| Docker | `deploy/docker/Dockerfile.cli` | Multi-stage build, pinned base image digest, non-root user. |
| VS Code extension | `package.json`, `package-lock.json` | Update `engines.vscode`, TypeScript and `@types/vscode`. Package with `@vscode/vsce`. Test with `@vscode/test-electron`. |

### Target layout

`NEW` means create the file. `CHG` means edit what exists.

```
.github/workflows/ci.yml            NEW
.github/workflows/release.yml       NEW
.github/dependabot.yml              NEW
.goreleaser.yaml                    NEW
LICENSE, SECURITY.md, CONTRIBUTING.md   NEW
docs/architecture.md                CHG  moved from repo root
docs/risk-scoring.md                NEW
cmd/sentinel/main.go                CHG  root command only
cmd/sentinel/scan.go                NEW  moved from main.go
cmd/sentinel/{doctor,baseline,diff,history,report,suppress,sbom,image,dast,threatmodel}.go   NEW
cmd/sentinel-agent/main.go          CHG  token auth
internal/adapters/runner.go         NEW  safe tool runner
internal/adapters/*/                CHG  engine label, error handling
internal/safety/target.go           NEW  DAST authorization and IP guard
internal/doctor/doctor.go           NEW
internal/baseline/baseline.go       NEW
internal/threatmodel/               NEW
internal/orchestrator/finding.go    CHG  Engine field
internal/orchestrator/scheduler.go  CHG  engines, exit codes
internal/config/{schema,loader}.go  CHG  new fields, strict parsing
internal/report/html.go             NEW
internal/report/{terminal,sarif,sqlite}.go   CHG
plugins/{install.sh,install.ps1}    CHG  checksums
plugins/versions.env                NEW
deploy/docker/Dockerfile.cli        CHG
deploy/github-actions/sentinel-scan/action.yml   CHG
extension-vscode/src/*              CHG  mode display, token
```

### WO-01: Module path and Go version

Files: `go.mod`, every `*.go` import, `README.md`, `action.yml`, `Dockerfile.cli`.

```
go mod edit -module github.com/DraculaHub786/DevSecOps-Unified-Scanner
grep -rl 'github.com/DraculaHub786/DevSecOps-Unified-Scanner' . --include='*.go' | xargs sed -i 's#github.com/DraculaHub786/DevSecOps-Unified-Scanner#github.com/DraculaHub786/DevSecOps-Unified-Scanner#g'
go mod tidy
```

Set the `go` line in `go.mod` to your installed version. Done when: build and tests pass, `go mod tidy` leaves no diff, and `grep -r sentinel-dev .` finds nothing outside `.git`.

### WO-02: Repo hygiene

Files: `.gitignore`, `testdata/vulnerable-app/.sentinel/history.db`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/`.

- The `.gitignore` rule `.sentinel/history.db` contains a slash, so Git anchors it to the repo root. It does not match the nested file under `testdata/`, which is why that file was committed. Change it to `**/.sentinel/` .
- Run `git rm --cached testdata/vulnerable-app/.sentinel/history.db`.
- Run `mkdir docs` and `git mv` the build guide to `docs/architecture.md` (the current name has spaces and an em dash).
- Add a `testdata/vulnerable-app/README.md` stating that every secret and flaw in it is fake and intentional.
- Add LICENSE (MIT or Apache-2.0), `SECURITY.md` (how to report issues, authorized-use notice), and `CONTRIBUTING.md`.
- Add a repo description and topics on GitHub: `devsecops`, `sast`, `sca`, `sarif`, `golang`, `security-tools`.

Done when: `git status` is clean after a scan of the fixture.

### WO-03: Engine provenance

Files: `internal/orchestrator/finding.go`, `scheduler.go`, `internal/report/terminal.go`, `sarif.go`.

- Add constants `EngineExternal` and `EngineEmbedded` and a `Finding.Engine` field (see Part 3).
- Every adapter sets `Engine` on each finding it returns.
- The scheduler records which engine each adapter used and puts it in `ScanResult`.
- Terminal output prints a header line such as `Mode: full (5 external)` or `Mode: lite (semgrep, osv embedded)`.
- SARIF: put `engine` in each result's `properties` and the tool version in the run.

Done when: a scan without the tools installed shows `embedded` in the header and SARIF, and a scan with them shows only `external`.

### WO-04: Safe tool runner

Files: new `internal/adapters/runner.go`. Code in Part 3.

It keeps stdout and stderr separate, returns the exit code, and reports timeouts. Every adapter uses it instead of `exec.Command(...).CombinedOutput()`. Done when: no adapter calls `CombinedOutput` (`grep -rn CombinedOutput internal/`).

### WO-05: Semgrep adapter

File: `internal/adapters/semgrep/semgrep.go` (`runCLI`, around lines 60 to 140).

- Use `RunTool`. Parse stdout only.
- Add `--metrics=off`. Replace `--config auto` with the configured ruleset; when `--offline` is set or the ruleset is empty, use `rules/` only.
- Exit code 0 is normal. Semgrep exits non-zero without `--error` only on real errors, so a non-zero code is an error, not a reason to fall back.
- A JSON parse error is an error. Do not fall back silently.
- Fall back to the embedded engine only when `exec.LookPath` fails and `engine` is not `external`. Set `Engine` accordingly.

Done when: a fake `semgrep` script that prints warnings to stderr and valid JSON to stdout still yields external findings (add this as a test).

### WO-06: Gitleaks adapter

File: `internal/adapters/gitleaks/gitleaks.go` (`runCLI`, around lines 70 to 150).

- Add `--redact` so raw secrets never reach the temp report.
- Keep `--exit-code 0`. Then any non-zero exit is a real error.
- Zero findings from a clean exit is a valid result. Remove the fallback that runs when the report is empty.
- Honor `scan_history`. For a history scan, the CI checkout needs `fetch-depth: 0`.
- Never store or print a raw secret; keep the existing `redactSecret` for the embedded engine.

Done when: scanning the fixture reports the fake secrets redacted, and scanning a clean repo reports zero without touching the embedded engine.

### WO-07: OSV adapter

File: `internal/adapters/osv/osv.go` (`runCLI` lines 77 to 160, fallback from line 165).

- Match the args and JSON structs to the OSV-Scanner version you pin (see the version table).
- The embedded fallback is a hardcoded list of about six advisories. Keep it only as lite mode. Add a warning to the report: `embedded advisory list has N entries; install osv-scanner for full coverage`.
- `checkReachability` is a text search for the package name in source files. Label it `heuristic` in the finding message and in `docs/risk-scoring.md`.
- Add license data to findings so `fail_on_license` can work (WO-11).

Done when: a lockfile with a known vulnerable package is found by the real tool, and the lite-mode warning shows without it.

### WO-08: Trivy adapter and new modes

File: `internal/adapters/trivy/trivy.go`.

- `trivy fs --format json --scanners misconfig` for IaC. Leave secrets to Gitleaks and dependencies to OSV to avoid duplicates, or let `correlate.go` merge them.
- Add `image` mode: `trivy image --format json <name>`.
- Add `sbom` mode: `trivy fs --format cyclonedx --output sbom.cdx.json .` (also `spdx-json`).
- Use `RunTool`, and keep the embedded IaC rules as lite mode only.

Done when: `sentinel image alpine:3` and `sentinel sbom` each produce output.

### WO-09: Nuclei and DAST safety

Files: `internal/adapters/nuclei/nuclei.go`, new `internal/safety/target.go`, `internal/config/schema.go`, `cmd/sentinel/dast.go`.

- `IsApplicable` must return false when there is no target.
- Call `safety.ValidateTarget` before any request, including the embedded header check in `runPassiveNativeChecks`.
- Require `--i-have-authorization`, a host in `dast.allowlist`, and a public IP unless `dast.allow_private: true`. Code in Part 3.
- Remove the fallback that runs native checks when the real Nuclei run finds nothing.
- Never add active or load-generating checks. Keep `-passive`.

Done when: a scan with `--dast` and no flag is refused, a loopback target is refused, and an allowlisted public host is scanned.

### WO-10: Scheduler and exit codes

File: `internal/orchestrator/scheduler.go` (`Execute`).

- Add `recover()` inside each adapter goroutine so one panic does not kill the run.
- Read the per-adapter timeout from config (now fixed at 60s, with 90s overall).
- Sort findings by severity, file, line before returning so reports are stable.
- In `--ci` mode, a missing tool is an error (exit 2) unless `--allow-lite` is set.
- Exit codes: 0 clean or below threshold, 1 findings at or above `--fail-on`, 2 scanner execution error.

Done when: a test with a panicking fake adapter still returns the other adapters' findings and a warning.

### WO-11: Config

Files: `internal/config/schema.go`, `loader.go`, `.sentinel.yml`, `.sentinel.yml.example`.

- Add `engine: auto | external | embedded` at the top level.
- Add `scanners.dast.allowlist` (list) and `scanners.dast.allow_private` (bool).
- Change `ignore.findings` from a list of IDs to entries with `id`, `reason` (required) and optional `expires`.
- Parse with `yaml.Decoder.KnownFields(true)` so typos fail loudly.
- Enforce `sca.fail_on_license`; it exists in config but no code reads it.
- Replace the placeholder target `https://staging.myapp.com` in `.sentinel.yml` with an empty value.

Done when: an unknown key and a suppression without a reason both fail validation.

### WO-12: Reports and history

Files: `internal/report/sqlite.go`, `sarif.go`, `terminal.go`, `markdown.go`, new `html.go`.

- SQLite: add `engine` and `status` columns, a scan summary, and a baseline table. Add a schema version and a migration step so old `history.db` files keep working.
- SARIF: include rule metadata, `partialFingerprints` (use the existing fingerprint), and the tool version. Keep the schema test and add a validation against the official SARIF schema.
- HTML: a single self-contained file with severity counts and a findings table; no external assets.

Done when: `sentinel report <scan-id> --format html` opens offline and `diff` can compare two stored scans.

### WO-13: CLI split and new commands

Files: `cmd/sentinel/main.go` (476 lines today) and the new command files in the layout above.

- Move `scan` into `scan.go`. Keep `main.go` for the root command and registration.
- Add flags to `scan`: `--skip`, `--changed-only`, `--baseline`, `--allow-lite`.
- `doctor`: for each tool, `LookPath`, run `--version`, print the version and `external` or `embedded`.
- `baseline`: write fingerprints of the current findings to `.sentinel/baseline.json`; later scans with `--baseline` fail only on findings not in that file.
- `diff <a> <b>` and `history`: query SQLite; print new, fixed and unchanged counts.
- `report`, `suppress`, `sbom`, `image`, `dast`, `secrets`, `deps`, `sast`, `iac`: thin wrappers over the scheduler with the right category set.

Done when: every command in the V2 command table prints help and runs against the fixture.

### WO-14: Threat-model command

Files: new `internal/threatmodel/`, `cmd/sentinel/threatmodel.go`.

- Detect entry points with simple patterns per language (for example `http.HandleFunc`, `r.GET`, `app.get`, `@app.route`), exposed ports (`EXPOSE` in Dockerfiles, Kubernetes `Service` and `Ingress`), auth middleware names, and data stores.
- Map each finding to a STRIDE category and CWE or OWASP Top 10 entry.
- Output Markdown: entry points, trust boundaries, findings on exposed routes.
- Feed the result into `Finding.Exposed` so risk scoring uses real exposure data instead of a guess.

Done when: the fixture app produces a report listing its routes and flags the findings that sit on them.

### WO-15: Risk scoring

Files: `internal/orchestrator/riskscore.go`, new `docs/risk-scoring.md`.

- Document the exact formula (severity, CVSS, reachability, exposure, exploit maturity) with worked examples.
- Mark reachability as a heuristic wherever it is shown.
- Add table-driven tests for each factor.

### WO-16: Agent security

Files: `cmd/sentinel-agent/main.go`, `extension-vscode/src/ipc/client.ts`.

- Generate a random token at startup and write it to a file with mode 0600 in the user cache directory.
- Require the token on every JSON-RPC request. Reject requests without it.
- Keep binding to loopback only. Set a maximum request size.
- The extension reads the token file and sends it with each call.

Done when: a raw TCP client without the token is rejected, and the extension still connects.

### WO-17: VS Code extension

Files: `extension-vscode/src/{extension,diagnostics,codeActions,statusBar}.ts`, `sidebar/findingsProvider.ts`, `package.json`.

- Status bar shows the mode (`full` or `lite`) and agent connection errors.
- Show the engine in the hover text.
- Update dependencies, add `.vscodeignore`, an icon, and a README for the Marketplace.
- Add `@vscode/test-electron` tests for diagnostics on a fixture workspace.
- Build with `npm run compile` and package with `npx @vscode/vsce package`.

### WO-18: Installer scripts

Files: `plugins/install.sh`, `plugins/install.ps1`, new `plugins/versions.env`, `plugins/checksums.txt`.

- Move all versions into `versions.env` and have both scripts read it.
- Download to a temp file, verify SHA-256 against `checksums.txt`, then extract. Do not pipe `curl` into `tar`.
- Add Semgrep (`pipx install semgrep==<version>`) and Nuclei.
- Fail the script on any checksum mismatch.

### WO-19: Docker image

File: `deploy/docker/Dockerfile.cli`.

- Multi-stage build: Go build stage, then a slim runtime with the pinned scanners installed through `plugins/install.sh`.
- Pin base images by digest. Run as a non-root user. Set `ENTRYPOINT ["sentinel"]`.
- Publish to `ghcr.io/draculahub786/devsecops-unified-scanner` from the release workflow.

### WO-20: GitHub Action

File: `deploy/github-actions/sentinel-scan/action.yml`. Code in Part 3.

- The current file installs `github.com/DraculaHub786/DevSecOps-Unified-Scanner/...@latest`, which cannot resolve. Switch to the Docker image so the scanners ship with it.
- Pass inputs through `env`, not by inserting `${{ inputs.* }}` into the shell script.
- Document the SARIF upload step and the `permissions` the caller needs (`security-events: write`).

### WO-21: CI, release, Dependabot

Files: `.github/workflows/ci.yml`, `release.yml`, `.github/dependabot.yml`, `.goreleaser.yaml`. CI code in Part 3.

- CI: vet, `go test -race`, `govulncheck`, a cross-compile matrix, a SARIF schema check, an egress test, and a self-scan gate.
- Release on tag: goreleaser builds binaries for darwin, linux and windows (amd64 and arm64), publishes the Docker image, and attaches checksums.
- Dependabot for `gomod`, `npm` (in `extension-vscode`), `github-actions` and `docker`.

### WO-22: Tests

Add these before you call v1 done:

| Package | Tests |
| --- | --- |
| `internal/adapters/*` | Golden-file parsers using recorded real tool output; a fake binary on `PATH` for stderr noise and non-zero exits |
| `internal/orchestrator` | Dedup across tools, scheduler panic recovery, exit codes 0, 1 and 2, stable ordering |
| `internal/safety` | Target validation: missing flag, off-allowlist host, loopback, private, link-local and metadata IPs |
| `internal/config` | Unknown keys, suppression without a reason, invalid thresholds |
| `internal/report` | SARIF schema validation, SQLite migration, HTML renders offline |
| `internal/baseline` | New vs existing findings, fingerprint stability across line moves |
| `testdata/` | One vulnerable fixture per language with expected counts per category |
| CI egress test | `unshare -rn ./bin/sentinel scan testdata/vulnerable-app --offline` completes with no network |

### WO-23: README and docs

- Remove the `under 30 milliseconds` claim. That speed comes from the embedded engines, not the real tools.
- Add a Modes section (full, lite) explaining `doctor` and `--allow-lite`.
- Add an Authorized use section: DAST needs written permission and the guardrails in WO-09.
- Add a terminal recording or screenshot of a real scan.
- Link `docs/architecture.md` and `docs/risk-scoring.md`.

### WO-24: Release v0.1.0

Tag only when every item below is true:

1. Gitleaks over the full history finds no real secrets.
2. CI is green, including the self-scan.
3. A fresh machine can install from the release and run `sentinel doctor` and `sentinel scan`.
4. The README claims match what the code does.
5. The extension installs from the `.vsix` and shows diagnostics.

## Part 3: Code and commands

Copy these as starting points. Adjust names to match your files.

### Engine field (WO-03)

In `internal/orchestrator/finding.go`:

```go
const (
	EngineExternal = "external" // real tool ran
	EngineEmbedded = "embedded" // built-in lite engine ran
)

// add to the Finding struct
Engine string `json:"engine"`
```

### Safe tool runner (WO-04)

New file `internal/adapters/runner.go`:

```go
package adapters

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

type ToolResult struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// RunTool runs bin with an argument array (never a shell string), keeps stdout
// and stderr apart, and returns the exit code. err is set only when the tool
// could not start or the context ended.
func RunTool(ctx context.Context, bin string, args ...string) (*ToolResult, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	res := &ToolResult{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}
	return res, runErr
}
```

### Adapter pattern (WO-05 to WO-08)

Every adapter follows the same shape. Fall back only when the binary is missing:

```go
bin, lookErr := exec.LookPath("semgrep")
if lookErr != nil {
	if cfg.Engine == "external" {
		return nil, fmt.Errorf("semgrep not installed and engine is external")
	}
	return a.runNativeFallback(repoPath, cfg) // findings get Engine = EngineEmbedded
}

res, err := adapters.RunTool(ctx, bin, args...)
if err != nil {
	return nil, fmt.Errorf("semgrep: %w", err) // could not run, or timed out
}
if res.ExitCode != 0 {
	return nil, fmt.Errorf("semgrep exit %d: %s", res.ExitCode, firstLine(res.Stderr))
}
findings, err := parseSemgrep(res.Stdout) // a parse error is an error, not a reason to fall back
```

Arguments to change:

```
semgrep:   scan --json --quiet --metrics=off --config <ruleset-or-rules/> <path>
gitleaks:  detect --source <path> --report-format json --report-path <tmp> --redact --exit-code 0 [--no-git]
trivy iac: fs --format json --scanners misconfig <path>
trivy img: image --format json <name>
trivy sbom: fs --format cyclonedx --output sbom.cdx.json <path>
nuclei:    -u <target> -tags misconfig,exposure,headers -passive -jsonl -silent
```

Check each line against `--help` for the version you pin; flags change between releases.

### DAST target guard (WO-09)

New file `internal/safety/target.go`:

```go
package safety

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
)

func ValidateTarget(raw string, allow []string, authorized, allowPrivate bool) error {
	if !authorized {
		return errors.New("DAST needs --i-have-authorization; scan only systems you own or may test in writing")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("invalid target %q", raw)
	}
	host := u.Hostname()
	if !slices.Contains(allow, host) {
		return fmt.Errorf("host %q is not in scanners.dast.allowlist", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("cannot resolve %q", host)
	}
	for _, ip := range ips {
		if !allowPrivate && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
			return fmt.Errorf("%q resolves to a non-public address %s", host, ip)
		}
	}
	return nil
}
```

This checks the address at validation time. To stop DNS rebinding, also check the connected IP inside a custom `http.Transport` `DialContext` in the embedded checker.

### Config additions (WO-11)

```yaml
version: 1
engine: auto            # auto | external | embedded
scanners:
  dast:
    enabled: false
    target: ''
    allowlist: []       # exact hostnames you may test
    allow_private: false
ignore:
  findings:
    - id: SENT-0000
      reason: 'accepted risk, ticket ABC-1'   # required
      expires: 2027-01-31                      # optional
```

### Fixed GitHub Action (WO-20)

`deploy/github-actions/sentinel-scan/action.yml` as a Docker action, so the scanners ship inside the image:

```yaml
name: Sentinel DevSecOps Scanner
description: Unified SAST, SCA, secrets, IaC and resilience scan that writes SARIF
inputs:
  fail-on:
    description: Fail at or above this severity (critical, high, medium, low)
    default: high
  path:
    description: Directory to scan
    default: .
runs:
  using: docker
  image: docker://ghcr.io/draculahub786/devsecops-unified-scanner:v0.1.0
  args:
    - scan
    - ${{ inputs.path }}
    - --ci
    - --fail-on
    - ${{ inputs.fail-on }}
    - --format
    - sarif
    - --out
    - results.sarif
```

Caller workflow:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v6
    with:
      fetch-depth: 0
  - uses: DraculaHub786/DevSecOps-Unified-Scanner/deploy/github-actions/sentinel-scan@v0.1.0
  - if: always()
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: results.sarif
```

Check the current major versions of each action on the day you commit, and pin by commit SHA before release.

### CI workflow (WO-21)

`.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - run: go vet ./...
      - run: go test -race ./...
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
      - run: go build -o bin/sentinel ./cmd/sentinel
      - name: Egress test (no network)
        run: sudo unshare -n ./bin/sentinel scan testdata/vulnerable-app --offline --format json --out /tmp/r.json
  self-scan:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: actions/setup-go@v6
        with:
          go-version-file: go.mod
      - run: bash plugins/install.sh
      - run: go run ./cmd/sentinel scan . --ci --fail-on=high --format sarif --out results.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

If the fixture under `testdata/` trips the self-scan, add `testdata/` to `ignore.paths` in a CI-only config.

### Installer checksums (WO-18)

`plugins/versions.env`:

```
GITLEAKS_VERSION=<pin>
OSV_VERSION=<pin>
TRIVY_VERSION=<pin>
SEMGREP_VERSION=<pin>
NUCLEI_VERSION=<pin>
```

In `install.sh`, download to a file, check, then extract:

```bash
set -euo pipefail
. "$(dirname "$0")/versions.env"
fetch_verify() { # url file expected_sha256
  curl -fsSL -o "$2" "$1"
  echo "$3  $2" | sha256sum -c -
}
```

Get each expected hash from the project's published checksum file and store it in `plugins/checksums.txt`.

### Daily check script

Run this before each commit:

```
go build ./... && go vet ./... && go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go build -o bin/sentinel ./cmd/sentinel
./bin/sentinel doctor
./bin/sentinel scan testdata/vulnerable-app --format sarif --out /tmp/r.sarif
git status --short
```

### Commit order

```
chore: rename module and tidy dependencies          (WO-01)
chore: untrack fixture history db, add license, docs (WO-02)
feat: label findings with engine                     (WO-03, WO-04)
fix: separate tool stdout and stderr, stop silent fallback   (WO-05 to WO-08)
feat: require authorization and allowlist for DAST   (WO-09)
feat: exit codes, lite mode gate, scheduler recovery (WO-10, WO-11)
feat: html report, history migration                 (WO-12)
feat: doctor, baseline, diff, sbom, image commands   (WO-13)
feat: threat-model command                           (WO-14, WO-15)
fix: authenticate agent connections                  (WO-16)
feat: extension mode display and tests               (WO-17)
chore: verified installer, docker image, action      (WO-18 to WO-20)
ci: add workflows, dependabot, goreleaser            (WO-21)
test: golden files and fixtures                      (WO-22)
docs: rewrite README claims                          (WO-23)
```

## Part 4: Progress tracker

Change the status as you go. Allowed values: Todo, Doing, Done, Blocked.

| WO | Task | Status | Commit |
| --- | --- | --- | --- |
| 01 | Module path and Go version | Done | feat |
| 02 | Repo hygiene | Done | chore |
| 03 | Engine provenance | Done | feat |
| 04 | Safe tool runner | Done | feat |
| 05 | Semgrep adapter | Done | fix |
| 06 | Gitleaks adapter | Done | fix |
| 07 | OSV adapter | Done | fix |
| 08 | Trivy adapter and modes | Done | feat |
| 09 | Nuclei and DAST safety | Done | feat |
| 10 | Scheduler and exit codes | Done | feat |
| 11 | Config | Done | feat |
| 12 | Reports and history | Done | feat |
| 13 | CLI split and new commands | Done | feat |
| 14 | Threat-model command | Done | feat |
| 15 | Risk scoring | Done | feat |
| 16 | Agent security | Done | fix |
| 17 | VS Code extension | Done | feat |
| 18 | Installer scripts | Done | chore |
| 19 | Docker image | Done | chore |
| 20 | GitHub Action | Done | chore |
| 21 | CI, release, Dependabot | Done | ci |
| 22 | Tests | Done | test |
| 23 | README and docs | Done | docs |
| 24 | Release v0.1.0 | Done | release |