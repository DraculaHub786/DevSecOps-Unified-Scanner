# Sentinel — Production Readiness Implementation Plan

Basis: direct verification on this machine (Go 1.27.3, all 5 engines installed, Windows 11).
Every item below was **reproduced**, not assumed.

---

## Verified baseline (measured)

| Check | Command | Result |
|---|---|---|
| Build | `go build ./cmd/sentinel` | OK |
| Unit tests | `go test ./...` | 18/18 packages pass |
| Engines | `sentinel doctor` | Semgrep 1.182.0, Gitleaks 8.30.1, OSV 2.7.0, Trivy 0.76.0, Nuclei 3.3.8 |
| Rule validation | `sentinel rules test` | 78 rules, real Semgrep parse + `#ruleid`/`#ok` behavioural fixtures |
| Vulnerable fixture | `scan testdata/vulnerable-app` | 29 findings across 5 categories |
| Clean fixture | `scan testdata/safe-app` | 0 findings (no false positives) |

Phase 0 defects from `V5 Master Plan.md` (P-01 panic, P-02 SAST poisoning, P-20 byte
slicing, P-03 false-assurance rule tests) **are already fixed**. That part is closed.

---

## Defects still live (all reproduced)

### B-01 — Every Semgrep rule reports twice (Critical, user-visible)
**Evidence** — `scan testdata/vulnerable-app --format=json`:
```
org-python-command-injection-shell        semgrep  app.py:11
rules.org-python-command-injection-shell  semgrep  app.py:11   <-- same rule, same line
```
Identical for `app.py:15`, `main.go:18`, `server.js:15`, `server.js:23`.

**Root cause** — two independent faults:
1. `config.DefaultConfig()` and `.sentinel.yml` ship `extra_rules: ["rules/sast-rules.yml"]`,
   the *same file* that is already embedded and always loaded. Semgrep gets the pack twice.
2. `semgrep.normalizeRuleID` strips only the `sentinel-rules-<n>.` prefix of the embedded
   copy. The extra-rules copy is passed as `rules/sast-rules.yml`, so Semgrep prefixes those
   IDs with `rules.` instead, which survives normalisation. Different IDs → different finding
   IDs → `CorrelateAndDeduplicate` cannot merge them.

**Fix**
- Remove the self-referential `extra_rules` default from `config.DefaultConfig()` and `.sentinel.yml`.
- Harden `normalizeRuleID` to strip any config-directory prefix.
- Regression test: no two findings share `(file, line, canonical-rule)`.

### B-02 — Cross-tool dedupe (P-14) never fires for Trivy
**Evidence** — `Dockerfile:1` reported twice:
```
DS-0001                              trivy    Dockerfile:1   ':latest' tag used
org-supplychain-docker-latest-tag    semgrep  Dockerfile:1   Docker base image uses ':latest'
```
`RuleTaxonomy` maps `avd-ds-0001` and `ds001`, but Trivy emits `DS-0001` → lowercased
`ds-0001`, a key that does not exist.

**Fix** — normalise taxonomy lookups, add the `ds-####` keys, extend the map to the real
observed IDs, add a golden test.

### B-03 — `--ci --offline` exits 2 instead of 1 (P-04, still open)
**Evidence** — `scan testdata/vulnerable-app --ci --offline --fail-on=high` → `CI_EXIT=2`.
Expected `1` (findings over threshold). `2` means "scanner error".

**Root cause** — `--offline` makes OSV degrade to the embedded advisory list, so
`enginesUsed["osv"]="embedded"` → `overallMode="lite"` → CI lite gate fires, even though
every engine is installed and the user explicitly asked for no network.

**Fix** — the CI lite gate fires only when an *expected* external engine is missing. A
deliberate `--offline` degrade is `degraded`, not `lite`.

### B-04 — Provenance line prints `SECRET: secret`
`engineToolMap` is keyed `"secrets"`; the category constant is `"secret"`. Lookup misses and
falls back to printing the category name as the tool.

**Fix** — key the map on the real constants, add a test over every category.

### B-05 — Banner says `Mode: LITE` on a fully-external run
Same root cause as B-03. `Mode` becomes `full` unless a genuinely missing external engine
forced a fallback.

---

## Scope decision

Delivering **Phase 0 completion + Phase 3 correctness** — the defects a user hits in the first
five minutes, all verifiable on this machine now.

Explicitly out of scope for this pass (documented, not silently dropped):
Phase 5 AI-assisted remediation, Phase 6 `@vscode/test-electron` CI on 3 OSes,
Phase 7 cosign/SLSA signing, Phase 9 cloud/team mode.

---

## Execution order

1. **B-01** config default + rule-ID normalisation + regression test
2. **B-02** taxonomy normalisation + golden test
3. **B-03/B-05** engine-provenance model: separate `expected`, `degraded`, `fallback`
4. **B-04** provenance label map
5. Re-verify: `go test ./...`, `rules test`, vulnerable + safe fixtures, CI exit-code matrix
6. Correct `README.md` / `Todo.md` claims where they still overstate

## Acceptance gates — RESULT

| Gate | Result |
|---|---|
| No duplicate `(file, line, rule)` pairs | **PASS** — 29 to 23 findings, 0 duplicate groups |
| `Dockerfile:1` latest-tag reported once, both sources | **PASS** — `DS-0001`, `source: trivy+semgrep` |
| `--ci` findings + `--offline` exits 1 | **PASS** — measured `1` |
| `--ci` clean exits 0 | **PASS** — measured `0` |
| Non-CI run exits 0 | **PASS** — measured `0` |
| `testdata/safe-app` stays at 0 findings | **PASS** |
| `go test ./...` | **PASS** — 18/18 packages |
| `go vet ./...` | **PASS** — clean |
| `gofmt -l internal cmd` | **PASS** — clean |
| `rules test` with real Semgrep | **PASS** — 78/78 rules |
| Mode banner on fully-external run | **PASS** — `FULL` |
| Provenance label | **PASS** — `Secrets: gitleaks (external)` |

Regression tests added:
- `internal/orchestrator/provenance_regression_test.go` — Trivy ID forms,
  directory-qualified duplicate merge, distinct-issue separation, provenance label
  mapping, engine provenance constants.
- `internal/adapters/semgrep/normalize_test.go` — rule-ID normalisation, idempotency,
  registry-pack passthrough, bundled rule index population.

## Second pass — audit against every P-item

After the first pass I audited each of P-01..P-25 against the actual code rather than the docs.

### Already implemented and verified in place

| ID | Verification |
|---|---|
| P-01 panic on `low` | `sevLabel` helper, no byte slicing |
| P-02 SAST poisoning | `ErrPartial` handling on exit 2 |
| P-03 false-assurance rules test | real Semgrep parse + `#ruleid`/`#ok` fixtures, 78/78 |
| P-04 `--ci` lite gate | exit matrix 0/1/2 correct |
| P-05 e2e-full CI job | present in `ci.yml`, runs `scripts/e2e-full.sh` |
| P-08 GHA false positive | `testdata/gha` yields **0** findings |
| P-10 shortcut parity | `sast`/`secrets`/`deps`/`iac` all accept `--format/--out/--fail-on/--offline` |
| P-11 explain cache | `lookupFinding` reads `last-scan.json`; test asserts no engine invoked |
| P-13 reachability beyond Go | every SCA finding carries `reachability_level` (`imported`/`unimported`) |
| P-17 rule counts | computed dynamically from YAML, not hardcoded |
| P-20 unsafe byte slicing | `truncateRunes` in terminal renderer |
| P-23 third-party notices | `THIRD_PARTY_NOTICES.md` present |

### Implemented in this pass

**P-22 — fuzz targets (were completely absent).** Added four Go native fuzzers and
wired a short-budget smoke run into CI:

| Fuzzer | Executions | Result |
|---|---|---|
| `FuzzLoadFile` (config loader) | 985 | PASS |
| `FuzzParseOutput` (Semgrep JSON) | 2,770,059 | **found a real bug, then PASS** |
| `FuzzNormalizeRuleID` | 1,737,563 | PASS |
| `FuzzCorrelateAndDeduplicate` | 423,779 | PASS |

**Bug the fuzzer found — B-06.** `ParseOutput` accepted a Semgrep result with
`"line": -1` and no `path`, producing a finding with `LineStart: -1`. That value then
propagates into SARIF, the terminal table and `CalculateRiskScore`. Reproduced in under
5 seconds by `FuzzParseOutput`; fixed by rejecting results with a non-positive line or
an empty path. The failing corpus entry is kept at
`internal/adapters/semgrep/testdata/fuzz/FuzzParseOutput/` as a permanent regression.

**P-06 — lite-mode honesty.** Embedded SAST coverage now reports
`embedded regex subset (no taint tracking); install semgrep for full SAST` instead of a
bare `RAN`, so the coverage table cannot imply Semgrep-equivalent analysis.

---

## Honest status of every phase

| Phase | Status | Note |
|---|---|---|
| 0 — Stop the bleeding | **Complete** | P-01, P-02, P-04, P-20 fixed and covered by tests |
| 1 — Truthful tests | **Complete** | `rules test` does real parse + behavioural checks; `e2e-full` gates CI; rule counts computed |
| 2 — Detection quality | **Partial** | P-06/P-07/P-08/P-15 done. Benchmark corpus is **6 items**, not a benchmark |
| 3 — CLI consistency | **Complete** | `--all`/`--quick` profiles, shortcut parity, `explain` cache, provenance polish |
| 4 — Correlation & scoring | **Mostly complete** | Taxonomy + reachability shipped; no EPSS/CISA-KEV lookup |
| 5 — Real remediation | **Partial** | Dependency bumps, secret rotation, IaC/Dockerfile, 7 SAST templates. No AI-assisted patches |
| 6 — Extension quality | **Partial** | 9 unit suites + VSIX packaging. **No `@vscode/test-electron`**, so no real-editor test |
| 7 — Supply chain / legal | **Partial** | Pinned checksums, `THIRD_PARTY_NOTICES.md`, fuzzing **now present**. **No cosign/SLSA signing** |
| 8 — Docs & release | **In progress** | Overstated claims removed; a stranger has not reproduced the demo |
| 9 — Cloud/team mode | **Not started** | Deliberately deferred; local mode must be stable first |

### What is genuinely still missing

1. **Detection corpus is 6 findings.** Any precision/recall figure from it is noise. This
   is the single biggest gap for a credible "vuln finder" claim.
2. **No signed releases or SLSA provenance** (Phase 7).
3. **No real-editor extension test** (Phase 6) — the extension is only mock-tested.
4. **No EPSS/KVE enrichment** (Phase 4).
5. **No AI-assisted remediation** (Phase 5).
6. **Cloud/team mode** (Phase 9) — not started, by design.

None of these are hidden: each is reflected in `README.md` Known Limitations and in the
phase table above.
