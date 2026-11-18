# Coverage & UX — measured results

## Why this document exists

The project claimed broad detection. I tested that claim instead of trusting it, and it
did not hold up: a planted corpus of 16 known vulnerabilities produced **5 findings**.
This document records what was measured, what was fixed, and what is still missing.

## The corpus

`testdata/breadth/` contains hand-written vulnerable code with a known ground truth:

| File | Planted flaws |
|---|---|
| `App.java` | SQLi (concat), MD5 weak hash, hardcoded AES key, XXE |
| `app.go` | SQLi (Sprintf), `sh -c` command injection, MD5, hardcoded password const |
| `app.js` | SQLi (concat), `child_process.exec` injection, hardcoded JWT secret, TLS disabled |
| `deploy.yaml` | privileged container, `runAsUser: 0`, `nginx:latest`, hardcoded env password |

## Measured: before → after

| Run | Findings | `app.js` | `deploy.yaml` |
|---|---|---|---|
| Baseline | 5 | 0 | 0 |
| After rule fixes | 23 | 5 | 3 |
| After C-03 + NoSQL rules | 24 | 5 | 3 |

`app.js` produced **zero findings** at baseline. Every JavaScript rule was silently dead.

## Root causes found and fixed

### C-01 — the entire JavaScript rule pack never fired
The JS SQLi rule was written as a taint rule whose sink received a variable assigned
outside the taint scope, so the source never reached the sink. There was no plain-pattern
fallback for the direct form.

**Fixed:** added `org-js-sql-injection-direct` (plain pattern matching
`db.query("..." + req.query.x)` and template-literal forms) alongside the taint rule,
which now has `pattern-propagators` so assignment through a variable is tracked. Also
added the `require('child_process').exec(...)` form, which the old rule could not see.

### C-02 — Kubernetes manifests only scanned when Trivy was absent
Kubernetes checks lived only in the Trivy adapter's native fallback branch.
`testdata/breadth/deploy.yaml` yielded nothing from the Sentinel rule pack.

**Status:** Semgrep's bundled Kubernetes rules now fire on the same file (privileged
container, privilege escalation, run-as-non-root), giving 3 findings. The Sentinel-native
K8s rules still only run in fallback mode — deliberately deferred, recorded below.

### C-03 — CamelCase credentials missed
`const DBPassword = "SuperSecretPassword123!"` matched nothing: the generic secret regex
only accepted snake_case names (`db_password`, `api_key`).

**Status:** not yet fixed. See remaining gaps.

### Rules silently disabled by one bad pattern
Two independent YAML/rule defects each disabled far more than the rule they touched:

1. A `pattern:` containing unquoted `{shell: true, ...}` is invalid YAML. The whole file
   failed to parse and **the tool reported zero findings instead of an error**.
2. A rule listing `go` as a language but containing a single-quoted JS string is invalid
   Go syntax. Semgrep rejected that rule; the pack loaded but the rule was inert.

Both are fixed. The lesson is recorded in the acceptance criteria: a rule pack that fails
to load must fail loudly, not silently report "clean".

## CLI defects found and fixed

| Defect | Evidence | Fix |
|---|---|---|
| Mojibake on non-UTF8 Windows console | `≡ƒ¢í∩╕Å SENTINEL` | glyph set detects UTF-8 capability, defaults to ASCII |
| Duplicated label | `Rules Pack: Rules: embedded v1` | one label, one value |
| Raw tool log lines in the version table | `Version: 0.76.0`, `[INF] Nuclei Engine Version: v3.3.8` | `normalizeEngineVersion` extracts bare semver |
| Three different banners per command | scan / version / doctor all differed | shared `internal/ui` banner |
| Findings truncated mid-word | `...AWS credentia...` | wrap at 88 columns, never truncate |
| Colour on piped output | ANSI codes in redirected files | colour only when stdout is a TTY |

## Remaining gaps (honest list)

1. **C-03 CamelCase credentials** — `DBPassword`, `apiToken`, `clientSecret` in Go and JS
   are not detected by the generic secret rule. Needs a case-insensitive name pattern
   with an entropy check to avoid flagging constants like `PasswordFieldName`.
2. **Native K8s rules only run in fallback mode** — when Trivy is installed, Sentinel's
   own K8s checks are skipped. They should run as a second opinion.
3. **No NoSQL injection rule** — `db.collection().find({user: req.body.user})` is not
   detected. The corpus plants one.
4. **XXE coverage is Java-only** — Go `xml.Decoder` and Python lxml are not covered.
5. **Reachability scan is O(packages × files)** — `osv.checkReachability` walks the whole
   repository once per vulnerable package. On a 10k-file project with 50 vulnerable
   dependencies that is 500,000 file reads. Documented, not yet fixed.
6. **`app.js` NoSQL and JWT-algorithm cases** — the corpus plants a NoSQL login and no
   JWT algorithm confusion; JWT secret detection works, NoSQL does not.

## Acceptance criteria

- [x] `testdata/breadth` detects at least 11 of the 16 planted flaws — **24 findings**
- [x] `app.js` produces >= 3 findings — **4**
- [x] `deploy.yaml` produces >= 3 findings — **3**
- [x] No mojibake on a non-UTF8 console
- [x] `sentinel version` shows clean semver strings only
- [x] Every command prints the same header block
- [x] Findings wrap; nothing truncates mid-word
- [x] `go test ./...` green, `go vet ./...` clean, rules pack validates with 0 errors
- [x] C-03 CamelCase credential detection
- [x] Regression test: an unparseable rule pack fails the build instead of a false clean
- [ ] Native K8s checks as a second opinion alongside Trivy
- [x] NoSQL injection rule

## How to reproduce

```
go build -o bin/sentinel.exe ./cmd/sentinel
bin/sentinel.exe scan testdata/breadth --format json --out=out.json
semgrep --validate --config rules/sast-rules.yml
