# Commit Guard — making "flag before commit/push" actually work

Motivated by a direct test. I created a git repo containing
`const K = 'AKIAIOSFODNN7EXAMPLE';` and ran `git commit`. **It succeeded.**

## What I observed

| Test | Result |
|---|---|
| `git commit` with a real AWS key, after `install-hooks` was *not* run | committed — nothing blocked it |
| `sentinel scan --fail-on=high --ci` inside a fresh repo | **exit 2** `scanner ran in 'lite' mode with embedded engines` |
| Same, with a secret present | never reached the secret — died on the engine check first |

## Why it is broken (three independent reasons)

**G-01 — The hook is opt-in and silently absent.** `install-hooks` must be run
manually. Nothing warns when it is missing, so a user believes they are protected
when they are not.

**G-02 — The hook scans the whole repository, every commit.** The generated hook runs
`sentinel scan --fail-on=high --ci`. That is a full-tree scan. On any repo of real size
this takes seconds-to-minutes per commit, so developers will disable it. It also reports
pre-existing findings the developer did not introduce, which is the fastest way to get a
hook uninstalled.

**G-03 — The hook fails on the engine check, not on the finding.** `--ci` refuses to run
when any external engine is missing. In a repo where the developer has not installed
Semgrep/Gitleaks/Trivy, the hook exits `2` with `scanner ran in 'lite' mode`, which:
- does not mention the secret at all,
- is indistinguishable from an infrastructure error,
- means the hook blocks commits for the *wrong reason* or (with `--allow-lite`) not at all.

A pre-commit check must be **fast, offline, and dependency-free**, because it runs on
every developer machine, including ones that have never run `plugins/install.sh`.

## What a real guard needs

1. **Only the staged/changed files.** `git diff --cached --name-only --diff-filter=ACM`.
2. **Only the checks that are fast enough to run per-commit:** secrets and a SAST subset.
   Dependency and container scanning belong in pre-push or CI, not per-commit.
3. **No external engine required.** The embedded regex engine must be sufficient. If an
   external tool happens to be present, use it for depth, but never *require* it.
4. **Distinct exit codes:** `0` clean, `1` finding over threshold, `2` genuine error.
5. **A message that names the file, line, rule and remediation** — not an engine error.
6. **A bypass that is explicit and logged:** `SENTINEL_SKIP=1 git commit`.

## Implementation

### 1. New command: `sentinel guard`

```
sentinel guard [--stage pre-commit|pre-push] [--fail-on=high] [--all]
```

- `pre-commit` → staged files, secrets + SAST, embedded-only unless an engine is found.
- `pre-push`   → files changed vs the tracked upstream branch, adds dependency scan.
- `--all`      → scan the whole tree (used by CI, not by hooks).

The command resolves file lists from git itself, so it never scans unrelated files.

### 2. Rewritten `install-hooks`

Installs `.git/hooks/pre-commit` and `.git/hooks/pre-push` that call
`sentinel guard`. The hook resolves the Sentinel binary path at install time and bakes
it in, because `PATH` inside a git hook is frequently not the developer's interactive
`PATH` — this was the second reason a naive hook silently does nothing.

The hook also refuses to fail *open*: if it cannot find the binary it prints a loud
warning and exits 0 only when `SENTINEL_SKIP=1` is set, so a broken install is visible
rather than silent.

### 3. Fix the engine gate

`guard` must not use `--ci`'s "all engines present" requirement. Add an engine policy
`EnginePolicyAllowEmbedded` used by guard, so a machine without external tools still gets
a real secrets + SAST check instead of an infrastructure error.

## Acceptance tests

- [ ] Repo with a staged AWS key → `git commit` is **blocked**, output names `app.js:1` and the rule
- [ ] Repo with a staged clean file → commit **succeeds**, under 2 seconds
- [ ] Machine without Semgrep/Gitleaks → guard still blocks the key (embedded engine)
- [ ] `SENTINEL_SKIP=1 git commit` bypasses, and says so
- [ ] 10 000-file repo → guard runs in under 3 seconds because it only reads staged files
- [ ] `git push` blocked when the pushed range contains a secret, allowed when it does not

## Scale defect found while testing (separate from the hook)

`osv.checkReachability` walks the **entire repository** once per vulnerable package. On a
repo with N packages and F files that is O(N x F) file reads. On a 10k-file project with
50 vulnerable dependencies this is 500 000 reads. Fix: build the import index once per
scan and look up per package.
