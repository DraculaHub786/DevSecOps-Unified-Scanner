# Sentinel CI/CD Integration & Security Gating

Sentinel is designed for seamless, tamper-resistant integration into modern continuous integration (CI) pipelines.

---

## 1. Process Exit Codes

Sentinel communicates scan status and gating results to CI workflows via standardized POSIX process exit codes:

| Exit Code | Status | Meaning | Recommended Pipeline Action |
|---|---|---|---|
| **`0`** | **PASS** | Scan completed successfully with zero findings at or above the failure threshold. | Allow build / merge to proceed. |
| **`1`** | **FAIL** | Security policy threshold violated. Findings detected with severity equal to or greater than `--fail-on`. | Block pipeline or require security review approval. |
| **`2`** | **ERROR** | Unrecoverable scanner failure, misconfiguration, or unhandled tool crash. | Fail the CI run immediately. |

---

## 2. Core CI Flags

| Flag | Default | Description |
|---|---|---|
| `--ci` | `false` | Enables strict CI mode: enforces non-interactive execution, evaluates failure thresholds, and verifies required scanner tools. |
| `--fail-on=<sev>` | `"high"` | Fails the pipeline (exit 1) on findings at or above this severity: `critical`, `high`, `medium`, or `low`. |
| `--format=<fmt>` | `"terminal"` | Report format: `sarif`, `json`, `terminal`, `markdown`, `html`, or `junit`. |
| `--out=<path>` | `""` | File path to write primary report output (e.g. `--out results.sarif`). |
| `--offline` | `false` | Strict zero-network mode. Blocks all external network egress. |
| `--trust-repo-policy` | `false` | Accepts `.sentinel.yml` located inside the scanned repo. By default, Sentinel ignores untrusted PR policy overrides. |
| `--allow-lite` | `false` | In `--ci`, allows embedded lite fallback engines to execute if external binaries (Semgrep, Trivy) are absent. |
| `--baseline` | `false` | Filters out pre-existing accepted baseline findings declared in `.sentinel/baseline.json`. |

---

## 3. GitHub Actions Integration

### 3.1 Standard PR Security Gate with SARIF Code Scanning

Add `.github/workflows/sentinel.yml` to your repository:

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  sentinel:
    name: Sentinel DevSecOps Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0

      - name: Run Sentinel Security Scan
        uses: DraculaHub786/DevSecOps-Unified-Scanner/deploy/github-actions/sentinel-scan@v1.0.0-rc1
        with:
          fail-on: high
          format: sarif
          out: results.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@9e8d0789d4a0fa618460e0086ab2d3ea880a416e # v3.26.0
        with:
          sarif_file: results.sarif
```

---

## 4. GitLab CI Integration

Add the following job to your `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

sentinel_security_scan:
  stage: security
  image: ghcr.io/draculahub786/devsecops-unified-scanner:v1.0.0-rc1
  script:
    - /usr/local/bin/sentinel scan . --ci --fail-on=high --format=junit --out=junit.xml --format=json --out=sentinel-report.json
  artifacts:
    when: always
    reports:
      junit: junit.xml
    paths:
      - sentinel-report.json
```

---

## 5. Local Pre-Commit Hook

Install Sentinel as a local git pre-commit hook to catch secrets and security flaws before pushing:

```bash
cat << 'EOF' > .git/hooks/pre-commit
#!/usr/bin/env bash
echo "🛡️  Running Sentinel pre-commit security check..."
sentinel scan --changed-only --fail-on=critical
EOF
chmod +x .git/hooks/pre-commit
```
