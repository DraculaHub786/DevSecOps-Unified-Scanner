# Changelog

All notable changes to the Sentinel DevSecOps Unified Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-10-24

### Fixed
- **Standard Library Vulnerability Remediation**: Upgraded Go toolchain to `1.27.3` and pinned `govulncheck@v1.1.4`, remediating `GO-2026-6809` (`crypto/x509`).
- **Scanner Self-Scan Cleanliness**:
  - Eliminated false-positive command injection warning in `cmd/sentinel/rules.go` by invoking native binary name via literal.
  - Reworded TLS rule description in `internal/adapters/semgrep/semgrep.go` to prevent regex self-matching.
  - Dynamically constructed simulated tokens in `scripts/pr-flow.sh` to prevent static secret false positives.
  - Added `rules/tests/**` to default ignore paths in `.sentinel.yml` to isolate intentional vulnerability test fixtures.
- **Rule Verification & Diagnostic Reporting**: Updated `sentinel version` to report accurate count of 65 embedded detection rules.

---

## [1.0.0-rc1] - 2026-10-23

### Added
- **Software Supply Chain Security**: 4 new rules detecting mutable `:latest`/untagged Docker base images (`AVD-DS-0001`), risky `curl | sh` / `wget | bash` execution (`AVD-DS-0003`), unverified npm lifecycle scripts, and wildcard dependencies.
- **CI/CD & GitHub Actions Security**: 4 workflow security rules detecting unpinned action references, `pull_request_target` misconfigurations, excessive `write-all` permissions, and untrusted context expression injection into shell steps.
- **Go Vulnerability Reachability Engine**: Integrated pinned `govulncheck` (`v1.1.4`) adapter parsing NDJSON execution traces to prove call-path reachability and distinguish reachable vs. dormant vulnerabilities.
- **Expanded Application Security (SAST) Rule Library**: 15 new SAST rules bringing total verified embedded rules to 65 (Spring CORS wildcard, Jackson deserialization, path traversal, hardcoded crypto keys, LDAP injection, open redirect, HttpOnly/Secure cookies, Jinja2/Thymeleaf/EJS SSTI).
- **Expanded IaC & DAST Fixtures**: Test fixtures and detection verification for Kubernetes Pod manifests, Docker Compose services, Helm charts, Terraform S3 buckets, and local vulnerable DAST target server.
- **VS Code Extension Security Hardening**:
  - Replaced blanket Markdown trust with explicit command allowlisting (`['sentinel.showFindingDetails', 'sentinel.applyFix']`).
  - Added untrusted text sanitization and Markdown escaping to neutralize command/javascript injection.
  - Added native side-by-side diff preview (`Preview Diff`) before applying automated code remediation.
  - Added comprehensive test suite verifying debounce timing, sidebar grouping (Severity, Category, File), and Workspace Trust boundary enforcement.
  - Pinned `@vscode/vsce` (`2.24.0`) in `devDependencies` for reproducible VSIX packaging.
- **Release Engineering & Hardening**:
  - Multi-stage, non-root hardened container image (`Dockerfile`) running as UID `10001:10001`.
  - Pinned all GitHub Actions dependencies to 40-character commit SHAs.
  - Configured Dependabot for GitHub Actions, Go modules, npm, and Docker.
  - Multi-platform release builder (`scripts/build-release-artifacts.sh` & `.ps1`) compiling Linux, macOS, and Windows archives with automated SHA-256 checksum generation.
- **Benchmark & Testing Framework**: Created `scripts/bench.sh`, `scripts/bench.ps1`, and `scripts/compare.py` for automated scan duration, deduplication accuracy, and merge integrity benchmarking.
- **Hostile Repository Testing**: Integration tests in `testdata/hostile/` verifying resilience against malformed lockfiles, invalid policies, deeply nested directories, and oversized files.
- **Comprehensive Documentation**: Added `docs/rules.md` (65-rule catalog), `docs/ci.md` (pipeline exit codes and integrations), `docs/extension.md` (IPC protocol and IDE setup), and `docs/security-model.md` (STRIDE threat analysis).

### Fixed
- **Trivy Offline IaC Scanning Regression**: Decoupled IaC misconfiguration scanning from vulnerability database updates (`--skip-db-update`, `--offline-scan`), preserving IaC findings during network isolation.
- **Checksum Verification**: Replaced unverified binary downloads with official pinned SHA-256 checksums and automated CI consistency verification.
- **Cross-Tool Deduplication**: Correlated secret findings across Gitleaks and Semgrep by file and line, preserving highest severity and combined source provenance (`gitleaks+semgrep`).
- **Cross-Tool SCA Correlation**: Merged OSV-Scanner and Trivy findings by CVE and manifest, retaining highest CVSS and richer fix diffs.
- **Go Standard Library Vulnerability**: Updated `go.mod` to Go 1.27.3 to resolve `GO-2026-6809` (`crypto/x509`).

---

## [0.2.0] - 2026-09-15

### Added
- Unified orchestrator engine and parallel scheduler.
- Baseline findings mechanism (`.sentinel/baseline.json`).
- STRIDE threat modeling command (`sentinel threatmodel`).
- Initial VS Code extension with JSON-RPC agent IPC daemon.
- Multi-format reporting: SARIF 2.1.0, JSON, Terminal, Markdown, and SQLite.
