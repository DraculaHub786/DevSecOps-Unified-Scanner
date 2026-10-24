# Changelog - Sentinel VS Code Extension

All notable changes to the Sentinel VS Code extension are documented in this file.

## [1.0.2] - 2026-10-24

### Added
- **Multi-tiered Reachability**: Displays honest reachability labels (`proven`, `imported`, `unimported`) on SCA vulnerability diagnostics.
- **Canonical Issue Correlation**: Automatically merges overlapping findings from different scanners onto a shared taxonomy key (e.g., Trivy `AVD-DS-0001` and Semgrep container rules).
- **Automated Re-scan Verification**: Applying a Quick Fix automatically triggers an immediate incremental re-scan to verify that the flaw is resolved with zero regressions.
- **Provider-specific Secret Remediation**: Rich rotation checklists and automated environment variable replacement diffs for GitHub PATs, AWS Access Keys, and Slack tokens.
- **Deterministic IaC Patches**: Quick Fixes for Dockerfile unprivileged `USER 10001:10001`, pinned base images, and restricted CIDR blocks.

### Improved
- **Secure Hover Markdown**: Disarms arbitrary executable URI schemes in finding hover tooltips.
- **Debounced Scans**: Optimized on-save incremental scan debounce to prevent redundant agent invocations.
- **Loopback IPC Security**: Restrictive `0600` cryptographic token handshake with local `sentinel-agent` daemon.

## [1.0.1] - 2026-10-15

### Added
- Native resilience adapter labeling to distinguish first-party checks from missing third-party engines.
- Initial interactive explain webview panel and sidebar grouping by Severity, Category, and File.

## [1.0.0] - 2026-10-01

- Initial release of Sentinel DevSecOps Unified Scanner for VS Code.
