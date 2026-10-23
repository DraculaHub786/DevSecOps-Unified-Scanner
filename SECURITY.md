# Security Policy

## Supported Versions

| Version    | Supported          |
| ---------- | ------------------ |
| 1.0.x-rc   | :white_check_mark: |
| 1.0.x      | :white_check_mark: |
| < 1.0      | :x:                |

## Reporting a Vulnerability

We take the security of Sentinel DevSecOps Scanner seriously. If you believe you have found a security vulnerability in Sentinel, please report it immediately rather than opening a public issue.

- **Email**: `security@sentinel.dev` (or open a Private Vulnerability Advisory on GitHub)
- **Response Time**: You will receive an acknowledgment within 48 hours.
- **Coordination**: We will work with you to understand the issue, validate a patch, and coordinate a disclosure timeline.

## Authorized-Use Notice (DAST & Network Scanning)

Sentinel incorporates dynamic application security testing (DAST) capabilities.
- **Strict Requirement**: Running scans against live web applications, networks, or host infrastructure requires explicit, written authorization from the owner of that system.
- Scanning unauthorized targets is illegal under international computer misuse laws (such as the United States Computer Fraud and Abuse Act - CFAA).
- Sentinel enforces `--i-have-authorization` flags, domain allowlists, and blocks private/loopback/metadata IP ranges by default.
