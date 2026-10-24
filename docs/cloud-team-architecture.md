# Sentinel Cloud & Self-Hosted Team Mode Architecture

**Version:** 1.0 (Phase 9 Specification)  
**Status:** Architecture Design & Self-Hosted Reference Specification  

This document specifies the architectural model for **Sentinel Team / Cloud Mode**, providing centralized vulnerability management, multi-repository trend reporting, organization-wide policy enforcement, and GitHub/GitLab PR gating.

---

## 1. Core Principles

1. **Results-Only Ingestion**:
   - Only normalized security findings, SARIF metadata, dependency versions, and software bill of materials (SBOM) are transmitted.
   - **Zero proprietary source code, secrets, or commit trees are ever uploaded.**
   - All secret literals are automatically redacted (`sha256:...`) on the local scanner before serialization.
2. **Local or Self-Hosted First**:
   - Organizations can run Team Mode completely on-premises or within their own private VPC using the provided Docker Compose or Kubernetes manifests.
3. **Tenant & Data Isolation**:
   - Single-tenant isolation with cryptographic project tokens and role-based access control (RBAC).
   - In ephemeral worker mode, scan jobs run inside sandboxed containers (gVisor / Firecracker) with dedicated network policies.

---

## 2. Ingestion API Specification

### Endpoint: `POST /api/v1/scans/upload`

#### Authentication:
Bearer token issued per repository: `Authorization: Bearer st_live_<project_key>`

#### Request Payload:
```json
{
  "$schema": "https://sentinel.dev/schemas/v1/scan-result.json",
  "project_id": "proj_9f83a0bc",
  "branch": "main",
  "commit_sha": "a1b2c3d4e5f6789012345678901234567890abcd",
  "scanner_version": "1.0.2",
  "timestamp": "2026-10-24T20:55:00Z",
  "summary": {
    "total_findings": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  },
  "provenance": {
    "sast": "semgrep 1.182.0",
    "secrets": "gitleaks 8.30.1",
    "sca": "osv-scanner 2.7.0",
    "iac": "trivy 0.76.0",
    "resilience": "native"
  },
  "findings": [
    {
      "id": "SENT-0119773a7723",
      "category": "secret",
      "rule": "aws-access-key-id",
      "severity": "critical",
      "file": "server.js",
      "line_start": 7,
      "line_end": 7,
      "message": "Identified hardcoded AWS Access Key ID",
      "snippet": "AKIA****************",
      "risk_score": 69.0,
      "fingerprint": "a3b90f421d8e"
    }
  ]
}
```

#### Validation & Ingestion Controls:
1. Payload schema validation rejects untyped or malformed JSON.
2. Snippet validation ensures no unredacted high-entropy secret patterns exceed 16 characters.
3. Database upsert updates issue lifecycles: `new`, `open`, `resolved`, or `suppressed`.

---

## 3. Database Schema (PostgreSQL)

```sql
-- Multi-tenant Organization & Project tables
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    api_token_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan execution history
CREATE TABLE scan_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    branch VARCHAR(255) NOT NULL,
    commit_sha CHAR(40) NOT NULL,
    scanner_version VARCHAR(32) NOT NULL,
    findings_count INT NOT NULL DEFAULT 0,
    critical_count INT NOT NULL DEFAULT 0,
    high_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Normalized security findings across all scans
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    finding_id VARCHAR(64) NOT NULL,
    fingerprint CHAR(24) NOT NULL,
    category VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    cve VARCHAR(64),
    cwe VARCHAR(64),
    file_path TEXT NOT NULL,
    line_start INT NOT NULL,
    risk_score NUMERIC(4, 1) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'open', -- open, resolved, suppressed
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(project_id, fingerprint)
);
```

---

## 4. PR Gating & Policy Controls

Sentinel Team Mode integrates with GitHub / GitLab to act as a required status check:
- **Zero-Critical Policy**: Merges are blocked if any unresolved `Critical` severity finding is introduced in the PR branch.
- **Max Risk Score Gate**: Merges blocked if any finding exceeds `risk_score_max: 75.0`.
- **License Allowlist Gate**: Merges blocked if new dependencies use forbidden licenses (e.g. AGPL/GPL).

---

## 5. Self-Hosted On-Premises Deployment

To run Sentinel Team Mode on-premises inside your infrastructure:
```bash
cd deploy/team-mode
docker compose up -d
```

Services initialized:
- `sentinel-server`: Go backend API service (port 8080).
- `sentinel-db`: PostgreSQL 16 database with persistent volume.
- `sentinel-ui`: Lightweight React/Vite dashboard displaying scan trends and team metrics.
