# Third-Party Software Notices and Information

**Project:** Sentinel DevSecOps Unified Scanner  
**License:** Apache License 2.0  
**Repository:** https://github.com/DraculaHub786/DevSecOps-Unified-Scanner  

This document contains information on licenses and redistribution policies for third-party software, libraries, and security intelligence data used in or wrapped by Sentinel.

---

## 1. Architectural Distribution Model

Sentinel adheres to a **download-at-install / bring-your-own-tool** distribution pattern:
- The core Sentinel binaries (`sentinel`, `sentinel-agent`) and VS Code extension contain **zero redistributed third-party binary executables**.
- Third-party security engines are downloaded, verified against cryptographic SHA-256 checksums (`plugins/checksums.txt`), and installed directly onto the user's host during setup via `plugins/install.sh` or `plugins/install.ps1`.
- When external engines are absent or offline, Sentinel relies exclusively on its own clean-room native implementations (`resilience`, `threatmodel`) and embedded fallback patterns.

---

## 2. Wrapped External Security Scanning Engines

| Component | Upstream Project | License | Distribution Terms |
| :--- | :--- | :--- | :--- |
| **Gitleaks** | [zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) | MIT License | Permissive; installed directly from upstream GitHub releases. |
| **OSV-Scanner** | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache License 2.0 | Permissive; queries public OSV API; fallback embedded advisories. |
| **Trivy** | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache License 2.0 | Permissive; vulnerability and misconfiguration database downloaded on demand. |
| **Semgrep CLI** | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 | Free open-source engine CLI. Custom first-party rules shipped in `rules/` under Apache-2.0. Optional community packs subject to Semgrep Registry terms. |
| **Nuclei** | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | MIT License | Permissive DAST runner; invoked strictly in passive mode with explicit user authorization. |

---

## 3. Direct Go Dependencies

The Sentinel Go binaries are statically compiled with the following open-source dependencies:

- **`github.com/spf13/cobra`**
  - License: Apache License 2.0
  - Copyright (c) Steve Francia, 2013-present
- **`github.com/spf13/pflag`**
  - License: BSD 3-Clause "New" or "Revised" License
  - Copyright (c) 2012 Alex Ogier, Steve Francia
- **`gopkg.in/yaml.v3`**
  - License: Apache License 2.0 / MIT License
  - Copyright (c) 2006-2010 Kirill Simonov, 2011-2019 Canonical Ltd
- **`github.com/owenrumney/go-sarif/v2`**
  - License: MIT License
  - Copyright (c) 2021 Owen Rumney

---

## 4. Vulnerability Data & Security Taxonomies

- **OSV (Open Source Vulnerability) Schema**:
  - Maintained by Google and the OpenSSF.
  - License: Creative Commons Attribution 4.0 International (CC-BY 4.0).
- **Common Weakness Enumeration (CWE™)**:
  - Maintained by The MITRE Corporation.
  - Used under MITRE CWE terms of use for security flaw classification.
- **OWASP® Top 10**:
  - Maintained by the Open Web Application Security Project (OWASP Foundation).
  - License: Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0).
