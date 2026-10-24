# Sentinel Contextual Risk Scoring Specification

Sentinel computes a continuous risk score from **0.0 to 100.0** for every detected vulnerability or misconfiguration. Unlike raw CVSS which is purely context-free, Sentinel adjusts risk based on **local repository context, exposure, and reachability**.

---

## 📐 Scoring Formula

The final risk score is computed as:

$$\text{FinalScore} = \min\left(100.0, \; \max\left(0.0, \; (\text{BaseScore} \times \text{ReachabilityMultiplier} \times \text{ExposureMultiplier}) + \text{CategoryBonus}\right)\right)$$

### 1. Base Score (Severity + CVSS)

Base severity provides the anchor score:

| Severity | Anchor Score |
| :--- | :--- |
| **Critical** | 45.0 |
| **High** | 35.0 |
| **Medium** | 22.0 |
| **Low** | 12.0 |
| **Info** | 4.0 |

If a **CVSS** score ($0.0 \le \text{CVSS} \le 10.0$) is available from OSV or Semgrep metadata:
$$\text{BaseScore} = (\text{BaseScore} \times 0.6) + \left(\frac{\text{CVSS}}{10.0} \times 40.0\right)$$

### 2. Reachability Multiplier (P-13)

Sentinel evaluates dependency reachability with honest, transparent tiers rather than binary assumptions:

- **`proven`** ($\times 1.35$): Call-graph level execution path verified to invoke vulnerable symbols (e.g., via `govulncheck` trace).
- **`imported`** ($\times 1.25$): Actively imported by non-test application source code (`.js`, `.ts`, `.py`, `.go`, `.java`). Test fixtures (`*_test.go`, `test_*.py`, `.spec.ts`) are excluded to avoid false inflation.
- **`unimported`** ($\times 0.65$): Declared in `package.json`, `requirements.txt`, or lockfiles, but never imported in application code. Automatically deprioritized.
- **Unspecified / Default** ($\times 1.00$): Used when language reachability analysis is not applicable.

### 3. Exposure Multiplier

Determined from repository file path structure and threat model analysis:
- **Public Entry Point** (HTTP routes, controllers, API handlers, ingress): $\times 1.20 - 1.25$
- **Internal / Non-exposed**: $\times 1.00$
- **Test / Mock Fixtures** (`*_test.go`, `test/`, `fixtures/`, `mock/`): $\times 0.60$

### 4. Category Bonus

- **Exposed Secret / Credential (`secret`)**: $+15.0$ points bonus. (Hardcoded API keys, tokens, and private keys pose immediate exploitation risk regardless of code complexity).

---

## 📊 Worked Examples

### Example A: Leaked GitHub Personal Access Token in `server.js`
- Severity: `Critical` (Anchor: 45.0)
- Exposure: Entry point (`server.js`) $\to \times 1.2$
- Category: `Secret` $\to +15.0$
- Final Score: $(45.0 \times 1.2) + 15.0 = \mathbf{69.0}$ / 100

### Example B: Critical Command Injection in `server.js:12`
- Severity: `Critical` (Anchor: 45.0)
- CVSS: 7.8 $\to (45.0 \times 0.6) + (0.78 \times 40.0) = 58.2$
- Exposure: `server.js` $\to \times 1.2$
- Final Score: $58.2 \times 1.2 = \mathbf{69.8}$ / 100

### Example C: Vulnerable Transitive Dependency in Unused Package
- Severity: `High` (Anchor: 35.0), CVSS: 7.5 $\to 51.0$
- Reachability: Unreachable (`false`) $\to \times 0.65$
- Final Score: $51.0 \times 0.65 = \mathbf{33.1}$ / 100 (automatically deprioritized)
