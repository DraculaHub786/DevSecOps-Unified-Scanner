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

### 2. Reachability Multiplier (Heuristic)

> [!NOTE]
> Reachability analysis in v1.0 operates as an AST/token reference **heuristic**. It checks whether the imported module or package identifier is actually invoked or referenced in application source files.

- **Reachable** (`true`): $\times 1.35$ (active code path imports and references the vulnerable dependency)
- **Unreachable** (`false`): $\times 0.65$ (dormant, unused transitive dependency)
- **Unknown** (`nil`): $\times 1.00$

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
