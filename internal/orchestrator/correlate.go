package orchestrator

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// RuleTaxonomy maps tool-specific rule IDs to a canonical issue key (P-14). Two tools
// that describe the same underlying defect must map to the same key so correlation can
// merge them instead of reporting the issue twice.
var RuleTaxonomy = map[string]string{
	// --- Dockerfile / container misconfiguration ---
	// Trivy emits "DS-0001"; older builds used "AVD-DS-0001". Both are registered.
	"avd-ds-0001":                       "docker-latest-tag",
	"ds-0001":                           "docker-latest-tag",
	"ds001":                             "docker-latest-tag",
	"org-supplychain-docker-latest-tag": "docker-latest-tag",
	"docker-latest-tag":                 "docker-latest-tag",

	"avd-ds-0002":                      "docker-run-as-root",
	"ds-0002":                          "docker-run-as-root",
	"ds002":                            "docker-run-as-root",
	"org-supplychain-docker-root-user": "docker-run-as-root",
	"docker-run-as-root":               "docker-run-as-root",

	"avd-ds-0026":                           "docker-missing-healthcheck",
	"ds-0026":                               "docker-missing-healthcheck",
	"ds026":                                 "docker-missing-healthcheck",
	"org-supplychain-docker-no-healthcheck": "docker-missing-healthcheck",
	"docker-missing-healthcheck":            "docker-missing-healthcheck",

	// --- Secrets ---
	"github-pat":                    "secret-github-pat",
	"aws-access-key-id":             "secret-aws-access-key",
	"aws-secret-access-key":         "secret-aws-secret-key",
	"slack-bot-token":               "secret-slack-token",
	"slack-webhook-url":             "secret-slack-webhook",
	"org-hardcoded-github-token":    "secret-github-pat",
	"org-hardcoded-aws-credentials": "secret-aws-access-key",
	"org-hardcoded-slack-webhook":   "secret-slack-webhook",

	// --- Injection ---
	"org-js-sql-injection-concat":        "sast-sql-injection",
	"org-go-sql-injection-concat":        "sast-sql-injection",
	"org-go-sql-injection-sprintf":       "sast-sql-injection",
	"org-python-sql-injection-format":    "sast-sql-injection",
	"org-java-sql-injection-concat":      "sast-sql-injection",
	"org-js-command-injection-exec":      "sast-command-injection",
	"org-go-command-injection-sh":        "sast-command-injection",
	"org-python-command-injection-shell": "sast-command-injection",
	"org-java-command-injection-runtime": "sast-command-injection",

	// --- Transport / TLS ---
	"org-go-insecure-skip-verify":      "sast-tls-verify-disabled",
	"org-python-requests-verify-false": "sast-tls-verify-disabled",
	"org-js-reject-unauthorized-false": "sast-tls-verify-disabled",
}

// CanonicalIssueType resolves a rule into a canonical taxonomy issue key. Lookup is
// tolerant of the directory qualifier Semgrep adds ("rules.org-x"), of "avd-" prefixes,
// and of zero-padding differences ("DS-0001" vs "DS001") (B-02).
func CanonicalIssueType(category, rule string) string {
	lower := strings.ToLower(strings.TrimSpace(rule))
	if lower == "" {
		return ""
	}

	candidates := []string{lower}

	// Strip any directory qualifier: "rules.org-x" -> "org-x".
	if idx := strings.LastIndex(lower, "."); idx != -1 && idx < len(lower)-1 {
		candidates = append(candidates, lower[idx+1:])
	}

	// Normalise the Trivy "avd-ds-NNNN" / "ds-NNNN" / "dsNNN" family to a single form.
	for _, c := range candidates {
		trimmed := strings.TrimPrefix(c, "avd-")
		candidates = append(candidates, trimmed)
		if strings.HasPrefix(trimmed, "ds-") || strings.HasPrefix(trimmed, "ds0") {
			digits := strings.TrimLeft(trimmed, "ds-")
			digits = strings.TrimPrefix(digits, "ds")
			candidates = append(candidates, "ds-"+digits, "ds"+digits)
		}
	}

	for _, c := range candidates {
		if canon, ok := RuleTaxonomy[c]; ok {
			return canon
		}
	}
	return ""
}

// CorrelateAndDeduplicate merges findings across multiple scanners, removes duplicate
// alerts for the same vulnerability/file/line, and keeps the highest severity and richest remediation.
func CorrelateAndDeduplicate(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	merged := make(map[string]*Finding)
	order := make([]string, 0)

	for i := range findings {
		f := findings[i]
		f.File = filepath.ToSlash(f.File)

		// Set default first seen if zero
		if f.FirstSeen.IsZero() {
			f.FirstSeen = time.Now().UTC()
		}

		// Ensure deterministic fingerprint
		if f.Fingerprint == "" {
			f.Fingerprint = GenerateFingerprint(f.Category, f.Rule, f.File, f.Message)
		}

		if len(f.Sources) == 0 && f.Source != "" {
			f.Sources = []string{f.Source}
		}

		// Construct primary key using canonical taxonomy (P-14)
		var key string
		canonType := CanonicalIssueType(f.Category, f.Rule)
		if f.Category == CategorySecret && f.File != "" && f.LineStart > 0 {
			key = fmt.Sprintf("secret:%s:%d", f.File, f.LineStart)
		} else if f.CVE != "" && f.File != "" {
			// For SCA dependencies, key by CVE and manifest file (deduplicating across OSV, Trivy, govulncheck)
			key = fmt.Sprintf("cve:%s:%s", strings.ToUpper(f.CVE), f.File)
		} else if canonType != "" && f.File != "" && f.LineStart > 0 {
			// Canonical issue key: (category, normalized-issue-type, file, line) (P-14)
			key = fmt.Sprintf("canon:%s:%s:%d", canonType, f.File, f.LineStart)
		} else {
			key = fmt.Sprintf("fp:%s", f.Fingerprint)
		}

		existing, exists := merged[key]
		if !exists {
			fCopy := f
			merged[key] = &fCopy
			order = append(order, key)
			continue
		}

		// Merge existing finding with new finding:
		// 1. Keep highest severity
		if SeverityRank(f.Severity) > SeverityRank(existing.Severity) {
			existing.Severity = f.Severity
		}

		// 2. Combine sources (e.g. "gitleaks+semgrep", "osv+trivy", "osv+govulncheck")
		if !strings.Contains(existing.Source, f.Source) {
			existing.Source = fmt.Sprintf("%s+%s", existing.Source, f.Source)
		}
		if f.Source != "" {
			hasSource := false
			for _, s := range existing.Sources {
				if s == f.Source {
					hasSource = true
					break
				}
			}
			if !hasSource {
				existing.Sources = append(existing.Sources, f.Source)
			}
		}

		// 3. Ensure secret category is retained if either engine identified it as secret
		if f.Category == CategorySecret {
			existing.Category = CategorySecret
		}

		// 3. Keep highest CVSS
		if f.CVSS > existing.CVSS {
			existing.CVSS = f.CVSS
		}

		// 4. Fill in missing CWE/CVE
		if existing.CWE == "" && f.CWE != "" {
			existing.CWE = f.CWE
		}
		if existing.CVE == "" && f.CVE != "" {
			existing.CVE = f.CVE
		}

		// 5. Keep richer FixSuggestion
		if existing.FixSuggestion == nil && f.FixSuggestion != nil {
			existing.FixSuggestion = f.FixSuggestion
		} else if existing.FixSuggestion != nil && f.FixSuggestion != nil {
			if existing.FixSuggestion.Diff == "" && f.FixSuggestion.Diff != "" {
				existing.FixSuggestion = f.FixSuggestion
			}
		}

		// 6. Inherit reachability if known; govulncheck proven reachability takes precedence
		if f.ReachabilityLevel == "proven" || f.Source == "govulncheck" {
			existing.Reachable = f.Reachable
			existing.ReachabilityLevel = "proven"
			if f.Snippet != "" {
				existing.Snippet = f.Snippet
			}
			if strings.Contains(f.Message, "Reachability:") {
				existing.Message = f.Message
			}
		} else if existing.ReachabilityLevel == "proven" {
			// existing already has proven reachability
		} else if f.ReachabilityLevel == "imported" {
			existing.Reachable = f.Reachable
			existing.ReachabilityLevel = "imported"
		} else if existing.ReachabilityLevel == "" && f.ReachabilityLevel != "" {
			existing.ReachabilityLevel = f.ReachabilityLevel
			existing.Reachable = f.Reachable
		} else if existing.Reachable == nil && f.Reachable != nil {
			existing.Reachable = f.Reachable
		}

		if existing.Exposed == nil && f.Exposed != nil {
			existing.Exposed = f.Exposed
		}

		// 7. Engine provenance: prefer external if either tool was real external engine
		if existing.Engine != EngineExternal && f.Engine == EngineExternal {
			existing.Engine = EngineExternal
		}
	}

	result := make([]Finding, 0, len(order))
	for _, k := range order {
		item := merged[k]
		item.RiskScore = CalculateRiskScore(item)
		result = append(result, *item)
	}

	return result
}
