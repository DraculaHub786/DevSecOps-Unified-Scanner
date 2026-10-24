package orchestrator

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// RuleTaxonomy maps tool-specific rule IDs or patterns to a canonical issue key (P-14).
var RuleTaxonomy = map[string]string{
	// Dockerfile / Container rules
	"avd-ds-0001":                           "docker-latest-tag",
	"ds001":                                 "docker-latest-tag",
	"org-supplychain-docker-latest-tag":      "docker-latest-tag",
	"docker-latest-tag":                     "docker-latest-tag",

	"avd-ds-0002":                           "docker-run-as-root",
	"ds002":                                 "docker-run-as-root",
	"org-supplychain-docker-root-user":      "docker-run-as-root",
	"docker-run-as-root":                    "docker-run-as-root",

	"avd-ds-0026":                           "docker-missing-healthcheck",
	"ds026":                                 "docker-missing-healthcheck",
	"org-supplychain-docker-no-healthcheck": "docker-missing-healthcheck",
	"docker-missing-healthcheck":            "docker-missing-healthcheck",

	// Secrets rules
	"github-pat":                            "secret-github-pat",
	"aws-access-key-id":                     "secret-aws-access-key",
	"aws-secret-access-key":                 "secret-aws-secret-key",
	"slack-bot-token":                       "secret-slack-token",
	"slack-webhook-url":                     "secret-slack-webhook",

	// SAST / Web patterns
	"org-js-sql-injection-concat":           "sast-sql-injection",
	"org-go-sql-injection-concat":           "sast-sql-injection",
	"org-python-sql-injection-format":       "sast-sql-injection",
	"org-js-command-injection":              "sast-command-injection",
	"org-python-command-injection":          "sast-command-injection",
}

// CanonicalIssueType resolves a category and rule into a canonical taxonomy issue key.
func CanonicalIssueType(category, rule string) string {
	lower := strings.ToLower(strings.TrimSpace(rule))
	if canon, ok := RuleTaxonomy[lower]; ok {
		return canon
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
