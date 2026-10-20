package orchestrator

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// CorrelateAndDeduplicate merges findings across multiple scanners, removes duplicate
// alerts for the same vulnerability/file/line, and keeps the highest severity and richest remediation.
func CorrelateAndDeduplicate(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	type dedupKey struct {
		cve  string
		file string
		line int
		cwe  string
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

		// Construct primary key
		var key string
		if f.CVE != "" && f.File != "" {
			key = fmt.Sprintf("cve:%s:%s:%d", strings.ToUpper(f.CVE), f.File, f.LineStart)
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

		// 2. Combine sources (e.g. "osv+trivy")
		if !strings.Contains(existing.Source, f.Source) {
			existing.Source = fmt.Sprintf("%s+%s", existing.Source, f.Source)
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

		// 6. Inherit reachability if known
		if existing.Reachable == nil && f.Reachable != nil {
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
		result = append(result, *merged[k])
	}

	return result
}
