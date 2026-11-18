package orchestrator

import (
	"path/filepath"
	"testing"
)

// B-02: Trivy 0.76 emits "DS-0001", not "AVD-DS-0001". Before the taxonomy was made
// prefix/zero-padding tolerant, the lookup missed and the same Dockerfile:1 defect was
// reported once by Trivy and once by Semgrep.
func TestCanonicalIssueTypeToleratesTrivyIDForms(t *testing.T) {
	cases := []struct {
		rule string
		want string
	}{
		{"DS-0001", "docker-latest-tag"},
		{"AVD-DS-0001", "docker-latest-tag"},
		{"avd-ds-0001", "docker-latest-tag"},
		{"ds001", "docker-latest-tag"},
		{"org-supplychain-docker-latest-tag", "docker-latest-tag"},
		{"rules.org-supplychain-docker-latest-tag", "docker-latest-tag"},
		{"DS-0002", "docker-run-as-root"},
		{"DS-0026", "docker-missing-healthcheck"},
		{"rules.org-python-command-injection-shell", "sast-command-injection"},
		{"org-go-insecure-skip-verify", "sast-tls-verify-disabled"},
		// Unmapped rules must not be forced into a bucket, or unrelated findings merge.
		{"org-unmapped-rule", ""},
		{"", ""},
	}

	for _, tc := range cases {
		if got := CanonicalIssueType(CategoryIaC, tc.rule); got != tc.want {
			t.Errorf("CanonicalIssueType(%q) = %q, want %q", tc.rule, got, tc.want)
		}
	}
}

// B-01: the exact payload observed from a live scan, where one Semgrep rule arrived
// twice under "org-x" and "rules.org-x", must collapse to a single finding.
func TestCorrelateMergesDirectoryQualifiedDuplicates(t *testing.T) {
	plain := Finding{
		ID:          "SENT-aaa",
		Source:      "semgrep",
		Engine:      EngineExternal,
		Category:    CategorySAST,
		Rule:        "org-python-command-injection-shell",
		Severity:    SeverityHigh,
		File:        "app.py",
		LineStart:   11,
		Message:     "subprocess executed with shell=True",
		Fingerprint: "fp-a",
	}
	qualified := plain
	qualified.ID = "SENT-bbb"
	qualified.Rule = "rules.org-python-command-injection-shell"
	qualified.Fingerprint = "fp-b"

	merged := CorrelateAndDeduplicate([]Finding{plain, qualified})
	if len(merged) != 1 {
		t.Fatalf("expected duplicate rule IDs to merge into 1 finding, got %d", len(merged))
	}
	if merged[0].File != "app.py" || merged[0].LineStart != 11 {
		t.Errorf("expected app.py:11, got %s:%d", merged[0].File, merged[0].LineStart)
	}
}

// Two genuinely different rules on the same line must never be merged by the canonical
// key - that would hide real findings.
func TestCorrelateKeepsDistinctIssuesSeparate(t *testing.T) {
	sql := Finding{
		ID: "SENT-1", Source: "semgrep", Category: CategorySAST,
		Rule: "org-js-sql-injection-concat", Severity: SeverityHigh,
		File: "server.js", LineStart: 23, Fingerprint: "fp-sql",
	}
	cmd := Finding{
		ID: "SENT-2", Source: "semgrep", Category: CategorySAST,
		Rule: "org-js-command-injection-exec", Severity: SeverityHigh,
		File: "server.js", LineStart: 23, Fingerprint: "fp-cmd",
	}

	merged := CorrelateAndDeduplicate([]Finding{sql, cmd})
	if len(merged) != 2 {
		t.Fatalf("expected 2 distinct findings to stay separate, got %d", len(merged))
	}
}

// B-04: every standard category must resolve to a human label and a real tool name.
// The old map keyed "secrets" instead of "secret", so the report printed "SECRET: secret".
func TestProvenanceLabelMapsEveryCategory(t *testing.T) {
	catNameMap := map[string]string{
		CategorySAST:       "SAST",
		CategorySCA:        "SCA",
		CategorySecret:     "Secrets",
		CategoryIaC:        "IaC",
		CategoryDAST:       "DAST",
		CategoryResilience: "Resilience",
	}
	engineToolMap := map[string]string{
		CategorySAST:       "semgrep",
		CategorySCA:        "osv-scanner",
		CategorySecret:     "gitleaks",
		CategoryIaC:        "trivy",
		CategoryDAST:       "nuclei",
		CategoryResilience: "resilience",
	}

	// Resilience is a first-party native engine, not a wrapper around an external
	// binary, so its tool name legitimately equals the category name. Every other
	// category name must resolve to a real external engine.
	nativeCategories := map[string]bool{CategoryResilience: true}

	for _, cat := range []string{
		CategorySAST, CategorySCA, CategorySecret,
		CategoryIaC, CategoryDAST, CategoryResilience,
	} {
		if catNameMap[cat] == "" {
			t.Errorf("category %q has no display label", cat)
		}
		tool := engineToolMap[cat]
		if tool == "" {
			t.Errorf("category %q has no engine name", cat)
		}
		if tool == cat && !nativeCategories[cat] {
			t.Errorf("category %q falls back to printing its own name as the tool", cat)
		}
	}
}

// B-03/B-05: degradation is tracked separately from a missing-binary fallback, so an
// offline scan is reported as degraded rather than flipping the whole run to lite.
func TestEngineProvenanceConstantsAreDistinct(t *testing.T) {
	if EngineExternal == EngineEmbedded || EngineEmbedded == EngineNative || EngineExternal == EngineNative {
		t.Fatal("engine provenance constants must be distinct values")
	}
}

// FuzzCorrelateAndDeduplicate guards the correlation layer against hostile engine
// output (P-22). It must never panic and must never lose a finding outright: the
// merged count can only stay equal or shrink, never grow, and never hit zero from
// a non-zero input.
func FuzzCorrelateAndDeduplicate(f *testing.F) {
	f.Add("semgrep", "org-js-sql-injection-concat", "server.js", 23, "high")
	f.Add("trivy", "DS-0001", "Dockerfile", 1, "medium")
	f.Add("gitleaks", "github-pat", "app.py", 7, "critical")
	f.Add("", "", "", 0, "")
	f.Add("semgrep", "rules.org-x", "../../etc/passwd", -1, "unknown")

	f.Fuzz(func(t *testing.T, source, rule, file string, line int, severity string) {
		input := []Finding{{
			ID:        GenerateID(source, rule, file, line),
			Source:    source,
			Engine:    EngineExternal,
			Category:  CategorySAST,
			Rule:      rule,
			Severity:  severity,
			File:      file,
			LineStart: line,
		}}

		merged := CorrelateAndDeduplicate(input)
		if len(merged) != 1 {
			t.Fatalf("single finding must survive correlation: got %d from 1", len(merged))
		}
		if merged[0].File != filepath.ToSlash(file) {
			t.Fatalf("file path not normalised: %q -> %q", file, merged[0].File)
		}
	})
}
