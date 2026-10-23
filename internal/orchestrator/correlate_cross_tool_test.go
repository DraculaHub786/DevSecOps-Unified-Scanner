package orchestrator

import (
	"strings"
	"testing"
)

func TestCorrelateCrossToolDeduplication(t *testing.T) {
	// Simulated OSV finding
	osvFinding := Finding{
		ID:          "osv-1",
		Source:      "osv",
		Engine:      EngineExternal,
		Category:    CategorySCA,
		Rule:        "GHSA-1234",
		CVE:         "CVE-2023-1234",
		Severity:    SeverityMedium,
		CVSS:        5.5,
		File:        "package.json",
		LineStart:   10,
		Message:     "Prototype pollution in lodash",
		Fingerprint: "fp-1234",
	}

	// Simulated Trivy finding for the same CVE and file
	trivyFinding := Finding{
		ID:          "trivy-1",
		Source:      "trivy",
		Engine:      EngineExternal,
		Category:    CategorySCA,
		Rule:        "CVE-2023-1234",
		CVE:         "CVE-2023-1234",
		Severity:    SeverityHigh,
		CVSS:        7.8,
		File:        "package.json",
		LineStart:   10,
		Message:     "Lodash prototype pollution vulnerability",
		Fingerprint: "fp-5678",
	}

	merged := CorrelateAndDeduplicate([]Finding{osvFinding, trivyFinding})
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}

	res := merged[0]
	// Verify highest severity was retained
	if res.Severity != SeverityHigh {
		t.Errorf("expected merged severity High, got %s", res.Severity)
	}
	// Verify sources combined
	if res.Source != "osv+trivy" {
		t.Errorf("expected combined source 'osv+trivy', got %q", res.Source)
	}
	// Verify highest CVSS kept
	if res.CVSS != 7.8 {
		t.Errorf("expected CVSS 7.8, got %f", res.CVSS)
	}
}

func TestCorrelateSecretFindingsAcrossTools(t *testing.T) {
	gitleaksSecret := Finding{
		ID:          "gitleaks-sec-1",
		Source:      "gitleaks",
		Engine:      EngineExternal,
		Category:    CategorySecret,
		Rule:        "aws-access-key-id",
		Severity:    SeverityCritical,
		File:        "server.js",
		LineStart:   7,
		LineEnd:     7,
		Message:     "Identified hardcoded AWS Access Key ID (Redacted: AKI***PLE)",
		Snippet:     "AKI***PLE",
		Fingerprint: "fp-gitleaks-aws",
	}

	semgrepSecret := Finding{
		ID:          "semgrep-sec-1",
		Source:      "semgrep",
		Engine:      EngineExternal,
		Category:    CategorySecret,
		Rule:        "org-hardcoded-aws-credentials",
		Severity:    SeverityHigh,
		File:        "server.js",
		LineStart:   7,
		LineEnd:     7,
		Message:     "Hardcoded AWS Access Key ID detected",
		Snippet:     "[REDACTED_SECRET]",
		Fingerprint: "fp-semgrep-aws",
	}

	merged := CorrelateAndDeduplicate([]Finding{gitleaksSecret, semgrepSecret})
	if len(merged) != 1 {
		t.Fatalf("expected 1 correlated secret finding, got %d", len(merged))
	}

	res := merged[0]
	if res.Category != CategorySecret {
		t.Errorf("expected category Secret, got %s", res.Category)
	}
	if res.Severity != SeverityCritical {
		t.Errorf("expected highest severity Critical, got %s", res.Severity)
	}
	if res.Source != "gitleaks+semgrep" {
		t.Errorf("expected combined source 'gitleaks+semgrep', got %q", res.Source)
	}
	if res.File != "server.js" || res.LineStart != 7 {
		t.Errorf("expected file server.js:7, got %s:%d", res.File, res.LineStart)
	}
}

func TestCorrelateGovulncheckReachabilityPrecedence(t *testing.T) {
	bFalse := false
	bTrue := true

	// Heuristic OSV finding on go.mod (unreachable heuristic)
	osvFinding := Finding{
		ID:          "osv-go-1",
		Source:      "osv",
		Engine:      EngineExternal,
		Category:    CategorySCA,
		Rule:        "CVE-2023-24538",
		CVE:         "CVE-2023-24538",
		Severity:    SeverityHigh,
		CVSS:        7.5,
		File:        "go.mod",
		LineStart:   1,
		Message:     "HTML/template vulnerability [Reachability: heuristic]",
		Snippet:     "html/template@v1.20.0",
		Reachable:   &bFalse,
		Fingerprint: "fp-osv-go",
	}

	// Proven govulncheck finding with call stack trace
	govulnFinding := Finding{
		ID:          "govuln-1",
		Source:      "govulncheck",
		Engine:      EngineExternal,
		Category:    CategorySCA,
		Rule:        "CVE-2023-24538",
		CVE:         "CVE-2023-24538",
		Severity:    SeverityHigh,
		CVSS:        7.5,
		File:        "go.mod",
		LineStart:   1,
		Message:     "HTML/template vulnerability [Reachability: proven (govulncheck)]",
		Snippet:     "main.main (main.go:42) -> html/template.Parse (template.go:105)",
		Reachable:   &bTrue,
		Fingerprint: "fp-govuln-go",
	}

	merged := CorrelateAndDeduplicate([]Finding{osvFinding, govulnFinding})
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}

	res := merged[0]
	if res.Source != "osv+govulncheck" {
		t.Errorf("expected combined source 'osv+govulncheck', got %q", res.Source)
	}
	if res.Reachable == nil || !*res.Reachable {
		t.Errorf("expected govulncheck proven reachability (true) to override heuristic (false)")
	}
	if !strings.Contains(res.Snippet, "main.main") {
		t.Errorf("expected call stack snippet to be preserved, got: %s", res.Snippet)
	}
	if !strings.Contains(res.Message, "[Reachability: proven (govulncheck)]") {
		t.Errorf("expected message to show proven reachability, got: %s", res.Message)
	}
}
