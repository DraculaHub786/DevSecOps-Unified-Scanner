package orchestrator

import (
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
