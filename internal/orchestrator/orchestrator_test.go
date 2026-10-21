package orchestrator

import (
	"testing"
	"time"
)

func TestCorrelateAndDeduplicate(t *testing.T) {
	reachableTrue := true
	findings := []Finding{
		{
			ID:          "1",
			Source:      "osv",
			Category:    CategorySCA,
			Rule:        "CVE-2021-23337",
			Severity:    SeverityMedium,
			CVE:         "CVE-2021-23337",
			CVSS:        5.0,
			File:        "package.json",
			LineStart:   10,
			Message:     "Command injection in lodash",
			Reachable:   &reachableTrue,
			FirstSeen:   time.Now(),
		},
		{
			ID:          "2",
			Source:      "trivy",
			Category:    CategorySCA,
			Rule:        "CVE-2021-23337",
			Severity:    SeverityHigh,
			CVE:         "CVE-2021-23337",
			CVSS:        7.2,
			File:        "package.json",
			LineStart:   10,
			Message:     "Critical command injection in lodash package",
			FirstSeen:   time.Now(),
		},
	}

	deduped := CorrelateAndDeduplicate(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(deduped))
	}

	res := deduped[0]
	if res.Severity != SeverityHigh {
		t.Errorf("expected highest severity %s, got %s", SeverityHigh, res.Severity)
	}
	if res.Source != "osv+trivy" {
		t.Errorf("expected merged source 'osv+trivy', got '%s'", res.Source)
	}
	if res.CVSS != 7.2 {
		t.Errorf("expected highest CVSS 7.2, got %f", res.CVSS)
	}
	if res.Reachable == nil || !*res.Reachable {
		t.Errorf("expected reachability to be preserved")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	reachable := true
	exposed := true
	f := &Finding{
		ID:        "TEST-01",
		Severity:  SeverityCritical,
		Category:  CategorySecret,
		CVSS:      9.8,
		Reachable: &reachable,
		Exposed:   &exposed,
	}

	score := CalculateRiskScore(f)
	if score <= 50.0 {
		t.Errorf("expected high risk score for exposed critical secret with CVSS 9.8, got %.1f", score)
	}
	if score > 100.0 {
		t.Errorf("risk score must be clamped at 100.0, got %.1f", score)
	}
}

func TestDiscoveryMultiLanguageAndFixtureScan(t *testing.T) {
	fixturePath := "../../testdata/vulnerable-app"
	discovery, err := Discover(fixturePath)
	if err != nil {
		t.Fatalf("Discover failed on vulnerable fixture: %v", err)
	}

	langs := make(map[string]bool)
	for _, l := range discovery.Languages {
		langs[l] = true
	}
	for _, requiredLang := range []string{"go", "javascript", "python", "terraform"} {
		if !langs[requiredLang] {
			t.Errorf("Expected language %q in discovery results, got: %v", requiredLang, discovery.Languages)
		}
	}

	manifests := make(map[string]bool)
	for _, m := range discovery.Manifests {
		manifests[m] = true
	}
	if !manifests["package.json"] {
		t.Errorf("Expected package.json in discovery manifests, got: %v", discovery.Manifests)
	}
	if !manifests["requirements.txt"] {
		t.Errorf("Expected requirements.txt in discovery manifests, got: %v", discovery.Manifests)
	}

	if len(discovery.IaCFiles) < 2 {
		t.Errorf("Expected at least 2 IaC files (Dockerfile, infra.tf), got: %v", discovery.IaCFiles)
	}
}

