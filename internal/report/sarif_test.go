package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestGenerateSARIF(t *testing.T) {
	findings := []orchestrator.Finding{
		{
			ID:          "SENT-test-1",
			Source:      "gitleaks",
			Category:    orchestrator.CategorySecret,
			Rule:        "aws-access-key-id",
			Severity:    orchestrator.SeverityCritical,
			CWE:         "CWE-798",
			File:        "config.go",
			LineStart:   15,
			LineEnd:     15,
			Fingerprint: "fp-test-123",
			Message:     "Hardcoded AWS key identified",
			FirstSeen:   time.Now(),
		},
	}

	data, err := GenerateSARIF(findings)
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	var parsed SARIFReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("generated invalid SARIF JSON: %v", err)
	}

	if parsed.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", parsed.Version)
	}
	if len(parsed.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(parsed.Runs))
	}
	if len(parsed.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result in run, got %d", len(parsed.Runs[0].Results))
	}

	if parsed.Runs[0].Tool.Driver.Version != "0.1.1" {
		t.Errorf("expected tool driver version '0.1.1', got '%s'", parsed.Runs[0].Tool.Driver.Version)
	}

	res := parsed.Runs[0].Results[0]
	if res.Level != "error" {
		t.Errorf("expected level 'error' for critical severity, got '%s'", res.Level)
	}
	if res.PartialFingerprints["primaryLocationLineHash"] == "" {
		t.Errorf("expected primaryLocationLineHash in partialFingerprints")
	}
}
