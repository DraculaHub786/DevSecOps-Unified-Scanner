package report

import (
	"strings"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestGenerateJUnit(t *testing.T) {
	result := &orchestrator.ScanResult{
		StartedAt:  time.Now(),
		FinishedAt: time.Now().Add(300 * time.Millisecond),
		DurationMs: 300,
		Mode:       "full",
		Summary: orchestrator.SeveritySummary{
			Total:    2,
			Critical: 1,
			Low:      1,
		},
		Findings: []orchestrator.Finding{
			{
				ID:        "f-1",
				Category:  orchestrator.CategorySAST,
				Severity:  "critical",
				Rule:      "sql-injection",
				File:      "main.go",
				LineStart: 12,
				Message:   "Query concatenation",
				RiskScore: 90.0,
			},
			{
				ID:        "f-2",
				Category:  orchestrator.CategorySAST,
				Severity:  "low",
				Rule:      "comment-todo",
				File:      "main.go",
				LineStart: 2,
				Message:   "TODO comment left",
				RiskScore: 10.0,
			},
		},
	}

	data, err := GenerateJUnit(result, "high")
	if err != nil {
		t.Fatalf("GenerateJUnit failed: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Errorf("Missing XML declaration header")
	}
	if !strings.Contains(content, `<testsuites name="Sentinel Security Scan"`) {
		t.Errorf("Missing testsuites root tag")
	}
	if !strings.Contains(content, `<failure message="[CRITICAL] sql-injection: Query concatenation"`) {
		t.Errorf("Expected critical finding to be flagged as failure when failOn is high")
	}
	if strings.Contains(content, `<failure message="[LOW]`) {
		t.Errorf("Low finding should not be flagged as failure when failOn is high")
	}
}
