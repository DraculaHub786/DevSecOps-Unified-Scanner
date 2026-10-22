package report

import (
	"strings"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestGenerateHTML(t *testing.T) {
	result := &orchestrator.ScanResult{
		StartedAt:  time.Now(),
		FinishedAt: time.Now().Add(500 * time.Millisecond),
		DurationMs: 500,
		Mode:       "full",
		Discovery: &orchestrator.DiscoveryResult{
			RepoPath: "/test/repo",
		},
		Summary: orchestrator.SeveritySummary{
			Total:    2,
			Critical: 1,
			High:     1,
		},
		Findings: []orchestrator.Finding{
			{
				ID:          "f-crit-1",
				Fingerprint: "fp-crit-1",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySAST,
				Severity:    "critical",
				File:        "cmd/main.go",
				LineStart:   42,
				RiskScore:   92.5,
				Rule:        "sql-injection",
				Message:     "Unsanitized input in query",
			},
			{
				ID:          "f-high-1",
				Fingerprint: "fp-high-1",
				Engine:      orchestrator.EngineEmbedded,
				Category:    orchestrator.CategorySecret,
				Severity:    "high",
				File:        ".env",
				LineStart:   3,
				RiskScore:   78.0,
				Rule:        "hardcoded-aws-key",
				Message:     "Exposed secret in config",
			},
		},
	}

	htmlContent := GenerateHTML(result, "high")

	if !strings.Contains(htmlContent, "<!DOCTYPE html>") {
		t.Errorf("HTML output missing <!DOCTYPE html>")
	}
	if !strings.Contains(htmlContent, "Sentinel DevSecOps Report") {
		t.Errorf("HTML output missing title")
	}
	if !strings.Contains(htmlContent, "FAILED (Fail-on: high)") {
		t.Errorf("Expected FAILED status badge in HTML report")
	}
	if !strings.Contains(htmlContent, "f-crit-1") || !strings.Contains(htmlContent, "f-high-1") {
		t.Errorf("HTML output missing finding IDs")
	}
	if !strings.Contains(htmlContent, "external") || !strings.Contains(htmlContent, "embedded") {
		t.Errorf("HTML output missing engine provenance values")
	}

	// Verify self-contained (no external http / cdn link tags or script tags)
	if strings.Contains(htmlContent, "http://") || strings.Contains(htmlContent, "https://") {
		t.Error("HTML output should be 100% offline self-contained without external links")
	}

	// Test with warnings
	result.Warnings = []string{"osv: embedded advisory list has 7 entries; install osv-scanner for full coverage"}
	htmlWithWarn := GenerateHTML(result, "high")
	if !strings.Contains(htmlWithWarn, "Scan Warnings") || !strings.Contains(htmlWithWarn, "embedded advisory list has 7 entries") {
		t.Errorf("Expected scan warning banner in HTML report")
	}

	mdWithWarn := GenerateMarkdown(result, "high")
	if !strings.Contains(mdWithWarn, "### ⚠️ Warnings") || !strings.Contains(mdWithWarn, "embedded advisory list has 7 entries") {
		t.Errorf("Expected scan warning section in Markdown report")
	}
}

