package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestSevLabelNoPanic(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "CRIT"},
		{"CRITICAL", "CRIT"},
		{"high", "HIGH"},
		{"medium", "MED"},
		{"low", "LOW"},
		{"LOW", "LOW"},
		{"info", "INFO"},
		{"unknown_severity", "INFO"},
		{"", "INFO"},
		{"a", "INFO"},
		{"ab", "INFO"},
		{"abc", "INFO"},
	}

	for _, tt := range tests {
		got := sevLabel(tt.input)
		if got != tt.expected {
			t.Errorf("sevLabel(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestRenderTerminalReportAllSeverities(t *testing.T) {
	severities := []string{
		"critical", "high", "medium", "low", "info", "unknown", "", "lo",
	}

	var findings []orchestrator.Finding
	for i, sev := range severities {
		findings = append(findings, orchestrator.Finding{
			ID:        string(rune('A' + i)),
			Severity:  sev,
			Category:  "sast",
			File:      "test.go",
			LineStart: 10 + i,
			Message:   "Test finding for severity " + sev,
			Engine:    orchestrator.EngineExternal,
		})
	}

	result := &orchestrator.ScanResult{
		Findings: findings,
		Summary:  orchestrator.SeveritySummary{},
	}

	var buf bytes.Buffer
	// Must not panic on any severity (especially "low" or empty string)
	RenderTerminal(&buf, result, "high")
	out := buf.String()

	if !strings.Contains(out, "CRIT") || !strings.Contains(out, "LOW") || !strings.Contains(out, "MED") {
		t.Errorf("Expected formatted severity labels in output, got:\n%s", out)
	}
}

func TestTruncateRunesUTF8Boundary(t *testing.T) {
	// 50 ASCII + multi-byte emoji/CJK characters at boundary
	text := strings.Repeat("A", 50) + "🛡️✨🚀🔒🌟" + strings.Repeat("B", 20)
	truncated := truncateRunes(text, 52)

	if !utf8.ValidString(truncated) {
		t.Errorf("truncateRunes produced invalid UTF-8 string: %q", truncated)
	}
	if utf8.RuneCountInString(truncated) != 52 {
		t.Errorf("expected 52 runes, got %d", utf8.RuneCountInString(truncated))
	}
}
