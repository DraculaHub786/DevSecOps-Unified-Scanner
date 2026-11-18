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

func TestCleanFixSummarySecretRotation(t *testing.T) {
	checklist := "Rotation Checklist for GitHub Token:\n" +
		"1. Immediately REVOKE at: https://github.com/settings/tokens\n" +
		"2. Replace hardcoded literal in server.js with environment variable\n" +
		"3. Ensure server.js is listed in .gitignore\n" +
		"4. Install pre-commit protection: `sentinel install-hooks`"

	summary := cleanFixSummary(checklist, 60)
	if strings.Contains(summary, "\n") || strings.Contains(summary, "\r") {
		t.Errorf("cleanFixSummary must not contain newlines, got: %q", summary)
	}
	if !strings.HasPrefix(summary, "Immediately REVOKE") {
		t.Errorf("expected summary to start with actionable step, got: %q", summary)
	}
}

func TestFindingLinesNoEmbeddedNewlines(t *testing.T) {
	f := orchestrator.Finding{
		ID:        "SENT-test1234",
		Severity:  "high",
		Category:  "secret",
		File:      "coverage.go",
		LineStart: 26,
		Message:   "Hardcoded credential literal assigned to a secret field.\nSecond line of message.",
		Engine:    orchestrator.EngineExternal,
		FixSuggestion: &orchestrator.Fix{
			Kind: "code_patch",
			Description: "Rotation Checklist for Hardcoded Credential:\n" +
				"1. Immediately REVOKE and rotate the exposed credential with the issuing provider\n" +
				"2. Replace hardcoded literal in coverage.go with an environment variable reference\n" +
				"3. Add coverage.go to .gitignore\n" +
				"4. Install pre-commit hook: `sentinel install-hooks`",
		},
	}

	lines := findingLines(f)
	for i, l := range lines {
		if strings.Contains(l, "\n") || strings.Contains(l, "\r") {
			t.Errorf("findingLines[%d] contains newline: %q", i, l)
		}
	}
}
