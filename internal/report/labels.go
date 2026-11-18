package report

import (
	"regexp"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

// cwePattern extracts the bare identifier from a CWE string.
//
// Scanners disagree on the format: some emit "CWE-89", Semgrep emits a full description
// such as "[CWE-250: Execution with Unnecessary Privileges]". Printing the description in
// the metadata row overran the panel border on every finding that carried a CWE, so the
// row keeps only the identifier. The description is available via `sentinel explain`.
var cwePattern = regexp.MustCompile(`CWE-\d+`)

// cweLabel reduces any CWE representation to "CWE-<number>", or "" when there is none.
func cweLabel(raw string) string {
	return cwePattern.FindString(raw)
}

// sevLabel is the fixed severity tag used in finding headers.
func sevLabel(s string) string {
	switch strings.ToLower(s) {
	case orchestrator.SeverityCritical:
		return "CRIT"
	case orchestrator.SeverityHigh:
		return "HIGH"
	case orchestrator.SeverityMedium:
		return "MED"
	case orchestrator.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// severityColour maps a severity to the palette entry used everywhere it appears, so a
// critical finding is the same red in the dial, the bar, the legend, and the card.
func severityColour(sev string) string {
	switch strings.ToLower(sev) {
	case orchestrator.SeverityCritical:
		return ui.T.Red
	case orchestrator.SeverityHigh:
		return ui.T.Amber
	case orchestrator.SeverityMedium:
		return ui.T.Cyan
	case orchestrator.SeverityLow:
		return ui.T.Primary
	default:
		return ui.T.Muted
	}
}

// normaliseSeverity collapses anything unrecognised to "info", so an adapter emitting a
// new or misspelled severity cannot create an invisible group that never renders.
func normaliseSeverity(s string) string {
	switch strings.ToLower(s) {
	case orchestrator.SeverityCritical, orchestrator.SeverityHigh,
		orchestrator.SeverityMedium, orchestrator.SeverityLow, orchestrator.SeverityInfo:
		return strings.ToLower(s)
	default:
		return orchestrator.SeverityInfo
	}
}

// truncateRunes is UTF-8 safe, so a multi-byte glyph is never split in half.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
