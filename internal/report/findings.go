package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

// messageWidth returns the optimal wrapping width inside the panel.
func messageWidth() int {
	return ui.GetPanelWidth() - 12
}

// renderFindings groups findings by severity, worst first, then by risk score. The old
// renderer listed them in discovery order, which interleaved critical secret exposures
// with informational notes and made triage a scanning exercise.
func renderFindings(w io.Writer, findings []orchestrator.Finding) {
	order := []string{
		orchestrator.SeverityCritical,
		orchestrator.SeverityHigh,
		orchestrator.SeverityMedium,
		orchestrator.SeverityLow,
		orchestrator.SeverityInfo,
	}

	bySeverity := make(map[string][]orchestrator.Finding)
	for _, f := range findings {
		key := normaliseSeverity(f.Severity)
		bySeverity[key] = append(bySeverity[key], f)
	}

	for _, sev := range order {
		group := bySeverity[sev]
		if len(group) == 0 {
			continue
		}
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].RiskScore != group[j].RiskScore {
				return group[i].RiskScore > group[j].RiskScore
			}
			if group[i].File != group[j].File {
				return group[i].File < group[j].File
			}
			return group[i].LineStart < group[j].LineStart
		})

		title := fmt.Sprintf("findings %s %s %s %d",
			ui.Separator(), strings.ToLower(sevLabel(sev)), ui.Separator(), len(group))

		contentWidth := ui.GetPanelWidth() - 4
		dash := "─"
		if !ui.Sym.Unicode {
			dash = "-"
		}
		var lines []string
		for i, f := range group {
			if i > 0 {
				lines = append(lines, ui.Fg(ui.T.Dark, strings.Repeat(dash, contentWidth)))
			}
			lines = append(lines, findingLines(f)...)
		}
		ui.Panel(w, ui.BoxFor(), title, lines)
	}
}

// findingLines renders one finding as a compact card: a location header, the wrapped
// message indented under it, then a two-row metadata footer.
//
// The indentation is not decoration. With the message flush against the border, the card
// and the panel edge merged into one block and the reader could not see where a finding
// began.
func findingLines(f orchestrator.Finding) []string {
	sevColour := severityColour(f.Severity)

	targetMarker := "@ "
	header := " " + ui.Tag(sevLabel(f.Severity), sevColour) +
		"  " + ui.Fg(ui.T.Dark, targetMarker) +
		ui.Fg(ui.T.Bright, ui.Trim(f.File, 44)) +
		ui.Fg(ui.T.Dark, ":") +
		ui.Fg(ui.T.Cyan, ui.Itoa(f.LineStart))

	lines := []string{header}

	for _, chunk := range ui.Wrap(f.Message, messageWidth()) {
		lines = append(lines, "   "+ui.Fg(ui.T.Muted, chunk))
	}

	engine := "external"
	switch f.Engine {
	case orchestrator.EngineEmbedded:
		engine = "embedded"
	case orchestrator.EngineNative:
		engine = "native"
	}

	// Two metadata rows: Risk meter and classification
	riskMeter := ui.SegBar(f.RiskScore/100.0, 10, sevColour)
	row1 := "   " + ui.Fg(ui.T.Dark, "risk ") + ui.BoldTxt(sevColour, fmt.Sprintf("%-4.1f", f.RiskScore)) +
		" " + riskMeter + ui.Fg(ui.T.Dark, "   "+f.Category+"   "+engine)
	if cweLabel(f.CWE) != "" {
		row1 += ui.Fg(ui.T.Cyan, "   "+cweLabel(f.CWE))
	}
	lines = append(lines, row1)

	row2 := "   " + ui.Fg(ui.T.Dark, "[ ")
	if f.Rule != "" {
		row2 += ui.Fg(ui.T.Muted, ui.Trim(f.Rule, 38)) + ui.Fg(ui.T.Dark, " // ")
	}
	row2 += ui.Fg(ui.T.Bright, f.ID) + ui.Fg(ui.T.Dark, " ]")
	lines = append(lines, row2)

	if f.FixSuggestion != nil && f.FixSuggestion.Description != "" {
		summary := cleanFixSummary(f.FixSuggestion.Description, messageWidth()-10)
		if summary != "" {
			fixText := "   " + ui.Fg(ui.T.Neon, "> FIX: ") + ui.Fg(ui.T.Bright, summary)
			lines = append(lines, fixText)
		}
	}

	return lines
}

// cleanFixSummary extracts a single-line, right-truncated remediation summary suitable for a finding card.
// If the description is a multi-step checklist (e.g. for secret rotation), it skips the checklist title
// and extracts the primary actionable step instead of truncating from the left and leaking raw newlines.
func cleanFixSummary(desc string, maxWidth int) string {
	clean := strings.ReplaceAll(desc, "\r\n", "\n")
	clean = strings.ReplaceAll(clean, "\r", "\n")
	lines := strings.Split(clean, "\n")
	first := ""
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(strings.ToLower(l), "rotation checklist") {
			continue
		}
		// Strip leading number prefix e.g. "1. " or "1) "
		if len(l) > 3 && l[0] >= '0' && l[0] <= '9' && (l[1] == '.' || l[1] == ')') && l[2] == ' ' {
			l = l[3:]
		}
		l = strings.TrimPrefix(l, "• ")
		l = strings.TrimPrefix(l, "- ")
		l = strings.TrimPrefix(l, "* ")
		first = strings.TrimSpace(l)
		break
	}
	if first == "" {
		first = desc
	}
	return ui.Truncate(first, maxWidth)
}

// renderClean is the zero-findings state. It states what ran, not merely "nothing found",
// because a clean result from a half-configured scan is not the same claim.
func renderClean(w io.Writer) {
	ui.Panel(w, ui.BoxFor(), "result", []string{
		" " + ui.Fg(ui.T.Primary, ui.Sym.OK+" no security flaws or secrets detected"),
		ui.Fg(ui.T.Dark, "   every enabled engine completed without findings"),
	})
}

// renderGatingAndActions reports whether the run passes or fails the requested threshold
// alongside actionable remediation commands, formatted as a unified cybersecurity panel.
func renderGatingAndActions(w io.Writer, result *orchestrator.ScanResult, failOn string) {
	failRank := orchestrator.SeverityRank(failOn)
	failedCount := 0
	for _, f := range result.Findings {
		if orchestrator.SeverityRank(f.Severity) >= failRank {
			failedCount++
		}
	}

	contentWidth := ui.GetPanelWidth() - 4
	dash := "─"
	bullet := "•"
	if !ui.Sym.Unicode {
		dash = "-"
		bullet = "*"
	}

	cmd1 := ui.BoldTxt(ui.T.Bright, ui.PadRight("sentinel explain <id>", 30))
	cmd2 := ui.BoldTxt(ui.T.Bright, ui.PadRight("sentinel fix <id> --apply", 30))
	cmd3 := ui.BoldTxt(ui.T.Bright, ui.PadRight("sentinel report --format html", 30))
	cmdBase := ui.BoldTxt(ui.T.Bright, ui.PadRight("sentinel baseline", 30))

	var lines []string
	if failedCount > 0 {
		statusLine := " " + ui.Tag("FAIL", ui.T.Red) + " " +
			ui.BoldTxt(ui.T.Red, fmt.Sprintf("Gating threshold failed: %d findings detected at or above '%s'", failedCount, failOn))
		lines = append(lines,
			statusLine,
			ui.Fg(ui.T.Dark, strings.Repeat(dash, contentWidth)),
			ui.Fg(ui.T.Cyan, " > NEXT REMEDIATION ACTIONS:"),
			"   "+bullet+" "+cmd1+" "+ui.Fg(ui.T.Dark, "Inspect flaw taint flow & vector details"),
			"   "+bullet+" "+cmd2+" "+ui.Fg(ui.T.Dark, "Apply verified automated patch to source"),
			"   "+bullet+" "+cmd3+" "+ui.Fg(ui.T.Dark, "Export interactive HTML report dashboard"),
		)
		ui.Panel(w, ui.BoxFor(), "pipeline gating // remediation actions", lines)
	} else {
		statusLine := " " + ui.Tag("PASS", ui.T.Neon) + " " +
			ui.BoldTxt(ui.T.Neon, fmt.Sprintf("Gating passed: No security flaws at or above '%s' threshold", failOn))
		lines = append(lines,
			statusLine,
			ui.Fg(ui.T.Dark, strings.Repeat(dash, contentWidth)),
			ui.Fg(ui.T.Cyan, " > RECOMMENDED NEXT STEPS:"),
			"   "+bullet+" "+cmdBase+" "+ui.Fg(ui.T.Dark, "Lock current findings baseline to prevent regressions"),
			"   "+bullet+" "+cmd3+" "+ui.Fg(ui.T.Dark, "Export interactive HTML report dashboard"),
		)
		ui.Panel(w, ui.BoxFor(), "pipeline gating // next steps", lines)
	}
}

// renderGating maintains backwards compatibility.
func renderGating(w io.Writer, result *orchestrator.ScanResult, failOn string) {
	renderGatingAndActions(w, result, failOn)
}
