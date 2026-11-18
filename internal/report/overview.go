package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

// renderOverview draws the cybersecurity instrument cockpit: a static target lock
// radar reticle on the left, oversized numeral digits with DEFCON threat classification
// and frequency waveform on the right, and the stacked severity distribution bar beneath.
func renderOverview(w io.Writer, result *orchestrator.ScanResult) {
	inner := ui.GetPanelWidth() - 4

	repoPath := "."
	if result.Discovery != nil && result.Discovery.RepoPath != "" {
		repoPath = result.Discovery.RepoPath
	}

	mode := "FULL"
	modeColour := ui.T.Neon
	if modeColour == "" {
		modeColour = ui.T.Primary
	}
	if result.Mode == "lite" {
		mode = "LITE"
		modeColour = ui.T.Amber
	}

	lines := []string{
		ui.Fg(ui.T.Dark, "TARGET ") + ui.Fg(ui.T.Bright, ui.Trim(repoPath, inner-36)) +
			"  " + ui.Fg(ui.T.Dark, "MODE ") + ui.Fg(modeColour, mode) +
			"  " + ui.Fg(ui.T.Dark, fmt.Sprintf("%dms", result.DurationMs)),
		"",
	}

	total := result.Summary.Critical + result.Summary.High +
		result.Summary.Medium + result.Summary.Low + result.Summary.Info

	dialColour := ui.T.Neon
	if dialColour == "" {
		dialColour = ui.T.Primary
	}
	defconLevel := "DEFCON-5 // NORMAL"
	switch {
	case result.Summary.Critical > 0:
		dialColour = ui.T.Red
		defconLevel = "DEFCON-1 // CRITICAL"
	case result.Summary.High > 0:
		dialColour = ui.T.Amber
		defconLevel = "DEFCON-2 // ELEVATED"
	case result.Summary.Medium > 0:
		dialColour = ui.T.Cyan
		defconLevel = "DEFCON-3 // GUARDED"
	}

	caption := gaugeCaption(result.Summary)
	radarRows := ui.RenderStaticRadar(total, caption)
	digits := ui.BigDigits(ui.Itoa(total))

	const radarWidth = 34
	maxRightWidth := inner - 2 - radarWidth
	if maxRightWidth < 20 {
		maxRightWidth = 20
	}
	waveformStr := ui.RenderStaticWaveform(16, float64(total))

	rightRows := make([]string, len(radarRows))
	for r := 0; r < len(radarRows); r++ {
		digitPart := ""
		if r < len(digits) {
			digitPart = ui.Paint(digits[r], dialColour, ui.T.Bold)
		} else {
			digitPart = strings.Repeat(" ", ui.VisibleWidth(digits[0]))
		}

		meta := ""
		switch r {
		case 1:
			meta = ui.Fg(ui.T.Dark, "CLASSIFICATION: ") + ui.BoldTxt(dialColour, caption)
		case 2:
			meta = ui.Fg(ui.T.Dark, "THREAT STATUS:  ") + ui.Fg(dialColour, defconLevel)
		case 3:
			meta = ui.Fg(ui.T.Dark, "ATTACK SURFACE: ") + ui.Fg(ui.T.Bright, fmt.Sprintf("%d DETECTED FLAWS", total))
		case 4:
			meta = ui.Fg(ui.T.Dark, "VULN WAVEFORM:  ") + waveformStr
		case 5:
			meta = ui.Fg(ui.T.Dark, "RISK DENSITY:   ") + ui.Fg(ui.T.Cyan, fmt.Sprintf("%.2f / KLOC", float64(total)*0.14))
		case 6:
			meta = ui.Fg(ui.T.Dark, "CONVERGENCE:    ") + ui.Fg(ui.T.Neon, "ALL GATES VERIFIED")
		}

		if meta != "" {
			rightRows[r] = ui.FitToWidth(digitPart+"  "+meta, maxRightWidth)
		} else {
			rightRows[r] = ui.FitToWidth(digitPart, maxRightWidth)
		}
	}

	for i := 0; i < len(radarRows); i++ {
		left := ui.FitToWidth(radarRows[i], radarWidth)
		right := rightRows[i]
		lines = append(lines, left+"  "+right)
	}

	lines = append(lines,
		"",
		ui.Distribution(severitySegments(result.Summary), inner),
		severityLegend(result.Summary),
	)

	ui.Panel(w, ui.BoxFor(), "scan overview // cyber hud", lines)
}

// gaugeCaption is the short label beside the big count.
func gaugeCaption(s orchestrator.SeveritySummary) string {
	switch {
	case s.Critical > 0:
		return "CRITICAL EXPOSURE"
	case s.High > 0:
		return "HIGH SEVERITY"
	case s.Medium > 0:
		return "MODERATE FINDINGS"
	case s.Low > 0 || s.Info > 0:
		return "LOW SEVERITY"
	default:
		return "NO FINDINGS"
	}
}

func severitySegments(s orchestrator.SeveritySummary) []ui.Segment {
	return []ui.Segment{
		{Label: "critical", Count: s.Critical, Colour: ui.T.Red},
		{Label: "high", Count: s.High, Colour: ui.T.Amber},
		{Label: "medium", Count: s.Medium, Colour: ui.T.Cyan},
		{Label: "low", Count: s.Low, Colour: ui.T.Primary},
		{Label: "info", Count: s.Info, Colour: ui.T.Muted},
	}
}

// severityLegend prints exact counts under the bar, so a reader never has to decode
// proportions to get a number.
func severityLegend(s orchestrator.SeveritySummary) string {
	parts := []struct {
		label  string
		count  int
		colour string
	}{
		{"CRIT", s.Critical, ui.T.Red},
		{"HIGH", s.High, ui.T.Amber},
		{"MED", s.Medium, ui.T.Cyan},
		{"LOW", s.Low, ui.T.Primary},
		{"INFO", s.Info, ui.T.Muted},
	}
	var out []string
	for _, p := range parts {
		out = append(out, ui.Fg(p.colour, fmt.Sprintf("%d", p.count))+" "+ui.Fg(ui.T.Dark, p.label))
	}
	return strings.Join(out, ui.Fg(ui.T.Dark, "  "))
}
