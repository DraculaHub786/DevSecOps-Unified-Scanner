package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

// renderCoverage shows which engine served each category, including degraded states.
// A finding from a degraded engine is weaker evidence than one from a healthy engine,
// and the reader needs to know which they are looking at before they trust a clean run.
func renderCoverage(w io.Writer, result *orchestrator.ScanResult) {
	if len(result.Coverage) == 0 {
		return
	}

	// Category to the tool that normally serves it. c.Engine holds the engine *type*
	// ("external"/"embedded"/"native"), not the tool name — printing it as the tool
	// produced rows reading "SAST READY external", which tells the reader nothing.
	toolByCategory := map[string]string{
		orchestrator.CategorySAST:       "semgrep",
		orchestrator.CategorySCA:        "osv-scanner",
		orchestrator.CategorySecret:     "gitleaks",
		orchestrator.CategoryIaC:        "trivy",
		orchestrator.CategoryDAST:       "nuclei",
		orchestrator.CategoryResilience: "built-in",
	}

	var lines []string
	for _, c := range result.Coverage {
		label := ui.PadRight(strings.ToUpper(c.Category), 14)

		tool := toolByCategory[c.Category]
		if tool == "" {
			tool = c.Category
		}

		var state, colour, mark string
		switch {
		case c.Status == "not-applicable":
			state, colour, mark = "[ BYPASS ]", ui.T.Dark, ui.MarkOff()
		case c.Status == "skipped":
			state, colour, mark = "[ SKIPPED ]", ui.T.Amber, ui.MarkOff()
		case c.Status == "degraded":
			state, colour, mark = "[ DEGRADED ]", ui.T.Amber, ui.MarkHalf()
		case c.Engine == orchestrator.EngineNative:
			state, colour, mark = "[ NATIVE ]", ui.T.Neon, ui.MarkOn()
		case c.Engine == orchestrator.EngineExternal:
			state, colour, mark = "[ READY ]", ui.T.Neon, ui.MarkOn()
		default:
			state, colour, mark = "[ EMBEDDED ]", ui.T.Cyan, ui.MarkHalf()
		}
		if colour == "" {
			colour = ui.T.Primary
		}

		lines = append(lines, fmt.Sprintf("%s %s %s  %s",
			ui.Fg(colour, mark),
			ui.Fg(ui.T.Bright, label),
			ui.BoldTxt(colour, ui.PadRight(state, 14)),
			ui.Fg(ui.T.Dark, tool),
		))
	}

	ui.Panel(w, ui.BoxFor(), "engine coverage // defense matrix", lines)
}

// renderWarnings prints degraded-mode explanations inside their own panel. These are the
// lines that prevent a reader from mistaking a partial scan for a thorough one.
func renderWarnings(w io.Writer, warnings []string) {
	var lines []string
	wrapW := ui.GetPanelWidth() - 8
	for _, warn := range warnings {
		for i, chunk := range ui.Wrap(warn, wrapW) {
			if i == 0 {
				lines = append(lines, ui.Fg(ui.T.Amber, ui.Sym.Warn+" ")+ui.Fg(ui.T.Muted, chunk))
			} else {
				lines = append(lines, "  "+ui.Fg(ui.T.Muted, chunk))
			}
		}
	}
	ui.Panel(w, ui.BoxFor(), "warnings", lines)
}
