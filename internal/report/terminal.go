package report

import (
	"fmt"
	"io"
	"os"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

// DisableColors strips all ANSI colour codes from terminal output. It delegates to the
// shared theme so the report and every other command agree on what "no colour" means.
func DisableColors() { ui.DisableColors() }

// isTTY reports whether f is an interactive terminal.
//
// Colour detection itself lives entirely in the ui package, which already honours
// NO_COLOR, SENTINEL_COLOR=always, and TTY detection. An earlier version of this file
// also called DisableColors from an init here; because that init ran after the ui
// package's, it silently overrode an explicit SENTINEL_COLOR=always request, making
// colour impossible to regain once output was piped.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// RenderTerminal prints a scan result as an instrument panel: header, overview dial,
// engine coverage, warnings, then one section per severity containing finding cards.
//
// The previous layout was a flat list under a one-line severity counter. It carried the
// same data but read as log output. A security report is something a person has to
// triage, so proportion and location must be legible before the details are.
func RenderTerminal(w io.Writer, result *orchestrator.ScanResult, failOn string) {
	ui.Banner(w)

	if result == nil {
		fmt.Fprintf(w, " %s\n\n", ui.Fg(ui.T.Red, "no scan result produced"))
		return
	}

	renderOverview(w, result)
	renderCoverage(w, result)

	if len(result.Warnings) > 0 {
		renderWarnings(w, result.Warnings)
	}

	if len(result.Findings) == 0 {
		renderClean(w)
		renderGatingAndActions(w, result, failOn)
		return
	}

	renderFindings(w, result.Findings)
	renderGatingAndActions(w, result, failOn)
}
