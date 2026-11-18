package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/doctor"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/rules"
)

// newVersionCmd prints the shared banner, then build facts, the rule pack breakdown as a
// bar chart, and a normalised engine table.
//
// The banner is shared rather than hand-drawn per command: three commands previously
// each rendered their own, with different widths, different separators, and one
// duplicated label ("Rules Pack: Rules: ..."). Engine versions are normalised because the
// tools' raw --version output is log text, not a version string.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Sentinel version, rule pack size, and detected engines",
		Run: func(cmd *cobra.Command, args []string) {
			ui.Banner(os.Stdout)
			renderBuildPanel(os.Stdout)
			renderRulesPanel(os.Stdout)
			renderEnginesPanel(os.Stdout)
			fmt.Printf("  %s %s\n\n",
				ui.Fg(ui.T.Muted, "DEEP DIAGNOSTICS"),
				ui.Fg(ui.T.Dark, fmt.Sprintf("sentinel doctor  %s  sentinel doctor --privacy", ui.Separator())),
			)
		},
	}
}

func renderBuildPanel(w io.Writer) {
	lines := []string{
		ui.Fg(ui.T.Dark, "BUILD    ") + ui.Fg(ui.T.Bright, commit) +
			ui.Fg(ui.T.Dark, "  "+ui.Separator()+"  ") + ui.Fg(ui.T.Muted, date),
		ui.Fg(ui.T.Dark, "LICENSE  ") + ui.Fg(ui.T.Bright, "MIT") +
			ui.Fg(ui.T.Dark, "  "+ui.Separator()+"  ") + ui.Fg(ui.T.Muted, "local-first, no source code egress"),
	}
	ui.Panel(w, ui.BoxFor(), "build", lines)
}

// renderRulesPanel shows each rule family as a bar, so the shape of the detection
// coverage is visible at a glance. A single summary sentence hid the fact that, for
// example, supply-chain coverage was four rules against seventy SAST rules.
func renderRulesPanel(w io.Writer) {
	stats, err := rules.CountRules()
	if err != nil {
		ui.Panel(w, ui.BoxFor(), "rules", []string{
			ui.Fg(ui.T.Amber, ui.Sym.Warn+" could not count rules: "+err.Error()),
		})
		return
	}

	families := []struct {
		label  string
		count  int
		colour string
	}{
		{"SAST", stats.SAST, ui.T.Primary},
		{"resilience", stats.Resilience, ui.T.Cyan},
		{"github actions", stats.GitHubActions, ui.T.Magenta},
		{"supply chain", stats.SupplyChain, ui.T.Amber},
	}

	const barWidth = 26
	var lines []string
	for _, f := range families {
		frac := 0.0
		if stats.Total > 0 {
			frac = float64(f.count) / float64(stats.Total)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s",
			ui.Fg(ui.T.Bright, ui.PadRight(f.label, 16)),
			ui.SegBar(frac, barWidth, f.colour),
			ui.Fg(ui.T.Muted, ui.PadLeft(ui.Itoa(f.count), 4)),
		))
	}
	lines = append(lines, "",
		ui.Fg(ui.T.Dark, "TOTAL    ")+ui.Fg(ui.T.Primary, ui.Itoa(stats.Total))+
			ui.Fg(ui.T.Dark, " rules embedded in the binary"),
	)

	ui.Panel(w, ui.BoxFor(), "rules pack · embedded v1", lines)
}

// renderEnginesPanel lists each engine with a ready/missing mark. The state column is
// coloured rather than glyph-only, so a missing engine is obvious without reading.
func renderEnginesPanel(w io.Writer) {
	engines := doctor.CheckEngines()

	var lines []string
	ready := 0
	for _, e := range engines {
		if e.Found {
			ready++
		}

		mark := ui.Fg(ui.T.Red, ui.MarkOff())
		state := ui.Fg(ui.T.Red, ui.PadRight("MISSING", 10))
		if e.Found {
			mark = ui.Fg(ui.T.Primary, ui.MarkOn())
			state = ui.Fg(ui.T.Primary, ui.PadRight("READY", 10))
		}

		lines = append(lines, fmt.Sprintf("%s %s %s %s",
			mark,
			ui.Fg(ui.T.Bright, ui.PadRight(e.Name, 24)),
			state,
			ui.Fg(ui.T.Muted, ui.PadRight(normalizeEngineVersion(e.Version), 12))+
				ui.Fg(ui.T.Dark, engineMode(e.Mode)),
		))
	}

	lines = append(lines, "",
		ui.Fg(ui.T.Dark, fmt.Sprintf("%d of %d engines available", ready, len(engines))),
	)
	ui.Panel(w, ui.BoxFor(), "scan engines", lines)
}

func engineMode(mode string) string {
	if mode == "embedded lite" {
		return "embedded"
	}
	return "external"
}
