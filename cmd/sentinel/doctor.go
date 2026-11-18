package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/doctor"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

func newDoctorCmd() *cobra.Command {
	var jsonOutput bool
	var privacyOutput bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect scanner engine availability, versions, full vs lite mode, and privacy disclosure",
		Run: func(cmd *cobra.Command, args []string) {
			if privacyOutput {
				doctor.PrintPrivacy()
				return
			}

			statuses := doctor.CheckEngines()

			if jsonOutput {
				data, _ := json.MarshalIndent(statuses, "", "  ")
				fmt.Println(string(data))
				return
			}

			ui.Banner(os.Stdout)
			renderDoctorEngines(os.Stdout, statuses)
			renderDoctorVerdict(os.Stdout, statuses)

			fmt.Printf("  %s %s\n\n",
				ui.Fg(ui.T.Muted, "PRIVACY"),
				ui.Fg(ui.T.Dark, fmt.Sprintf("sentinel doctor --privacy  %s  every network endpoint contacted, and why", ui.Separator())),
			)
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output diagnostics in JSON format")
	cmd.Flags().BoolVar(&privacyOutput, "privacy", false, "Audit and print all external network endpoints contacted and why")
	return cmd
}

// renderDoctorEngines prints one row per engine with availability, mode, and the
// remediation hint when the engine is missing. The hint belongs on the same row as the
// failure: a footnotes section at the bottom is where people stop reading.
func renderDoctorEngines(w *os.File, statuses []doctor.ToolStatus) {
	var lines []string
	for _, st := range statuses {
		mark := ui.Fg(ui.T.Red, ui.MarkOff())
		state := ui.Fg(ui.T.Red, ui.PadRight("MISSING", 9))
		if st.Found {
			mark = ui.Fg(ui.T.Primary, ui.MarkOn())
			state = ui.Fg(ui.T.Primary, ui.PadRight("READY", 9))
		}

		lines = append(lines, fmt.Sprintf("%s %s %s %s %s",
			mark,
			ui.Fg(ui.T.Bright, ui.PadRight(st.Name, 24)),
			state,
			ui.Fg(ui.T.Muted, ui.PadRight(engineMode(st.Mode), 10)),
			ui.Fg(ui.T.Dark, normalizeEngineVersion(st.Version)),
		))

		if !st.Found && st.Recommended != "" {
			for i, chunk := range ui.Wrap(st.Recommended, ui.PanelWidth-14) {
				if i == 0 {
					lines = append(lines, "  "+ui.Fg(ui.T.Amber, ui.Sym.Arrow+" ")+ui.Fg(ui.T.Dark, chunk))
				} else {
					lines = append(lines, "    "+ui.Fg(ui.T.Dark, chunk))
				}
			}
		}
	}
	ui.Panel(w, ui.BoxFor(), "engine diagnostics", lines)
}

// renderDoctorVerdict states plainly whether full scanning is available. The old version
// buried this under a table and a separator line.
func renderDoctorVerdict(w *os.File, statuses []doctor.ToolStatus) {
	missing := 0
	for _, st := range statuses {
		if !st.Found {
			missing++
		}
	}

	var lines []string
	if missing == 0 {
		lines = append(lines,
			ui.Fg(ui.T.Primary, ui.Sym.OK+" all "+ui.Itoa(len(statuses))+" engines available"),
			ui.Fg(ui.T.Dark, "full production scanning active"),
		)
	} else {
		lines = append(lines,
			ui.Fg(ui.T.Amber, fmt.Sprintf("%s %d of %d engines missing", ui.Sym.Warn, missing, len(statuses))),
			ui.Fg(ui.T.Dark, "those categories run on embedded lite engines with reduced coverage"),
			ui.Fg(ui.T.Dark, "in --ci mode a missing engine halts the build unless --allow-lite is set"),
		)
	}
	ui.Panel(w, ui.BoxFor(), "verdict", lines)
}
