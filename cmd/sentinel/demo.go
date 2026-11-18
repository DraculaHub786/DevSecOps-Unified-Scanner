package main

import (
	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

func newDemoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "demo [path]",
		Short: "Showcase cybersecurity HUD scanning simulation and report",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			ui.RunSimulationDemo(path)
			runScanInternal(
				path,
				"",
				nil,
				nil,
				false,
				nil,
				"high",
				"terminal",
				"",
				true, // ciMode true suppresses redundant duplicate HUD
				false,
				false,
				"",
				false,
				false,
				"",
				false,
				false,
				false,
			)
		},
	}
	return cmd
}
