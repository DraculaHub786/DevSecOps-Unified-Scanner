package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/ui"
)

var (
	version = "1.0.2"
	commit  = "none"
	date    = "2026-10-25"
)

func main() {
	ui.SetVersion(version)

	// The banner is drawn by the ui package rather than written into Long, because
	// Long is a static string cobra prints verbatim: it cannot colour, cannot adapt
	// its width, and cannot fall back to ASCII on a console that needs it. That is
	// how the previous header ended up as raw emoji on a Windows terminal.
	rootCmd := &cobra.Command{
		Use:     "sentinel",
		Version: version,
		Short:   "Sentinel - unified DevSecOps security scanner",
		Long: `Sentinel is a local-first DevSecOps security scanner. It orchestrates Semgrep,
Trivy, OSV-Scanner, Gitleaks and Nuclei behind one interface, correlates their
findings, scores contextual risk, and proposes fixes - without sending source code
anywhere.

Run "sentinel help" followed by a command name for that command's flags.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				ui.Banner(os.Stdout)
			}
			_ = cmd.Help()
		},
	}

	// Core scan and category shortcuts
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newSecretsCmd())
	rootCmd.AddCommand(newDepsCmd())
	rootCmd.AddCommand(newSASTCmd())
	rootCmd.AddCommand(newIaCCmd())

	// Extended V2 commands
	rootCmd.AddCommand(newImageCmd())
	rootCmd.AddCommand(newSBOMCmd())
	rootCmd.AddCommand(newDASTCmd())
	rootCmd.AddCommand(newThreatModelCmd())
	rootCmd.AddCommand(newBaselineCmd())
	rootCmd.AddCommand(newDiffCmd())
	rootCmd.AddCommand(newHistoryCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newSuppressCmd())
	rootCmd.AddCommand(newDoctorCmd())

	// Guided remediation and automation helpers
	rootCmd.AddCommand(newExplainCmd())
	rootCmd.AddCommand(newFixCmd())
	rootCmd.AddCommand(newWatchCmd())
	rootCmd.AddCommand(newInstallHooksCmd())
	rootCmd.AddCommand(newGuardCmd())
	rootCmd.AddCommand(newVersionCmd())

	// V4 Phase 3 commands
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newRulesCmd())
	rootCmd.AddCommand(newCompletionCmd())
	rootCmd.AddCommand(newBenchDetectCmd())
	rootCmd.AddCommand(newDemoCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}
