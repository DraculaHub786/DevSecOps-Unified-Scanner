package main

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "1.0.1"
	commit  = "none"
	date    = "2026-10-24"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sentinel",
		Short: "🛡️ Sentinel — Unified DevSecOps Security Scanner",
		Long: `Sentinel is a local-first DevSecOps unified security scanner orchestrating
industry-standard vulnerability detection engines (Semgrep, Trivy, OSV-Scanner,
Gitleaks, Nuclei) behind one consistent interface, correlating findings,
scoring contextual risk, and suggesting actionable fixes without leaking source code.`,
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
	rootCmd.AddCommand(newVersionCmd())

	// V4 Phase 3 commands
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newRulesCmd())
	rootCmd.AddCommand(newCompletionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}
