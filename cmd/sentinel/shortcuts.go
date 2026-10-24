package main

import (
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
	"github.com/spf13/cobra"
)

type sharedScanFlags struct {
	failOn      string
	configPath  string
	offline     bool
	formatStr   string
	outFile     string
	changedOnly bool
	useBaseline bool
	ciMode      bool
	allowLite   bool
	noColor     bool
}

func addSharedScanFlags(cmd *cobra.Command, flags *sharedScanFlags) {
	cmd.Flags().StringVar(&flags.failOn, "fail-on", "high", "Fail gating threshold: critical|high|medium|low")
	cmd.Flags().StringVar(&flags.configPath, "config", "", "Explicit path to .sentinel.yml policy file")
	cmd.Flags().BoolVar(&flags.offline, "offline", false, "Disable network requests")
	cmd.Flags().StringVar(&flags.formatStr, "format", "terminal", "Output formats (terminal,sarif,json,markdown,html,junit)")
	cmd.Flags().StringVar(&flags.outFile, "out", "", "File path to write primary report output")
	cmd.Flags().BoolVar(&flags.changedOnly, "changed-only", false, "Scan only modified and uncommitted files in git workspace")
	cmd.Flags().BoolVar(&flags.useBaseline, "baseline", false, "Filter out accepted baseline findings from .sentinel/baseline.json")
	cmd.Flags().BoolVar(&flags.ciMode, "ci", false, "CI mode: fail build on threshold and halt if missing tools unless --allow-lite")
	cmd.Flags().BoolVar(&flags.allowLite, "allow-lite", false, "Allow embedded fallback engines to run in --ci mode without failing")
	cmd.Flags().BoolVar(&flags.noColor, "no-color", false, "Disable ANSI color output in terminal")
}

func newSecretsCmd() *cobra.Command {
	return createCategoryShortcutCmd("secrets", "Scan for hardcoded secrets, API tokens, and credentials", "secrets")
}

func newDepsCmd() *cobra.Command {
	return createCategoryShortcutCmd("deps", "Scan dependencies and lockfiles for known vulnerabilities (SCA)", "sca")
}

func newSASTCmd() *cobra.Command {
	return createCategoryShortcutCmd("sast", "Run static code analysis for security vulnerabilities (SAST)", "sast")
}

func newIaCCmd() *cobra.Command {
	return createCategoryShortcutCmd("iac", "Scan Infrastructure as Code and Dockerfiles for misconfigurations", "iac")
}

func createCategoryShortcutCmd(use, short, category string) *cobra.Command {
	flags := &sharedScanFlags{}

	cmd := &cobra.Command{
		Use:   use + " [path]",
		Short: short,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if flags.noColor {
				report.DisableColors()
			}
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			runScanInternal(
				path,
				flags.configPath,
				[]string{category},
				nil,
				flags.changedOnly,
				nil,
				flags.failOn,
				flags.formatStr,
				flags.outFile,
				flags.ciMode,
				flags.allowLite,
				flags.useBaseline,
				"",
				flags.offline,
				false,
				"",
				false,
				false,
				false,
			)
		},
	}

	addSharedScanFlags(cmd, flags)
	return cmd
}
