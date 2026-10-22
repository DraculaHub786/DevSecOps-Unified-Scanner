package main

import (
	"github.com/spf13/cobra"
)

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
	var (
		failOn     string
		configPath string
		offline    bool
	)

	cmd := &cobra.Command{
		Use:   use + " [path]",
		Short: short,
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := "."
			if len(args) > 0 {
				path = args[0]
			}
			runScanInternal(path, configPath, []string{category}, nil, false, nil, failOn, "terminal", "", false, false, false, "", offline, false)
		},
	}

	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail gating threshold: critical|high|medium|low")
	cmd.Flags().StringVar(&configPath, "config", "", "Explicit path to .sentinel.yml policy file")
	cmd.Flags().BoolVar(&offline, "offline", false, "Disable network requests")
	return cmd
}
