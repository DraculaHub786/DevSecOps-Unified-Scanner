package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const starterConfig = `# Sentinel Unified DevSecOps Policy
version: 1

thresholds:
  fail_on: "high"
  risk_score_max: 70.0

scanners:
  sast:
    enabled: true
    ruleset: "default"
  secrets:
    enabled: true
    scan_history: true
  sca:
    enabled: true
  iac:
    enabled: true
  dast:
    enabled: false
  resilience:
    enabled: true

ignore:
  paths:
    - "testdata/**"
    - "vendor/**"
    - "node_modules/**"
  findings: []
`

const starterWorkflow = `name: Sentinel Security Gate

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write

jobs:
  security-scan:
    name: Sentinel Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Base Policy (Protected Branch)
        if: github.event_name == 'pull_request'
        run: |
          mkdir -p "${RUNNER_TEMP}"
          if git show "origin/${{ github.base_ref }}:.sentinel.yml" > "${RUNNER_TEMP}/trusted-policy.yml" 2>/dev/null; then
            echo "Using base-branch policy from origin/${{ github.base_ref }}"
            echo "POLICY_FLAG=--config=${RUNNER_TEMP}/trusted-policy.yml" >> $GITHUB_ENV
          else
            echo "Base branch has no .sentinel.yml; using default repository policy"
            echo "POLICY_FLAG=" >> $GITHUB_ENV
          fi

      - name: Run Sentinel Scan
        uses: DraculaHub786/DevSecOps-Unified-Scanner/deploy/github-actions/sentinel-scan@v0.1.2
        with:
          fail-on: "high"
          upload-sarif: "true"
          args: "--ci ${{ env.POLICY_FLAG }}"
`

func newInitCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Initialize starter .sentinel.yml configuration and CI workflow",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := "."
			if len(args) > 0 {
				targetDir = args[0]
			}

			absTarget, err := filepath.Abs(targetDir)
			if err != nil {
				return fmt.Errorf("error resolving path %q: %w", targetDir, err)
			}

			configPath := filepath.Join(absTarget, ".sentinel.yml")
			workflowDir := filepath.Join(absTarget, ".github", "workflows")
			workflowPath := filepath.Join(workflowDir, "sentinel.yml")

			if !force {
				if _, err := os.Stat(configPath); err == nil {
					return fmt.Errorf("%s already exists (use --force to overwrite)", configPath)
				}
				if _, err := os.Stat(workflowPath); err == nil {
					return fmt.Errorf("%s already exists (use --force to overwrite)", workflowPath)
				}
			}

			if err := os.MkdirAll(workflowDir, 0755); err != nil {
				return fmt.Errorf("error creating directory %s: %w", workflowDir, err)
			}

			if err := os.WriteFile(configPath, []byte(starterConfig), 0644); err != nil {
				return fmt.Errorf("error writing %s: %w", configPath, err)
			}

			if err := os.WriteFile(workflowPath, []byte(starterWorkflow), 0644); err != nil {
				return fmt.Errorf("error writing %s: %w", workflowPath, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Initialized Sentinel configuration: %s\n", configPath)
			fmt.Fprintf(cmd.OutOrStdout(), "✅ Initialized GitHub Actions CI workflow: %s\n", workflowPath)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing configuration and workflow files")
	return cmd
}
