package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
)

func newTestRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "sentinel",
		Short: "Sentinel CLI",
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newSecretsCmd())
	rootCmd.AddCommand(newDepsCmd())
	rootCmd.AddCommand(newSASTCmd())
	rootCmd.AddCommand(newIaCCmd())
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
	rootCmd.AddCommand(newExplainCmd())
	rootCmd.AddCommand(newFixCmd())
	rootCmd.AddCommand(newWatchCmd())
	rootCmd.AddCommand(newInstallHooksCmd())
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newConfigCmd())
	rootCmd.AddCommand(newRulesCmd())
	rootCmd.AddCommand(newCompletionCmd())

	return rootCmd
}

func TestCommandSmokeTable(t *testing.T) {
	commands := []struct {
		name string
		args []string
	}{
		{"scan help", []string{"scan", "--help"}},
		{"secrets help", []string{"secrets", "--help"}},
		{"deps help", []string{"deps", "--help"}},
		{"sast help", []string{"sast", "--help"}},
		{"iac help", []string{"iac", "--help"}},
		{"image help", []string{"image", "--help"}},
		{"sbom help", []string{"sbom", "--help"}},
		{"dast help", []string{"dast", "--help"}},
		{"threat-model help", []string{"threat-model", "--help"}},
		{"baseline help", []string{"baseline", "--help"}},
		{"diff help", []string{"diff", "--help"}},
		{"history help", []string{"history", "--help"}},
		{"report help", []string{"report", "--help"}},
		{"suppress help", []string{"suppress", "--help"}},
		{"doctor help", []string{"doctor", "--help"}},
		{"explain help", []string{"explain", "--help"}},
		{"fix help", []string{"fix", "--help"}},
		{"watch help", []string{"watch", "--help"}},
		{"install-hooks help", []string{"install-hooks", "--help"}},
		{"version help", []string{"version", "--help"}},
		{"init help", []string{"init", "--help"}},
		{"config help", []string{"config", "--help"}},
		{"config validate help", []string{"config", "validate", "--help"}},
		{"rules help", []string{"rules", "--help"}},
		{"rules test help", []string{"rules", "test", "--help"}},
		{"completion help", []string{"completion", "--help"}},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			root := newTestRootCmd()
			buf := new(bytes.Buffer)
			root.SetOut(buf)
			root.SetErr(buf)
			root.SetArgs(tc.args)

			err := root.Execute()
			if err != nil {
				t.Fatalf("command %v failed: %v", tc.args, err)
			}
			out := buf.String()
			if len(out) == 0 {
				t.Fatalf("command %v returned empty output", tc.args)
			}
		})
	}
}

func TestInitAndConfigValidateFlow(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Run init in tmpDir
	root := newTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", tmpDir})
	if err := root.Execute(); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	configPath := filepath.Join(tmpDir, ".sentinel.yml")
	workflowPath := filepath.Join(tmpDir, ".github", "workflows", "sentinel.yml")

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected %s to be created", configPath)
	}
	if _, err := os.Stat(workflowPath); err != nil {
		t.Fatalf("expected %s to be created", workflowPath)
	}

	// 2. Validate the generated config with config validate
	root = newTestRootCmd()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"config", "validate", configPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("config validate failed on generated config: %v (output: %s)", err, buf.String())
	}

	// 3. Running init again without --force should fail
	root = newTestRootCmd()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", tmpDir})
	if err := root.Execute(); err == nil {
		t.Fatalf("expected init without --force to fail when files exist")
	}

	// 4. Running init with --force should succeed
	root = newTestRootCmd()
	buf.Reset()
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"init", "--force", tmpDir})
	if err := root.Execute(); err != nil {
		t.Fatalf("expected init --force to succeed, got: %v", err)
	}
}

func TestRulesTestCommand(t *testing.T) {
	root := newTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"rules", "test"})

	if err := root.Execute(); err != nil {
		t.Fatalf("rules test failed: %v (output: %s)", err, buf.String())
	}
}
