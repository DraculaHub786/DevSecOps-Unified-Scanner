package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/rules"
)

type cliRule struct {
	ID        string   `yaml:"id"`
	Message   string   `yaml:"message"`
	Severity  string   `yaml:"severity"`
	Languages []string `yaml:"languages"`
	Metadata  struct {
		CWE        string `yaml:"cwe"`
		OWASP      string `yaml:"owasp"`
		Category   string `yaml:"category"`
		Confidence string `yaml:"confidence"`
	} `yaml:"metadata"`
}

type cliRuleFile struct {
	Rules []cliRule `yaml:"rules"`
}

func newRulesCmd() *cobra.Command {
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage and test Sentinel detection rules",
	}

	rulesCmd.AddCommand(newRulesTestCmd())
	return rulesCmd
}

func newRulesTestCmd() *cobra.Command {
	var runSemgrep bool

	cmd := &cobra.Command{
		Use:   "test [dir]",
		Short: "Run validation and test suites against embedded and custom rules",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "🧪 Running Sentinel Detection Rule Verification...")

			entries, err := rules.Content.ReadDir(".")
			if err != nil {
				return fmt.Errorf("error reading embedded rules: %w", err)
			}

			totalRules := 0
			passedRules := 0
			var failed []string
			var ruleIDs []string

			validSeverities := map[string]bool{"ERROR": true, "WARNING": true, "INFO": true}
			validCategories := map[string]bool{"sast": true, "secret": true, "resilience": true, "iac": true}
			validConfidences := map[string]bool{"high": true, "medium": true, "low": true}

			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
					continue
				}

				data, err := rules.Content.ReadFile(entry.Name())
				if err != nil {
					failed = append(failed, fmt.Sprintf("Failed to read %s: %v", entry.Name(), err))
					continue
				}

				var file cliRuleFile
				if err := yaml.Unmarshal(data, &file); err != nil {
					failed = append(failed, fmt.Sprintf("Invalid YAML in %s: %v", entry.Name(), err))
					continue
				}

				for _, r := range file.Rules {
					totalRules++
					ruleID := strings.TrimSpace(r.ID)
					var errs []string

					if ruleID == "" {
						errs = append(errs, "empty rule id")
					}
					if strings.TrimSpace(r.Message) == "" {
						errs = append(errs, "empty message")
					}
					if len(r.Languages) == 0 {
						errs = append(errs, "empty languages")
					}
					if !validSeverities[strings.ToUpper(strings.TrimSpace(r.Severity))] {
						errs = append(errs, fmt.Sprintf("invalid severity %q", r.Severity))
					}
					if strings.TrimSpace(r.Metadata.CWE) == "" {
						errs = append(errs, "missing metadata.cwe")
					}
					if strings.TrimSpace(r.Metadata.OWASP) == "" {
						errs = append(errs, "missing metadata.owasp")
					}
					if !validCategories[strings.ToLower(strings.TrimSpace(r.Metadata.Category))] {
						errs = append(errs, fmt.Sprintf("invalid metadata.category %q", r.Metadata.Category))
					}
					if !validConfidences[strings.ToLower(strings.TrimSpace(r.Metadata.Confidence))] {
						errs = append(errs, fmt.Sprintf("invalid metadata.confidence %q", r.Metadata.Confidence))
					}

					if len(errs) > 0 {
						failed = append(failed, fmt.Sprintf("FAIL %s: %s", ruleID, strings.Join(errs, ", ")))
					} else {
						passedRules++
						ruleIDs = append(ruleIDs, ruleID)
						fmt.Fprintf(cmd.OutOrStdout(), "  PASS %-40s [sev: %-7s cwe: %-8s owasp: %-12s conf: %s]\n",
							ruleID, r.Severity, r.Metadata.CWE, r.Metadata.OWASP, r.Metadata.Confidence)
					}
				}
			}

			// Also verify test coverage in rules/tests/ if present
			testDir := filepath.Join("rules", "tests")
			if fi, err := os.Stat(testDir); err == nil && fi.IsDir() {
				testEntries, _ := os.ReadDir(testDir)
				testContent := ""
				for _, te := range testEntries {
					if !te.IsDir() {
						c, _ := os.ReadFile(filepath.Join(testDir, te.Name()))
						testContent += "\n" + string(c)
					}
				}

				missingTests := 0
				for _, id := range ruleIDs {
					if !strings.Contains(testContent, id) {
						failed = append(failed, fmt.Sprintf("Rule %q has no test case in %s", id, testDir))
						missingTests++
					}
				}
				if missingTests == 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "✅ All %d rules have corresponding test fixtures in %s\n", len(ruleIDs), testDir)
				}
			}

			// If Semgrep CLI is installed or requested, wrap semgrep --test
			if runSemgrep {
				if semgrepPath, err := exec.LookPath("semgrep"); err == nil {
					fmt.Fprintf(cmd.OutOrStdout(), "\n⚡ Executing native Semgrep rule test runner (%s --test rules/)...\n", semgrepPath)
					cmdExec := exec.Command("semgrep", "--test", "rules/")
					cmdExec.Stdout = cmd.OutOrStdout()
					cmdExec.Stderr = cmd.ErrOrStderr()
					if err := cmdExec.Run(); err != nil {
						failed = append(failed, fmt.Sprintf("semgrep --test rules/ failed: %v", err))
					}
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "ℹ️ Semgrep binary not found on PATH; skipped external --test runner")
				}
			}

			fmt.Fprintln(cmd.OutOrStdout(), "\n=======================================================")
			if len(failed) > 0 {
				for _, f := range failed {
					fmt.Fprintf(cmd.ErrOrStderr(), "  • %s\n", f)
				}
				return fmt.Errorf("rule test suite failed: %d/%d passed, %d failure(s)", passedRules, totalRules, len(failed))
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ All %d rules passed metadata and test verification (100%%)\n", passedRules)
			return nil
		},
	}

	cmd.Flags().BoolVar(&runSemgrep, "semgrep", false, "Also invoke host semgrep --test runner if available")
	return cmd
}
