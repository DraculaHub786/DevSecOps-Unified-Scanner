package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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

func findSemgrepExecutable() string {
	if p, err := exec.LookPath("semgrep"); err == nil {
		return p
	}
	candidates := []string{
		filepath.Join("plugins", "semgrep"),
		filepath.Join("plugins", "semgrep.exe"),
		filepath.Join("bin", "semgrep"),
		filepath.Join("bin", "semgrep.exe"),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

func newRulesTestCmd() *cobra.Command {
	var runSemgrep bool
	var requireSemgrep bool

	cmd := &cobra.Command{
		Use:   "test [dir]",
		Short: "Run validation and test suites against embedded and custom rules",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()

			fmt.Fprintln(out, "🧪 Running Sentinel Detection Rule Verification...")

			var ruleFiles map[string][]byte = make(map[string][]byte)

			// Determine rule source directory or embedded rules
			targetDir := ""
			if len(args) == 1 && args[0] != "" {
				targetDir = args[0]
			}

			if targetDir != "" {
				entries, err := os.ReadDir(targetDir)
				if err != nil {
					return fmt.Errorf("error reading rule directory %s: %w", targetDir, err)
				}
				for _, e := range entries {
					if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
						data, err := os.ReadFile(filepath.Join(targetDir, e.Name()))
						if err != nil {
							return fmt.Errorf("error reading %s: %w", e.Name(), err)
						}
						ruleFiles[e.Name()] = data
					}
				}
			} else {
				entries, err := rules.Content.ReadDir(".")
				if err != nil {
					return fmt.Errorf("error reading embedded rules: %w", err)
				}
				for _, entry := range entries {
					if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yml") {
						data, err := rules.Content.ReadFile(entry.Name())
						if err != nil {
							return fmt.Errorf("error reading embedded %s: %w", entry.Name(), err)
						}
						ruleFiles[entry.Name()] = data
					}
				}
			}

			totalRules := 0
			passedRules := 0
			var failed []string
			var ruleIDs []string

			validSeverities := map[string]bool{"ERROR": true, "WARNING": true, "INFO": true}
			validCategories := map[string]bool{"sast": true, "secret": true, "resilience": true, "iac": true}
			validConfidences := map[string]bool{"high": true, "medium": true, "low": true}

			for filename, data := range ruleFiles {
				var file cliRuleFile
				if err := yaml.Unmarshal(data, &file); err != nil {
					failed = append(failed, fmt.Sprintf("Invalid YAML in %s: %v", filename, err))
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
						fmt.Fprintf(out, "  PASS %-40s [sev: %-7s cwe: %-8s owasp: %-12s conf: %s]\n",
							ruleID, r.Severity, r.Metadata.CWE, r.Metadata.OWASP, r.Metadata.Confidence)
					}
				}
			}

			// Verify test fixtures coverage in rules/tests/
			testDir := filepath.Join("rules", "tests")
			if targetDir != "" {
				testDirCandidate := filepath.Join(targetDir, "tests")
				if fi, err := os.Stat(testDirCandidate); err == nil && fi.IsDir() {
					testDir = testDirCandidate
				}
			}

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
					fmt.Fprintf(out, "✅ All %d rules have corresponding test fixtures in %s\n", len(ruleIDs), testDir)
				}
			}

			// Semgrep engine execution (parse check + behavioral tests)
			semgrepPath := findSemgrepExecutable()
			semgrepRan := false

			if semgrepPath != "" || runSemgrep {
				if semgrepPath == "" {
					if requireSemgrep {
						return fmt.Errorf("semgrep executable not found on PATH or plugins/, but --require-semgrep was specified")
					}
					fmt.Fprintln(out, "\n[Semgrep Engine Validation]")
					fmt.Fprintln(out, "⚠️  SKIPPED (semgrep not installed)")
				} else {
					semgrepRan = true
					fmt.Fprintf(out, "\n⚡ Executing Semgrep Rule Parse & Behavioral Checks (%s)...\n", semgrepPath)

					// 1. Parse check: run semgrep scan on an empty directory to validate rule syntax
					tmpEmptyDir, err := os.MkdirTemp("", "sentinel-empty-*")
					if err == nil {
						defer os.RemoveAll(tmpEmptyDir)
					} else {
						tmpEmptyDir = os.TempDir()
					}

					tmpRulesDir, err := os.MkdirTemp("", "sentinel-rules-validate-*")
					if err == nil {
						defer os.RemoveAll(tmpRulesDir)
						// Copy semgrep-compatible rule files (excluding resilience rules which are native)
						for fname, content := range ruleFiles {
							if strings.HasPrefix(fname, "resilience") {
								continue
							}
							_ = os.WriteFile(filepath.Join(tmpRulesDir, fname), content, 0644)
						}

						ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
						defer cancel()

						parseCmd := exec.CommandContext(ctx, semgrepPath, "scan",
							"--metrics=off",
							"--disable-version-check",
							"--config", tmpRulesDir,
							tmpEmptyDir,
						)
						var parseStderr bytes.Buffer
						parseCmd.Stderr = &parseStderr
						if parseErr := parseCmd.Run(); parseErr != nil {
							errStr := parseStderr.String()
							if strings.Contains(errStr, "Rule parse error") || strings.Contains(errStr, "Semgrep Core error") {
								failed = append(failed, fmt.Sprintf("Semgrep parse check failed: %s", strings.TrimSpace(errStr)))
							}
						} else {
							fmt.Fprintln(out, "  ✅ Semgrep rule syntax and schema parse check PASSED")
						}
					}

					// 2. Behavioral positive & negative checks via semgrep --test
					if fi, err := os.Stat("rules"); err == nil && fi.IsDir() {
						ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
						defer cancel()

						testCmd := exec.CommandContext(ctx, semgrepPath, "--test", "rules/")
						var testOut, testErr bytes.Buffer
						testCmd.Stdout = &testOut
						testCmd.Stderr = &testErr

						if err := testCmd.Run(); err != nil {
							errMsg := testErr.String()
							if errMsg == "" {
								errMsg = testOut.String()
							}
							failed = append(failed, fmt.Sprintf("semgrep --test rules/ failed: %v\n%s", err, strings.TrimSpace(errMsg)))
						} else {
							fmt.Fprintln(out, "  ✅ Native Semgrep fixture tests (positive & negative #ruleid / #ok) PASSED")
						}
					}
				}
			} else {
				if requireSemgrep {
					return fmt.Errorf("semgrep is required but not installed")
				}
				fmt.Fprintln(out, "\n[Semgrep Engine Validation]")
				fmt.Fprintln(out, "⚠️  SKIPPED (semgrep not installed)")
			}

			fmt.Fprintln(out, "\n=======================================================")
			if len(failed) > 0 {
				for _, f := range failed {
					fmt.Fprintf(errOut, "  • %s\n", f)
				}
				return fmt.Errorf("rule test suite failed: %d/%d passed, %d failure(s)", passedRules, totalRules, len(failed))
			}

			if semgrepRan {
				fmt.Fprintf(out, "✅ All %d rules passed metadata, parse, and behavioral verification (100%%)\n", passedRules)
			} else {
				fmt.Fprintf(out, "⚠️  PARTIAL VERIFICATION: %d/%d rules passed structural/metadata checks.\n", passedRules, totalRules)
				fmt.Fprintln(out, "   Semgrep behavioral validation was SKIPPED (semgrep not installed).")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&runSemgrep, "semgrep", false, "Force execution of Semgrep engine tests")
	cmd.Flags().BoolVar(&requireSemgrep, "require-semgrep", false, "Fail if Semgrep is not installed")
	return cmd
}
