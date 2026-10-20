package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentinel-dev/sentinel/internal/adapters/gitleaks"
	"github.com/sentinel-dev/sentinel/internal/adapters/nuclei"
	"github.com/sentinel-dev/sentinel/internal/adapters/osv"
	"github.com/sentinel-dev/sentinel/internal/adapters/resilience"
	"github.com/sentinel-dev/sentinel/internal/adapters/semgrep"
	"github.com/sentinel-dev/sentinel/internal/adapters/trivy"
	"github.com/sentinel-dev/sentinel/internal/config"
	"github.com/sentinel-dev/sentinel/internal/orchestrator"
	"github.com/sentinel-dev/sentinel/internal/report"
)

var (
	version = "1.0.0"
	commit  = "none"
	date    = "2026-10-20"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sentinel",
		Short: "🛡️ Sentinel — Unified DevSecOps SAST, SCA, Secrets, IaC, and Resilience Scanner",
		Long: `Sentinel orchestrates industry-standard vulnerability detection engines
(Semgrep, Trivy, OSV-Scanner, Gitleaks, Nuclei) behind one unified interface,
correlates and deduplicates their output, scores contextual risk, and suggests
actionable inline remediations without leaking source code.`,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newExplainCmd())
	rootCmd.AddCommand(newFixCmd())
	rootCmd.AddCommand(newWatchCmd())
	rootCmd.AddCommand(newInstallHooksCmd())
	rootCmd.AddCommand(newVersionCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func newScanCmd() *cobra.Command {
	var (
		onlyCategories []string
		targetURL      string
		dastFlag       bool
		resilienceFlag bool
		ciMode         bool
		failOn         string
		formatStr      string
		outFile        string
		offline        bool
		repoPath       string
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan repository or directory for security vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				repoPath = args[0]
			} else {
				repoPath = "."
			}

			absRepo, err := filepath.Abs(repoPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
				os.Exit(2)
			}

			cfg, err := config.Load(absRepo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load .sentinel.yml: %v (using defaults)\n", err)
				cfg = config.DefaultConfig()
			}

			if failOn != "" {
				cfg.Thresholds.FailOn = failOn
			}

			if dastFlag && targetURL != "" {
				cfg.Scanners.DAST.Enabled = true
				cfg.Scanners.DAST.Target = targetURL
			}
			if resilienceFlag {
				cfg.Scanners.Resilience.Enabled = true
			}

			// Instantiate adapters
			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
			)

			opts := orchestrator.ScanOptions{
				RepoPath:       absRepo,
				OnlyCategories: onlyCategories,
				TargetURL:      targetURL,
				Timeout:        90 * time.Second,
			}

			result, err := scheduler.Execute(context.Background(), cfg, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Scan execution failed: %v\n", err)
				os.Exit(2)
			}

			// Save to local SQLite history
			if store, err := report.NewSQLiteStore(absRepo); err == nil {
				_ = store.RecordScan(result, getGitCommit(absRepo))
			}

			// Render outputs
			formats := strings.Split(formatStr, ",")
			if len(formats) == 0 || (len(formats) == 1 && formats[0] == "") {
				formats = cfg.Output.Formats
			}

			for _, fmtType := range formats {
				fmtType = strings.TrimSpace(strings.ToLower(fmtType))
				switch fmtType {
				case "terminal":
					report.RenderTerminal(os.Stdout, result, cfg.Thresholds.FailOn)
				case "sarif":
					sarifData, err := report.GenerateSARIF(result.Findings)
					if err == nil {
						if outFile != "" && strings.HasSuffix(outFile, ".sarif") {
							_ = os.WriteFile(outFile, sarifData, 0644)
							fmt.Printf("SARIF report written to: %s\n", outFile)
						} else {
							defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "results.sarif")
							_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
							_ = os.WriteFile(defaultOut, sarifData, 0644)
						}
					}
				case "json":
					jsonData, err := report.GenerateJSON(result)
					if err == nil {
						if outFile != "" && strings.HasSuffix(outFile, ".json") {
							_ = os.WriteFile(outFile, jsonData, 0644)
							fmt.Printf("JSON report written to: %s\n", outFile)
						}
					}
				case "markdown":
					md := report.GenerateMarkdown(result, cfg.Thresholds.FailOn)
					if outFile != "" && strings.HasSuffix(outFile, ".md") {
						_ = os.WriteFile(outFile, []byte(md), 0644)
						fmt.Printf("Markdown report written to: %s\n", outFile)
					} else {
						defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "summary.md")
						_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
						_ = os.WriteFile(defaultOut, []byte(md), 0644)
					}
				}
			}

			// Gating check for CI mode exit code
			failRank := orchestrator.SeverityRank(cfg.Thresholds.FailOn)
			for _, f := range result.Findings {
				if orchestrator.SeverityRank(f.Severity) >= failRank {
					os.Exit(1)
				}
			}

			os.Exit(0)
		},
	}

	cmd.Flags().StringSliceVar(&onlyCategories, "only", nil, "Scan specific categories (sast,sca,secrets,iac,dast,resilience)")
	cmd.Flags().StringVar(&targetURL, "target", "", "Target URL for DAST scanning")
	cmd.Flags().BoolVar(&dastFlag, "dast", false, "Enable DAST runtime scanning")
	cmd.Flags().BoolVar(&resilienceFlag, "resilience", false, "Enable resilience/DoS posture checks")
	cmd.Flags().BoolVar(&ciMode, "ci", false, "CI mode: fail build on threshold")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail gating on severity: critical|high|medium|low")
	cmd.Flags().StringVar(&formatStr, "format", "terminal", "Output formats (terminal,sarif,json,markdown)")
	cmd.Flags().StringVar(&outFile, "out", "", "File path to write primary report output")
	cmd.Flags().BoolVar(&offline, "offline", false, "Disable network requests")

	return cmd
}

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <finding-id>",
		Short: "Print rule rationale, CWE link, and remediation guidance for a finding",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			findingID := args[0]
			repoPath, _ := filepath.Abs(".")

			cfg, _ := config.Load(repoPath)
			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
			)

			result, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{RepoPath: repoPath})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
				os.Exit(2)
			}

			var matched *orchestrator.Finding
			for _, f := range result.Findings {
				if strings.EqualFold(f.ID, findingID) {
					fCopy := f
					matched = &fCopy
					break
				}
			}

			if matched == nil {
				fmt.Fprintf(os.Stderr, "Finding ID %s not found in current workspace scan.\n", findingID)
				os.Exit(1)
			}

			fmt.Println("\n=======================================================")
			fmt.Printf("🔍 Finding Details: %s\n", matched.ID)
			fmt.Println("=======================================================")
			fmt.Printf("Severity:    %s\n", strings.ToUpper(matched.Severity))
			fmt.Printf("Category:    %s\n", matched.Category)
			fmt.Printf("Rule/CVE:    %s\n", matched.Rule)
			if matched.CVE != "" {
				fmt.Printf("CVE:         %s\n", matched.CVE)
			}
			if matched.CWE != "" {
				fmt.Printf("CWE:         https://cwe.mitre.org/data/definitions/%s.html\n", strings.TrimPrefix(matched.CWE, "CWE-"))
			}
			fmt.Printf("Location:    %s:%d\n", matched.File, matched.LineStart)
			fmt.Printf("Risk Score:  %.1f / 100\n", matched.RiskScore)
			fmt.Printf("Message:     %s\n", matched.Message)

			if matched.FixSuggestion != nil {
				fmt.Println("\n🛠️ Remediation Proposal:")
				fmt.Printf("Action:      %s\n", matched.FixSuggestion.Description)
				fmt.Printf("Confidence:  %s\n", matched.FixSuggestion.Confidence)
				if matched.FixSuggestion.Diff != "" {
					fmt.Println("\nPatch Diff Preview:")
					fmt.Println(matched.FixSuggestion.Diff)
				}
			}
			fmt.Println("=======================================================")
		},
	}
}

func newFixCmd() *cobra.Command {
	var apply bool

	cmd := &cobra.Command{
		Use:   "fix <finding-id>",
		Short: "Preview or apply automated remediation fix for a finding",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			findingID := args[0]
			repoPath, _ := filepath.Abs(".")

			cfg, _ := config.Load(repoPath)
			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
			)

			result, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{RepoPath: repoPath})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
				os.Exit(2)
			}

			var matched *orchestrator.Finding
			for _, f := range result.Findings {
				if strings.EqualFold(f.ID, findingID) {
					fCopy := f
					matched = &fCopy
					break
				}
			}

			if matched == nil {
				fmt.Fprintf(os.Stderr, "Finding ID %s not found.\n", findingID)
				os.Exit(1)
			}

			if matched.FixSuggestion == nil || matched.FixSuggestion.Diff == "" {
				fmt.Printf("No automated code patch available for %s.\nGuidance:\n%s\n", matched.ID, matched.Message)
				return
			}

			fmt.Println("\nSuggested Patch Diff:")
			fmt.Println("=======================================================")
			fmt.Println(matched.FixSuggestion.Diff)
			fmt.Println("=======================================================")

			if !apply {
				fmt.Printf("\nTo apply this patch, re-run with: sentinel fix %s --apply\n\n", matched.ID)
				return
			}

			fmt.Print("Are you sure you want to apply this patch to your workspace? (y/N): ")
			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			if input != "y" && input != "yes" {
				fmt.Println("Patch application cancelled.")
				return
			}

			diffApplied, err := orchestrator.ApplyFix(repoPath, matched)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error applying patch: %v\n", err)
				os.Exit(2)
			}

			fmt.Printf("✅ Successfully applied fix to %s:\n%s\n", matched.File, diffApplied)
		},
	}

	cmd.Flags().BoolVar(&apply, "apply", false, "Apply the patch after user confirmation")
	return cmd
}

func newWatchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch [path]",
		Short: "Watch workspace and trigger incremental scans on file modifications",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}
			absTarget, _ := filepath.Abs(target)

			fmt.Printf("👀 Sentinel Watch Mode active for %s\nPress Ctrl+C to terminate.\n\n", absTarget)

			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()

			lastScan := time.Now()
			for range ticker.C {
				var changed []string
				_ = filepath.Walk(absTarget, func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					if info.ModTime().After(lastScan) {
						rel, _ := filepath.Rel(absTarget, path)
						changed = append(changed, rel)
					}
					return nil
				})

				if len(changed) > 0 {
					fmt.Printf("\n⚡ File modification detected (%d changed files). Triggering scan...\n", len(changed))
					lastScan = time.Now()

					cfg, _ := config.Load(absTarget)
					scheduler := orchestrator.NewScheduler(
						gitleaks.New(),
						osv.New(),
						semgrep.New(),
						trivy.New(),
						resilience.New(),
					)
					res, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
						RepoPath:     absTarget,
						Incremental:  true,
						ChangedFiles: changed,
					})
					if err == nil {
						report.RenderTerminal(os.Stdout, res, cfg.Thresholds.FailOn)
					}
				}
			}
		},
	}
}

func newInstallHooksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install-hooks",
		Short: "Install Sentinel pre-commit git hook to prevent committing secrets and critical flaws",
		Run: func(cmd *cobra.Command, args []string) {
			gitHookDir := filepath.Join(".git", "hooks")
			if _, err := os.Stat(gitHookDir); err != nil {
				fmt.Fprintln(os.Stderr, "Error: current directory is not the root of a git repository.")
				os.Exit(1)
			}

			hookPath := filepath.Join(gitHookDir, "pre-commit")
			hookContent := `#!/bin/sh
# Sentinel DevSecOps Pre-Commit Guard
echo "🛡️ Running Sentinel pre-commit security verification..."
sentinel scan --fail-on=high
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ Sentinel blocked commit due to high/critical security findings."
  echo "Run 'sentinel scan' to review findings or 'sentinel fix <id>' to resolve."
  exit 1
fi
echo "✅ Sentinel security checks passed."
exit 0
`
			if err := os.WriteFile(hookPath, []byte(hookContent), 0755); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write hook: %v\n", err)
				os.Exit(2)
			}

			fmt.Println("✅ Sentinel pre-commit hook successfully installed to .git/hooks/pre-commit")
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Sentinel version and scanner engine availability",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Sentinel DevSecOps Unified Scanner v%s (commit: %s, built: %s)\n\n", version, commit, date)
			fmt.Println("Registered Scanner Adapters & Detected System Binaries:")

			checkBin("Semgrep (SAST)", "semgrep")
			checkBin("Gitleaks (Secrets)", "gitleaks")
			checkBin("OSV-Scanner (SCA)", "osv-scanner")
			checkBin("Trivy (IaC/Containers)", "trivy")
			checkBin("Nuclei (DAST)", "nuclei")
			fmt.Printf("  • Resilience/Posture Checks: Native Go Engine (Embedded) [Available]\n\n")
		},
	}
}

func checkBin(name, bin string) {
	path, err := exec.LookPath(bin)
	if err == nil {
		fmt.Printf("  • %-28s %s [Found: %s]\n", name, "External CLI", path)
	} else {
		fmt.Printf("  • %-28s %s [Fallback Engine Active]\n", name, "Embedded Native")
	}
}

func getGitCommit(repoPath string) string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	return "none"
}
