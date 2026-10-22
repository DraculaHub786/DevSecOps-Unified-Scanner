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

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/doctor"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
)

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <finding-id> [path]",
		Short: "Print rule rationale, CWE link, and remediation guidance for a finding",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			findingID := args[0]
			targetPath := "."
			if len(args) > 1 {
				targetPath = args[1]
			}
			repoPath, _ := filepath.Abs(targetPath)

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
				fmt.Fprintf(os.Stderr, "Finding ID %s not found in scan of %s.\n", findingID, repoPath)
				os.Exit(1)
			}

			fmt.Println("\n=======================================================")
			fmt.Printf("🔍 Finding Details: %s\n", matched.ID)
			fmt.Println("=======================================================")
			fmt.Printf("Severity:    %s\n", strings.ToUpper(matched.Severity))
			fmt.Printf("Category:    %s\n", matched.Category)
			fmt.Printf("Engine:      %s\n", matched.Engine)
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
		Use:   "fix <finding-id> [path]",
		Short: "Preview or apply automated remediation fix for a finding",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			findingID := args[0]
			targetPath := "."
			if len(args) > 1 {
				targetPath = args[1]
			}
			repoPath, _ := filepath.Abs(targetPath)

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
sentinel scan --fail-on=high --ci
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
			fmt.Printf("Sentinel DevSecOps Unified Scanner v%s (commit: %s, built: %s)\n", version, commit, date)
			fmt.Println("Rules: embedded v1 (40 SAST rules, 4 resilience rules)")
			fmt.Println("\nDetected Scanner Engines:")
			statuses := doctor.CheckEngines()
			for _, s := range statuses {
				ver := s.Version
				if ver == "" {
					ver = "none"
				}
				fmt.Printf("  • %-12s: %-10s (%s)\n", s.Name, ver, s.Mode)
			}
			fmt.Println("\nUse 'sentinel doctor' for deep diagnostics, paths, and pinned version comparison.")
		},
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
