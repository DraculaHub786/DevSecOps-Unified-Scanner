package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/govulncheck"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
)

// lookupFinding retrieves a finding by ID from recent scan cache, falling back to rescan only if not found (P-11).
func lookupFinding(repoPath, findingID string) (*orchestrator.Finding, error) {
	// 1. Try .sentinel/last-scan.json
	lastScanPath := filepath.Join(repoPath, ".sentinel", "last-scan.json")
	if data, err := os.ReadFile(lastScanPath); err == nil {
		var res orchestrator.ScanResult
		if err := json.Unmarshal(data, &res); err == nil {
			for _, f := range res.Findings {
				if strings.EqualFold(f.ID, findingID) {
					fCopy := f
					return &fCopy, nil
				}
			}
		}
	}

	// 2. Try .sentinel/reports/results.json
	reportJSONPath := filepath.Join(repoPath, ".sentinel", "reports", "results.json")
	if data, err := os.ReadFile(reportJSONPath); err == nil {
		var res orchestrator.ScanResult
		if err := json.Unmarshal(data, &res); err == nil {
			for _, f := range res.Findings {
				if strings.EqualFold(f.ID, findingID) {
					fCopy := f
					return &fCopy, nil
				}
			}
		}
	}

	// 3. Fallback: Not in cache, inform user and run fresh scan
	fmt.Fprintf(os.Stderr, "Finding ID %s not found in recent scan cache; re-scanning %s...\n", findingID, repoPath)
	cfg, _ := config.Load(repoPath)
	scheduler := orchestrator.NewScheduler(
		gitleaks.New(),
		osv.New(),
		semgrep.New(),
		trivy.New(),
		nuclei.New(),
		resilience.New(),
		govulncheck.New(),
	)

	result, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{RepoPath: repoPath})
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Cache the scan
	_ = os.MkdirAll(filepath.Dir(lastScanPath), 0755)
	if data, err := json.MarshalIndent(result, "", "  "); err == nil {
		_ = os.WriteFile(lastScanPath, data, 0644)
	}

	for _, f := range result.Findings {
		if strings.EqualFold(f.ID, findingID) {
			fCopy := f
			return &fCopy, nil
		}
	}

	return nil, fmt.Errorf("finding ID %s not found in %s", findingID, repoPath)
}

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

			matched, err := lookupFinding(repoPath, findingID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
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
			fmt.Printf("Risk Score:  %.1f / 100\n", matched.RiskScore)
			reachStr := "unspecified"
			if matched.ReachabilityLevel != "" {
				reachStr = matched.ReachabilityLevel
			} else if matched.Reachable != nil {
				if *matched.Reachable {
					reachStr = "reachable"
				} else {
					reachStr = "unreachable"
				}
			}
			expStr := "internal"
			if matched.Exposed != nil {
				if *matched.Exposed {
					expStr = "publicly exposed"
				} else {
					expStr = "internal only"
				}
			} else {
				lowPath := strings.ToLower(matched.File)
				if strings.Contains(lowPath, "api/") || strings.Contains(lowPath, "handler") || strings.Contains(lowPath, "controller") || strings.Contains(lowPath, "route") || strings.Contains(lowPath, "server") {
					expStr = "public entry point (heuristic)"
				} else if strings.Contains(lowPath, "test") || strings.Contains(lowPath, "fixture") || strings.Contains(lowPath, "mock") {
					expStr = "test/fixture (heuristic)"
				}
			}
			fmt.Printf("Audit Inputs: Severity=%s | Reachability=%s | Exposure=%s | CVSS=%.1f\n", strings.ToUpper(matched.Severity), reachStr, expStr, matched.CVSS)
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

			matched, err := lookupFinding(repoPath, findingID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
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

			// Automatic verification re-scan (Phase 5 / P-12)
			fmt.Printf("🔄 Verifying fix: performing automatic re-scan of %s...\n", matched.File)
			rescanCfg, _ := config.Load(repoPath)
			rescanScheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
				govulncheck.New(),
			)
			rescanResult, err := rescanScheduler.Execute(context.Background(), rescanCfg, orchestrator.ScanOptions{
				RepoPath: repoPath,
			})
			if err == nil {
				lastScanPath := filepath.Join(repoPath, ".sentinel", "last-scan.json")
				if data, mErr := json.MarshalIndent(rescanResult, "", "  "); mErr == nil {
					_ = os.WriteFile(lastScanPath, data, 0644)
				}
				stillPresent := false
				for _, rf := range rescanResult.Findings {
					if rf.File == matched.File && (rf.ID == matched.ID || (rf.LineStart == matched.LineStart && rf.Rule == matched.Rule)) {
						stillPresent = true
						break
					}
				}
				if !stillPresent {
					fmt.Printf("🎉 Verification PASSED: finding %s is resolved. Zero regressions detected in %s.\n", matched.ID, matched.File)
				} else {
					fmt.Printf("⚠️ Verification WARNING: finding %s is still detected after applying fix.\n", matched.ID)
				}
			}
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
						govulncheck.New(),
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
	var force bool

	cmd := &cobra.Command{
		Use:   "install-hooks",
		Short: "Install pre-commit and pre-push guard hooks into this git repository",
		Long: `Installs git hooks that call 'sentinel guard'.

The absolute path of the running Sentinel binary is baked into the generated hook,
because PATH inside a git hook is frequently not the developer's interactive PATH.
A hook that cannot find its binary is a hook that silently protects nothing.`,
		Run: func(cmd *cobra.Command, args []string) {
			hooksDir, err := resolveHooksDir(".")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			binPath, err := os.Executable()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: cannot determine Sentinel binary path: %v\n", err)
				os.Exit(2)
			}
			binPath = filepath.ToSlash(binPath)

			hooks := []struct {
				name  string
				stage string
			}{
				{"pre-commit", "pre-commit"},
				{"pre-push", "pre-push"},
			}

			for _, h := range hooks {
				hookPath := filepath.Join(hooksDir, h.name)
				if _, statErr := os.Stat(hookPath); statErr == nil && !force {
					existing, _ := os.ReadFile(hookPath)
					if !strings.Contains(string(existing), "sentinel guard") {
						fmt.Fprintf(os.Stderr, "⚠️  %s already exists and is not a Sentinel hook; leaving it untouched (use --force to overwrite).\n", h.name)
						continue
					}
				}

				content := fmt.Sprintf(`#!/bin/sh
# Sentinel commit guard — installed by 'sentinel install-hooks'
# The binary path is absolute and quoted on purpose: PATH inside git hooks is often
# minimal, and install paths routinely contain spaces (e.g. "DevSecOps Unified Scanner").
SENTINEL_BIN='%s'

if [ ! -x "$SENTINEL_BIN" ]; then
  echo "sentinel: guard binary missing at $SENTINEL_BIN" >&2
  echo "sentinel: reinstall with 'sentinel install-hooks', or bypass once with SENTINEL_SKIP=1" >&2
  # Fail open only on an explicit bypass, so a broken install is loud, not silent.
  if [ -n "$SENTINEL_SKIP" ]; then exit 0; fi
  exit 2
fi

"$SENTINEL_BIN" guard --stage %s --fail-on high
exit $?
`, binPath, h.stage)

				if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", h.name, err)
					os.Exit(2)
				}
				fmt.Printf("✅ Installed %s -> %s\n", filepath.ToSlash(hookPath), binPath)
			}

			fmt.Println("\nCommits are now checked for secrets and SAST findings.")
			fmt.Println("Bypass a single commit with: SENTINEL_SKIP=1 git commit ...")
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing non-Sentinel hook")
	return cmd
}

// resolveHooksDir finds .git/hooks, honouring core.hooksPath and linked worktrees.
func resolveHooksDir(repoPath string) (string, error) {
	// core.hooksPath overrides the default location entirely.
	if out := gitLines(repoPath, "config", "--get", "core.hooksPath"); len(out) > 0 {
		custom := out[0]
		if !filepath.IsAbs(custom) {
			absRepo, _ := filepath.Abs(repoPath)
			custom = filepath.Join(absRepo, custom)
		}
		if err := os.MkdirAll(custom, 0755); err != nil {
			return "", err
		}
		return custom, nil
	}

	// In a linked worktree .git is a file pointing at the real git dir.
	if out := gitLines(repoPath, "rev-parse", "--git-dir"); len(out) > 0 {
		gitDir := out[0]
		if !filepath.IsAbs(gitDir) {
			absRepo, _ := filepath.Abs(repoPath)
			gitDir = filepath.Join(absRepo, gitDir)
		}
		hooks := filepath.Join(gitDir, "hooks")
		if err := os.MkdirAll(hooks, 0755); err != nil {
			return "", err
		}
		return hooks, nil
	}

	return "", fmt.Errorf("not a git repository (run 'git init' first)")
}

// normalizeEngineVersion reduces a tool's raw --version output to a bare semver.
// The raw output was pasted straight into the table, producing rows like
// "osv-scanner version: 2.7.0" and "[INF] Nuclei Engine Version: v3.3.8" that read as
// log spam rather than a version table.
func normalizeEngineVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "-"
	}
	re := regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?`)
	if m := re.FindString(raw); m != "" {
		return m
	}
	// No version number at all: keep the first line, minus common log prefixes.
	first := strings.SplitN(raw, "\n", 2)[0]
	first = strings.TrimSpace(strings.TrimPrefix(first, "[INF] "))
	if len(first) > 40 {
		first = first[:40]
	}
	return first
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
