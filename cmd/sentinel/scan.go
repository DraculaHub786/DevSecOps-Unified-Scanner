package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/baseline"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
)

func newScanCmd() *cobra.Command {
	var (
		onlyCategories  []string
		skipCategories  []string
		targetURL       string
		dastFlag        bool
		resilienceFlag  bool
		ciMode          bool
		allowLite       bool
		useBaseline     bool
		changedOnly     bool
		failOn          string
		formatStr       string
		outFile         string
		authorized      bool
		configPath      string
		repoPath        string
		sinceRef        string
		showCoverage    bool
		offline         bool
		noColor         bool
		trustRepoPolicy bool
	)

	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan repository or directory for security vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if noColor {
				report.DisableColors()
			}
			if len(args) > 0 {
				repoPath = args[0]
			} else {
				repoPath = "."
			}

			runScanInternal(
				repoPath,
				configPath,
				onlyCategories,
				skipCategories,
				changedOnly,
				nil,
				failOn,
				formatStr,
				outFile,
				ciMode,
				allowLite,
				useBaseline,
				targetURL,
				offline,
				authorized,
				sinceRef,
				trustRepoPolicy,
			)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Explicit path to .sentinel.yml policy file (e.g. from trusted base ref)")
	cmd.Flags().StringSliceVar(&onlyCategories, "only", nil, "Scan specific categories only (sast,sca,secrets,iac,dast,resilience)")
	cmd.Flags().StringSliceVar(&skipCategories, "skip", nil, "Skip specific categories")
	cmd.Flags().StringVar(&targetURL, "target", "", "Target URL for DAST scanning")
	cmd.Flags().BoolVar(&dastFlag, "dast", false, "Enable DAST runtime scanning")
	cmd.Flags().BoolVar(&authorized, "i-have-authorization", false, "Mandatory authorization flag for DAST scanning")
	cmd.Flags().BoolVar(&resilienceFlag, "resilience", false, "Enable resilience/DoS posture checks")
	cmd.Flags().BoolVar(&ciMode, "ci", false, "CI mode: fail build on threshold and halt if missing tools unless --allow-lite")
	cmd.Flags().BoolVar(&allowLite, "allow-lite", false, "Allow embedded fallback engines to run in --ci mode without failing")
	cmd.Flags().BoolVar(&useBaseline, "baseline", false, "Filter out accepted baseline findings from .sentinel/baseline.json")
	cmd.Flags().BoolVar(&changedOnly, "changed-only", false, "Scan only modified and uncommitted files in git workspace")
	cmd.Flags().StringVar(&sinceRef, "since", "", "Scan files changed since git ref or commit SHA (e.g. main, HEAD~1)")
	cmd.Flags().BoolVar(&showCoverage, "show-coverage", true, "Show category coverage summary in report output")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail gating on severity: critical|high|medium|low")
	cmd.Flags().StringVar(&formatStr, "format", "terminal", "Output formats (terminal,sarif,json,markdown,html,junit)")
	cmd.Flags().StringVar(&outFile, "out", "", "File path to write primary report output")
	cmd.Flags().BoolVar(&offline, "offline", false, "Disable network requests")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable ANSI color output in terminal")
	cmd.Flags().BoolVar(&trustRepoPolicy, "trust-repo-policy", false, "In --ci, accept a .sentinel.yml found inside the scanned repository (default: refuse; use --config with a trusted policy)")

	return cmd
}

func runScanInternal(
	repoPath string,
	configPath string,
	onlyCategories []string,
	skipCategories []string,
	changedOnly bool,
	changedFiles []string,
	failOn string,
	formatStr string,
	outFile string,
	ciMode bool,
	allowLite bool,
	useBaseline bool,
	targetURL string,
	offline bool,
	authorized bool,
	sinceRef string,
	trustRepoPolicy bool,
) {
	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(2)
	}

	// Policy that lives in the code under review is controlled by whoever wrote that
	// code, so a CI gate must not obey it unless the caller says so explicitly.
	if err := checkUntrustedPolicy(ciMode, configPath, trustRepoPolicy, absRepo); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v.\n", err)
		fmt.Fprintln(os.Stderr, "Pass --config <policy from the protected base branch>, or --trust-repo-policy to accept this file.")
		os.Exit(2)
	}

	var cfg *config.Config
	if configPath != "" {
		loaded, err := config.LoadFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading policy from %s: %v\n", configPath, err)
			os.Exit(2)
		}
		cfg = loaded
		fmt.Printf("Policy: %s\n", configPath)
	} else {
		loaded, err := config.Load(absRepo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load .sentinel.yml: %v (using defaults)\n", err)
			loaded = config.DefaultConfig()
		}
		cfg = loaded
	}

	if auditWarnings := config.Audit(cfg); len(auditWarnings) > 0 {
		for _, w := range auditWarnings {
			fmt.Fprintf(os.Stderr, "⚠️ Policy Audit: %s\n", w)
		}
	}

	if offline {
		cfg.Offline = true
	}

	if failOn != "" {
		cfg.Thresholds.FailOn = failOn
	}

	if targetURL != "" {
		cfg.Scanners.DAST.Enabled = true
		cfg.Scanners.DAST.Target = targetURL
	}

	if sinceRef != "" {
		changedOnly = true
		changedFiles = detectGitChangedSince(absRepo, sinceRef)
	} else if changedOnly && len(changedFiles) == 0 {
		changedFiles = detectGitChangedFiles(absRepo)
	}

	scheduler := orchestrator.NewScheduler(
		gitleaks.New(),
		osv.New(),
		semgrep.New(),
		trivy.New(),
		nuclei.NewWithAuth(authorized),
		resilience.New(),
		govulncheck.New(),
	)

	opts := orchestrator.ScanOptions{
		RepoPath:       absRepo,
		OnlyCategories: onlyCategories,
		SkipCategories: skipCategories,
		TargetURL:      targetURL,
		Incremental:    changedOnly,
		ChangedFiles:   changedFiles,
		Timeout:        90 * time.Second,
		CI:             ciMode,
		AllowLite:      allowLite,
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan execution failed: %v\n", err)
		os.Exit(2)
	}

	// Filter baseline if requested
	if useBaseline {
		if baselineSet, err := baseline.Load(absRepo); err == nil {
			origCount := len(result.Findings)
			result.Findings = baseline.FilterNewFindings(result.Findings, baselineSet)
			fmt.Printf("🛡️ Baseline filter applied: %d accepted findings ignored (%d new findings remain)\n",
				origCount-len(result.Findings), len(result.Findings))
		} else {
			fmt.Fprintf(os.Stderr, "Warning: failed to load baseline: %v\n", err)
		}
	}

	// Save to local SQLite history
	if store, err := report.NewSQLiteStore(absRepo); err == nil {
		_ = store.RecordScan(result, getGitCommit(absRepo))
	}

	// Render requested formats
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
			sarifData, err := report.GenerateSARIFWithCoverage(result.Findings, result.Coverage)
			if err == nil {
				if outFile != "" {
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
				if outFile != "" {
					_ = os.WriteFile(outFile, jsonData, 0644)
					fmt.Printf("JSON report written to: %s\n", outFile)
				} else {
					defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "results.json")
					_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
					_ = os.WriteFile(defaultOut, jsonData, 0644)
				}
			}
		case "markdown", "md":
			md := report.GenerateMarkdown(result, cfg.Thresholds.FailOn)
			if outFile != "" {
				_ = os.WriteFile(outFile, []byte(md), 0644)
				fmt.Printf("Markdown report written to: %s\n", outFile)
			} else {
				defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "summary.md")
				_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
				_ = os.WriteFile(defaultOut, []byte(md), 0644)
			}
		case "html":
			htmlContent := report.GenerateHTML(result, cfg.Thresholds.FailOn)
			if outFile != "" {
				_ = os.WriteFile(outFile, []byte(htmlContent), 0644)
				fmt.Printf("HTML report written to: %s\n", outFile)
			} else {
				defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "report.html")
				_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
				_ = os.WriteFile(defaultOut, []byte(htmlContent), 0644)
			}
		case "junit", "xml":
			junitData, err := report.GenerateJUnit(result, cfg.Thresholds.FailOn)
			if err == nil {
				if outFile != "" {
					_ = os.WriteFile(outFile, junitData, 0644)
					fmt.Printf("JUnit report written to: %s\n", outFile)
				} else {
					defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "junit.xml")
					_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
					_ = os.WriteFile(defaultOut, junitData, 0644)
				}
			}
		}
	}

	// Gating check for CI mode exit code
	if shouldFailGating(ciMode, cfg.Thresholds.FailOn, result.Findings) {
		os.Exit(1)
	}

	os.Exit(0)
}

func shouldFailGating(ciMode bool, failOn string, findings []orchestrator.Finding) bool {
	if !ciMode {
		return false
	}

	failRank := orchestrator.SeverityRank(failOn)
	for _, f := range findings {
		if orchestrator.SeverityRank(f.Severity) >= failRank {
			return true
		}
	}
	return false
}

func checkUntrustedPolicy(ciMode bool, configPath string, trustRepoPolicy bool, absRepo string) error {
	if ciMode && configPath == "" && !trustRepoPolicy {
		if _, statErr := os.Stat(filepath.Join(absRepo, ".sentinel.yml")); statErr == nil {
			return fmt.Errorf("--ci found .sentinel.yml inside the scanned repository. Policy from the code under review is untrusted")
		}
	}
	return nil
}

func detectGitChangedFiles(repoPath string) []string {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: not a git repository or git command unavailable; falling back to full scan\n")
		return nil
	}

	var changed []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 3 {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				changed = append(changed, parts[len(parts)-1])
			}
		}
	}
	return changed
}

func detectGitChangedSince(repoPath, ref string) []string {
	cmd := exec.Command("git", "diff", "--name-only", ref)
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: git diff failed against ref %q; falling back to full scan\n", ref)
		return nil
	}

	var changed []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			changed = append(changed, line)
		}
	}

	// Also append untracked files
	untrackedCmd := exec.Command("git", "ls-files", "--others", "--exclude-standard")
	untrackedCmd.Dir = repoPath
	if unOut, err := untrackedCmd.Output(); err == nil {
		for _, line := range strings.Split(string(unOut), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				changed = append(changed, line)
			}
		}
	}

	return changed
}
