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
		onlyCategories []string
		skipCategories []string
		targetURL      string
		dastFlag       bool
		resilienceFlag bool
		ciMode         bool
		allowLite      bool
		useBaseline    bool
		changedOnly    bool
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

			runScanInternal(
				repoPath,
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
			)
		},
	}

	cmd.Flags().StringSliceVar(&onlyCategories, "only", nil, "Scan specific categories only (sast,sca,secrets,iac,dast,resilience)")
	cmd.Flags().StringSliceVar(&skipCategories, "skip", nil, "Skip specific categories")
	cmd.Flags().StringVar(&targetURL, "target", "", "Target URL for DAST scanning")
	cmd.Flags().BoolVar(&dastFlag, "dast", false, "Enable DAST runtime scanning")
	cmd.Flags().BoolVar(&resilienceFlag, "resilience", false, "Enable resilience/DoS posture checks")
	cmd.Flags().BoolVar(&ciMode, "ci", false, "CI mode: fail build on threshold and halt if missing tools unless --allow-lite")
	cmd.Flags().BoolVar(&allowLite, "allow-lite", false, "Allow embedded fallback engines to run in --ci mode without failing")
	cmd.Flags().BoolVar(&useBaseline, "baseline", false, "Filter out accepted baseline findings from .sentinel/baseline.json")
	cmd.Flags().BoolVar(&changedOnly, "changed-only", false, "Scan only modified and uncommitted files in git workspace")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail gating on severity: critical|high|medium|low")
	cmd.Flags().StringVar(&formatStr, "format", "terminal", "Output formats (terminal,sarif,json,markdown,html)")
	cmd.Flags().StringVar(&outFile, "out", "", "File path to write primary report output")
	cmd.Flags().BoolVar(&offline, "offline", false, "Disable network requests")

	return cmd
}

func runScanInternal(
	repoPath string,
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
) {
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

	if targetURL != "" {
		cfg.Scanners.DAST.Enabled = true
		cfg.Scanners.DAST.Target = targetURL
	}

	if changedOnly && len(changedFiles) == 0 {
		changedFiles = detectGitChangedFiles(absRepo)
	}

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
		case "markdown", "md":
			md := report.GenerateMarkdown(result, cfg.Thresholds.FailOn)
			if outFile != "" && (strings.HasSuffix(outFile, ".md") || strings.HasSuffix(outFile, ".markdown")) {
				_ = os.WriteFile(outFile, []byte(md), 0644)
				fmt.Printf("Markdown report written to: %s\n", outFile)
			} else {
				defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "summary.md")
				_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
				_ = os.WriteFile(defaultOut, []byte(md), 0644)
			}
		case "html":
			htmlContent := report.GenerateHTML(result, cfg.Thresholds.FailOn)
			if outFile != "" && strings.HasSuffix(outFile, ".html") {
				_ = os.WriteFile(outFile, []byte(htmlContent), 0644)
				fmt.Printf("HTML report written to: %s\n", outFile)
			} else {
				defaultOut := filepath.Join(absRepo, ".sentinel", "reports", "report.html")
				_ = os.MkdirAll(filepath.Dir(defaultOut), 0755)
				_ = os.WriteFile(defaultOut, []byte(htmlContent), 0644)
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
}

func detectGitChangedFiles(repoPath string) []string {
	cmd := exec.Command("git", "status", "--porcelain")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
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
