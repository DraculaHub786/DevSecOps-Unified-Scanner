package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// guardExitFinding is returned when the guard finds a violation. It is distinct from a
// genuine error so git hooks and scripts can tell "you committed a secret" apart from
// "the scanner is broken".
const guardExitFinding = 1

func newGuardCmd() *cobra.Command {
	var (
		stage      string
		failOn     string
		scanAll    bool
		repoPath   string
		configPath string
		quiet      bool
		deep       bool
	)

	cmd := &cobra.Command{
		Use:   "guard",
		Short: "Fast pre-commit / pre-push security gate over changed files only",
		Long: `Guard is the command git hooks call. It scans only the files in the change set,
uses the embedded engine when no external scanner is installed, and is designed to
finish in well under a second on a typical commit.

Exit codes:
  0  clean (commit may proceed)
  1  findings at or above --fail-on (commit blocked)
  2  genuine error (config, git, or scanner failure)

Bypass a single commit with: SENTINEL_SKIP=1 git commit ...`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				repoPath = args[0]
			}
			if repoPath == "" {
				repoPath = "."
			}
			absRepo, err := filepath.Abs(repoPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sentinel guard: cannot resolve %s: %v\n", repoPath, err)
				os.Exit(2)
			}

			// Explicit, logged bypass. Never silent.
			if os.Getenv("SENTINEL_SKIP") != "" {
				fmt.Fprintln(os.Stderr, "sentinel guard: SKIPPED because SENTINEL_SKIP is set. This bypass is logged.")
				os.Exit(0)
			}

			os.Exit(runGuard(absRepo, stage, failOn, scanAll, configPath, quiet, deep))
		},
	}

	cmd.Flags().StringVar(&stage, "stage", "pre-commit", "Hook stage: pre-commit (staged files) or pre-push (pushed range)")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Block on severity: critical|high|medium|low")
	cmd.Flags().BoolVar(&scanAll, "all", false, "Scan the entire working tree instead of the change set")
	cmd.Flags().StringVar(&configPath, "config", "", "Explicit path to .sentinel.yml")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Only print on failure")
	cmd.Flags().BoolVar(&deep, "deep", false, "Also run external engines (Semgrep/Gitleaks). Adds several seconds per commit")
	return cmd
}

// runGuard returns the process exit code.
func runGuard(absRepo, stage, failOn string, scanAll bool, configPath string, quiet, deep bool) int {
	started := time.Now()

	cfg, err := loadGuardConfig(absRepo, configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel guard: %v\n", err)
		return 2
	}
	if failOn != "" {
		cfg.Thresholds.FailOn = failOn
	}

	// A pre-commit hook must never touch the network. Left online, Semgrep fetches the
	// p/default registry pack on every single commit, which measured at ~24s for a
	// one-file change.
	cfg.Offline = true

	// Default to the embedded engine. Measured: embedded completes in ~100ms, while a
	// single-file run with the external Semgrep CLI takes 17-24s because every rule is
	// re-parsed from scratch on process start. A hook that takes 20s is a hook developers
	// disable on day one, which protects nothing. --deep opts into the external engines
	// for those who want maximum depth and accept the cost.
	if !deep {
		cfg.Engine = "embedded"
	}

	changedFiles, err := resolveChangeSet(absRepo, stage, scanAll)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel guard: %v\n", err)
		return 2
	}
	if len(changedFiles) == 0 {
		if !quiet {
			fmt.Println("sentinel guard: no scannable changes in this commit.")
		}
		return 0
	}

	// Guard is deliberately fast and dependency-free. The embedded engine always runs;
	// external engines are used only if already present, never required.
	scheduler := orchestrator.NewScheduler(
		gitleaks.New(),
		semgrep.New(),
		resilience.New(),
	)

	// Every adapter walks the tree it is given. To keep a commit fast we hand it a
	// temporary workspace containing only the changed files, preserving their relative
	// paths so reported locations still match the real repository. Without this the hook
	// scans the whole repository on every commit, which is why the old hook was unusable.
	scanRoot := absRepo
	if !scanAll && len(changedFiles) > 0 {
		staged, cleanup, stageErr := stageChangedFiles(absRepo, changedFiles)
		if stageErr != nil {
			fmt.Fprintf(os.Stderr, "sentinel guard: cannot stage change set: %v\n", stageErr)
			return 2
		}
		defer cleanup()
		scanRoot = staged
	}

	opts := orchestrator.ScanOptions{
		RepoPath:       scanRoot,
		Incremental:    true,
		ChangedFiles:   changedFiles,
		Timeout:        60 * time.Second,
		AllowLite:      true, // an embedded result is valid for a pre-commit gate
		GuardMode:      true, // suppress the "all engines required" CI behaviour
		OnlyCategories: guardCategories(stage),
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentinel guard: scan failed: %v\n", err)
		return 2
	}

	failRank := orchestrator.SeverityRank(cfg.Thresholds.FailOn)
	var blocking []orchestrator.Finding
	for _, f := range result.Findings {
		if orchestrator.SeverityRank(f.Severity) >= failRank {
			blocking = append(blocking, f)
		}
	}

	elapsed := time.Since(started).Milliseconds()

	if len(blocking) == 0 {
		if !quiet {
			fmt.Printf("sentinel guard: clean (%d files, %dms).\n", len(changedFiles), elapsed)
		}
		return 0
	}

	fmt.Fprintf(os.Stderr, "\n\033[31m✗ Sentinel blocked this %s — %d finding(s) at or above '%s'\033[0m\n\n",
		strings.ReplaceAll(stage, "-", " "), len(blocking), cfg.Thresholds.FailOn)
	for _, f := range blocking {
		fmt.Fprintf(os.Stderr, "  %-8s %s:%d\n           %s\n           rule=%s  category=%s\n\n",
			strings.ToUpper(f.Severity), f.File, f.LineStart, f.Message, f.Rule, f.Category)
	}
	fmt.Fprintln(os.Stderr, "Fix these before committing, or bypass once with:")
	fmt.Fprintln(os.Stderr, "  SENTINEL_SKIP=1 git commit ...")
	return guardExitFinding
}

// loadGuardConfig loads policy but never fails because a repo has no .sentinel.yml.
func loadGuardConfig(absRepo, configPath string) (*config.Config, error) {
	if configPath != "" {
		return config.LoadFile(configPath)
	}
	cfg, err := config.Load(absRepo)
	if err != nil {
		// A malformed policy is a real error: silently defaulting would let a broken
		// policy disable the guard.
		return nil, fmt.Errorf("invalid .sentinel.yml: %w", err)
	}
	return cfg, nil
}

// resolveChangeSet determines which files the guard must examine.
func resolveChangeSet(absRepo, stage string, scanAll bool) ([]string, error) {
	if scanAll {
		return nil, nil // nil == scan everything
	}
	var raw []string
	switch strings.ToLower(stage) {
	case "pre-push":
		raw = gitPushedFiles(absRepo)
	default:
		raw = gitStagedFiles(absRepo)
	}
	return filterScannable(raw), nil
}

// guardCategories keeps the per-commit path cheap. Dependency and container scanning
// are slow and belong in pre-push or CI, not on every commit.
func guardCategories(stage string) []string {
	if strings.EqualFold(stage, "pre-push") {
		return []string{orchestrator.CategorySecret, orchestrator.CategorySAST, orchestrator.CategorySCA}
	}
	return []string{orchestrator.CategorySecret, orchestrator.CategorySAST}
}

// stageChangedFiles copies the change set into a throwaway directory, preserving each
// file's path relative to the repository root. Scanning that directory yields findings
// whose File values match the real repository, while keeping the work proportional to
// the size of the commit rather than the size of the repository.
func stageChangedFiles(absRepo string, files []string) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "sentinel-guard-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	for _, rel := range files {
		// Refuse absolute paths or anything that escapes the repository.
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
			continue
		}
		src := filepath.Join(absRepo, rel)
		info, statErr := os.Stat(src)
		if statErr != nil || info.IsDir() {
			continue // deleted between git listing us and us reading it
		}
		dst := filepath.Join(tmpDir, rel)
		if mkErr := os.MkdirAll(filepath.Dir(dst), 0755); mkErr != nil {
			cleanup()
			return "", nil, mkErr
		}
		data, readErr := os.ReadFile(src)
		if readErr != nil {
			continue // unreadable file should not break the commit
		}
		if writeErr := os.WriteFile(dst, data, 0644); writeErr != nil {
			cleanup()
			return "", nil, writeErr
		}
	}
	return tmpDir, cleanup, nil
}
