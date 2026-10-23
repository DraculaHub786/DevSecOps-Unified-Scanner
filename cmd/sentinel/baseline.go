package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
)

func newBaselineCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "baseline [path]",
		Short: "Accept current findings into baseline so subsequent scans only alert on new flaws",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			repoPath := "."
			if len(args) > 0 {
				repoPath = args[0]
			}
			absRepo, err := filepath.Abs(repoPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
				os.Exit(2)
			}

			cfg, err := config.Load(absRepo)
			if err != nil {
				cfg = config.DefaultConfig()
			}

			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.New(),
				resilience.New(),
				govulncheck.New(),
			)

			fmt.Println("🔍 Scanning repository to establish security baseline...")
			result, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
				RepoPath: absRepo,
				Timeout:  90 * time.Second,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Baseline scan failed: %v\n", err)
				os.Exit(2)
			}

			savedPath, err := baseline.Save(absRepo, result.Findings)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write baseline file: %v\n", err)
				os.Exit(2)
			}

			fmt.Printf("✅ Accepted %d findings into baseline.\n", len(result.Findings))
			fmt.Printf("📁 Saved baseline configuration: %s\n", savedPath)
			fmt.Println("Subsequent scans running with --baseline will ignore these existing findings.")
		},
	}
}
