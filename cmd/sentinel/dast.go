package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/safety"
)

func newDASTCmd() *cobra.Command {
	var (
		targetURL  string
		authorized bool
		failOn     string
	)

	cmd := &cobra.Command{
		Use:   "dast",
		Short: "Run dynamic application security testing against an authorized web target",
		Run: func(cmd *cobra.Command, args []string) {
			if targetURL == "" {
				fmt.Fprintln(os.Stderr, "Error: --target URL is required for DAST scanning.")
				os.Exit(2)
			}

			repoPath, _ := filepath.Abs(".")
			cfg, err := config.Load(repoPath)
			if err != nil {
				cfg = config.DefaultConfig()
			}

			// Enforce legal and network safety boundaries
			if err := safety.ValidateTarget(targetURL, cfg.Scanners.DAST.Allowlist, authorized, cfg.Scanners.DAST.AllowPrivate); err != nil {
				fmt.Fprintf(os.Stderr, "🛡️ DAST Safety Refusal: %v\n", err)
				os.Exit(2)
			}

			fmt.Printf("🌐 Starting DAST scan against target: %s\n", targetURL)
			adapter := nuclei.New()

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()

			findings, err := adapter.Run(ctx, repoPath, cfg, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "DAST execution error: %v\n", err)
				os.Exit(2)
			}

			res := &orchestrator.ScanResult{
				StartedAt:  time.Now(),
				FinishedAt: time.Now(),
				Mode:       "full",
				Discovery: &orchestrator.DiscoveryResult{
					RepoPath: targetURL,
				},
				Findings: findings,
			}

			for _, f := range findings {
				res.Summary.Total++
				switch stringsToLower(f.Severity) {
				case "critical":
					res.Summary.Critical++
				case "high":
					res.Summary.High++
				case "medium":
					res.Summary.Medium++
				case "low":
					res.Summary.Low++
				}
			}

			report.RenderTerminal(os.Stdout, res, failOn)

			failRank := orchestrator.SeverityRank(failOn)
			for _, f := range findings {
				if orchestrator.SeverityRank(f.Severity) >= failRank {
					os.Exit(1)
				}
			}
		},
	}

	cmd.Flags().StringVar(&targetURL, "target", "", "Target URL to scan (e.g. https://staging.example.com)")
	cmd.Flags().BoolVar(&authorized, "i-have-authorization", false, "Mandatory acknowledgement that you own or have explicit authorization to test this target")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail gating threshold: critical|high|medium|low")
	_ = cmd.MarkFlagRequired("target")

	return cmd
}
