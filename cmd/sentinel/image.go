package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
)

func newImageCmd() *cobra.Command {
	var failOn string

	cmd := &cobra.Command{
		Use:   "image <image-name>",
		Short: "Scan container image for vulnerabilities and misconfigurations using Trivy",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			imageName := args[0]

			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()

			fmt.Printf("🐳 Scanning container image: %s\n", imageName)
			findings, err := trivy.ScanImage(ctx, imageName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Container scan error: %v\n", err)
				os.Exit(2)
			}

			res := &orchestrator.ScanResult{
				StartedAt:  time.Now(),
				FinishedAt: time.Now(),
				Mode:       "full",
				Discovery: &orchestrator.DiscoveryResult{
					RepoPath: imageName,
				},
				Findings: findings,
			}

			// Calculate summary
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

	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail gating threshold: critical|high|medium|low")
	return cmd
}

func stringsToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
