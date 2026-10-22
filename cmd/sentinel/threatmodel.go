package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/threatmodel"
	"github.com/spf13/cobra"
)

func newThreatModelCmd() *cobra.Command {
	var (
		format string
		out    string
	)

	cmd := &cobra.Command{
		Use:     "threat-model [path]",
		Aliases: []string{"threatmodel"},
		Short:   "Generate automated threat model with entry points, data stores, and STRIDE mapping",
		Args:    cobra.MaximumNArgs(1),
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
				resilience.New(),
			)

			fmt.Println("🗺️ Scanning workspace and mapping STRIDE threat model...")
			result, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
				RepoPath: absRepo,
				Timeout:  90 * time.Second,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Scan failed during threat modeling: %v\n", err)
				os.Exit(2)
			}

			tmReport, err := threatmodel.GenerateThreatModel(absRepo, result.Findings)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Threat model generation failed: %v\n", err)
				os.Exit(2)
			}

			var outputText string
			if format == "json" {
				data, _ := json.MarshalIndent(tmReport, "", "  ")
				outputText = string(data)
			} else {
				outputText = tmReport.RenderMarkdown()
			}

			if out != "" {
				if err := os.WriteFile(out, []byte(outputText), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to write report to %s: %v\n", out, err)
					os.Exit(2)
				}
				fmt.Printf("✅ Threat model report written to: %s\n", out)
			} else {
				fmt.Println(outputText)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "md", "Output format: md or json")
	cmd.Flags().StringVar(&out, "out", "", "Output file destination (e.g. THREATMODEL.md)")

	return cmd
}
