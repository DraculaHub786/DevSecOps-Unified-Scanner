package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
)

func newSBOMCmd() *cobra.Command {
	var (
		format string
		out    string
	)

	cmd := &cobra.Command{
		Use:   "sbom [path]",
		Short: "Generate Software Bill of Materials (SBOM) in CycloneDX or SPDX format",
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

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()

			if err := trivy.GenerateSBOM(ctx, absRepo, format, out); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating SBOM: %v\n", err)
				os.Exit(2)
			}
		},
	}

	cmd.Flags().StringVar(&format, "format", "cyclonedx", "SBOM standard: cyclonedx or spdx")
	cmd.Flags().StringVar(&out, "out", "", "Output file path (e.g. bom.cdx.json)")

	return cmd
}
