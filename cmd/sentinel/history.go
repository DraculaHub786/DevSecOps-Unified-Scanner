package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
)

func newHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history [path]",
		Short: "Display historical scan runs and finding trends",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			repoPath := "."
			if len(args) > 0 {
				repoPath = args[0]
			}
			absRepo, _ := filepath.Abs(repoPath)

			store, err := report.NewSQLiteStore(absRepo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open history store: %v\n", err)
				os.Exit(2)
			}

			scans, err := store.ListScans()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to retrieve scan history: %v\n", err)
				os.Exit(2)
			}

			if len(scans) == 0 {
				fmt.Println("No past scans recorded in this repository.")
				return
			}

			fmt.Println("\n📜 Sentinel Scan History")
			fmt.Println("==========================================================================================")
			fmt.Printf("%-8s %-22s %-12s %-10s %-10s %-10s\n", "SCAN ID", "TIMESTAMP", "COMMIT", "TOTAL", "CRITICAL", "HIGH")
			fmt.Println("------------------------------------------------------------------------------------------")
			for _, s := range scans {
				fmt.Printf("%-8d %-22s %-12s %-10d %-10d %-10d\n",
					s.ID,
					s.StartedAt.Format("2006-01-02 15:04:05"),
					s.CommitSHA,
					s.TotalFindings,
					s.CriticalCount,
					s.HighCount,
				)
			}
			fmt.Println("==========================================================================================")
			fmt.Println("Use 'sentinel diff <idA> <idB>' to compare changes between two scans.")
		},
	}
}
