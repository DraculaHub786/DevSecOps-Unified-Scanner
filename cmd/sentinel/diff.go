package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
)

func newDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <scan-id-a> <scan-id-b>",
		Short: "Compare findings between two past scans (new vs fixed flaws)",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			idA, err1 := strconv.ParseInt(args[0], 10, 64)
			idB, err2 := strconv.ParseInt(args[1], 10, 64)
			if err1 != nil || err2 != nil {
				fmt.Fprintln(os.Stderr, "Error: scan IDs must be numeric integers.")
				os.Exit(2)
			}

			repoPath, _ := filepath.Abs(".")
			store, err := report.NewSQLiteStore(repoPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open history store: %v\n", err)
				os.Exit(2)
			}

			diff, err := store.CompareScans(idA, idB)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to compute diff between scan %d and %d: %v\n", idA, idB, err)
				os.Exit(2)
			}

			fmt.Printf("\n📊 Findings Diff: Scan #%d -> Scan #%d\n", idA, idB)
			fmt.Println("==========================================================================================")
			fmt.Printf("✨ New Findings:       %d\n", len(diff.New))
			fmt.Printf("✅ Fixed Findings:      %d\n", len(diff.Fixed))
			fmt.Printf("⏸️  Unchanged Findings:  %d\n", len(diff.Unchanged))
			fmt.Println("------------------------------------------------------------------------------------------")

			if len(diff.New) > 0 {
				fmt.Println("\n🚨 NEW FINDINGS INTRODUCED:")
				for _, f := range diff.New {
					fmt.Printf("  [+] [%s] %-8s %s:%d (Rule: %s, Risk: %.1f)\n",
						f.Engine, f.Severity, f.File, f.LineStart, f.Rule, f.RiskScore)
				}
			}

			if len(diff.Fixed) > 0 {
				fmt.Println("\n🎉 FINDINGS RESOLVED / FIXED:")
				for _, f := range diff.Fixed {
					fmt.Printf("  [-] [%s] %-8s %s:%d (Rule: %s)\n",
						f.Engine, f.Severity, f.File, f.LineStart, f.Rule)
				}
			}
			fmt.Println("==========================================================================================")
			fmt.Println()
		},
	}
}
