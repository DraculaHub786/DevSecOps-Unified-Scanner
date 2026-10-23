package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/report"
	"github.com/spf13/cobra"
)

func newReportCmd() *cobra.Command {
	var (
		formatStr string
		outFile   string
	)

	cmd := &cobra.Command{
		Use:   "report <scan-id>",
		Short: "Re-render an existing historical scan report in sarif, md, html, or json format",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			scanID, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error: scan ID must be an integer.")
				os.Exit(2)
			}

			repoPath, _ := filepath.Abs(".")
			dbPath := filepath.Join(repoPath, ".sentinel", "history.db")
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open history database: %v\n", err)
				os.Exit(2)
			}
			defer db.Close()

			var r orchestrator.ScanResult
			var startStr, finStr, commitSHA string
			row := db.QueryRow(`SELECT started_at, finished_at, commit_sha, total_findings, critical_count, high_count FROM scans WHERE id = ?`, scanID)
			if err := row.Scan(&startStr, &finStr, &commitSHA, &r.Summary.Total, &r.Summary.Critical, &r.Summary.High); err != nil {
				fmt.Fprintf(os.Stderr, "Scan #%d not found in history: %v\n", scanID, err)
				os.Exit(2)
			}
			r.StartedAt, _ = time.Parse(time.RFC3339, startStr)
			r.FinishedAt, _ = time.Parse(time.RFC3339, finStr)
			r.Mode = "full"
			r.Discovery = &orchestrator.DiscoveryResult{RepoPath: repoPath}

			rows, err := db.Query(`SELECT id, fingerprint, engine, category, severity, file, line_start, risk_score FROM findings WHERE scan_id = ?`, scanID)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var f orchestrator.Finding
					if err := rows.Scan(&f.ID, &f.Fingerprint, &f.Engine, &f.Category, &f.Severity, &f.File, &f.LineStart, &f.RiskScore); err == nil {
						f.Rule = f.ID
						r.Findings = append(r.Findings, f)
					}
				}
				if err := rows.Err(); err != nil {
					_ = err
				}
			}

			switch formatStr {
			case "sarif":
				sarifData, err := report.GenerateSARIF(r.Findings)
				if err != nil {
					fmt.Fprintf(os.Stderr, "SARIF generation error: %v\n", err)
					os.Exit(2)
				}
				outputOrPrint(sarifData, outFile)
			case "html":
				htmlData := report.GenerateHTML(&r, "high")
				outputOrPrint([]byte(htmlData), outFile)
			case "md", "markdown":
				mdData := report.GenerateMarkdown(&r, "high")
				outputOrPrint([]byte(mdData), outFile)
			case "json":
				jsonData, err := report.GenerateJSON(&r)
				if err != nil {
					fmt.Fprintf(os.Stderr, "JSON generation error: %v\n", err)
					os.Exit(2)
				}
				outputOrPrint(jsonData, outFile)
			default:
				report.RenderTerminal(os.Stdout, &r, "high")
			}
		},
	}

	cmd.Flags().StringVar(&formatStr, "format", "terminal", "Output format: sarif, html, md, json, terminal")
	cmd.Flags().StringVar(&outFile, "out", "", "File destination path")

	return cmd
}

func outputOrPrint(data []byte, dest string) {
	if dest != "" {
		if err := os.WriteFile(dest, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output to %s: %v\n", dest, err)
			os.Exit(2)
		}
		fmt.Printf("✅ Report successfully saved to: %s\n", dest)
	} else {
		fmt.Println(string(data))
	}
}
