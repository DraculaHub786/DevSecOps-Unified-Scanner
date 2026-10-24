package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/govulncheck"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

type groundTruthEntry struct {
	Category string `json:"category"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Rule     string `json:"rule"`
}

type metrics struct {
	TP int
	FP int
	FN int
}

func (m metrics) Precision() float64 {
	if m.TP+m.FP == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(m.TP+m.FP)
}

func (m metrics) Recall() float64 {
	if m.TP+m.FN == 0 {
		return 1.0
	}
	return float64(m.TP) / float64(m.TP+m.FN)
}

func (m metrics) F1() float64 {
	p := m.Precision()
	r := m.Recall()
	if p+r == 0 {
		return 0.0
	}
	return 2 * (p * r) / (p + r)
}

func newBenchDetectCmd() *cobra.Command {
	var minScore float64

	cmd := &cobra.Command{
		Use:   "bench-detect [benchmark-dir]",
		Short: "Benchmark detection accuracy (Precision, Recall, F1) against labelled ground truth",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			errOut := cmd.ErrOrStderr()

			benchDir := filepath.Join("testdata", "benchmark")
			if len(args) == 1 && args[0] != "" {
				benchDir = args[0]
			}

			absBenchDir, err := filepath.Abs(benchDir)
			if err != nil {
				return fmt.Errorf("resolving benchmark directory: %w", err)
			}

			gtPath := filepath.Join(absBenchDir, "ground_truth.json")
			gtBytes, err := os.ReadFile(gtPath)
			if err != nil {
				return fmt.Errorf("reading ground truth file %s: %w", gtPath, err)
			}

			var groundTruth []groundTruthEntry
			if err := json.Unmarshal(gtBytes, &groundTruth); err != nil {
				return fmt.Errorf("unmarshaling ground truth JSON: %w", err)
			}

			fmt.Fprintf(out, "\n🎯 Sentinel Detection Benchmark (bench-detect)\n")
			fmt.Fprintf(out, "   Corpus: %s (%d labelled ground-truth issues)\n\n", absBenchDir, len(groundTruth))

			scheduler := orchestrator.NewScheduler(
				gitleaks.New(),
				osv.New(),
				semgrep.New(),
				trivy.New(),
				nuclei.NewWithAuth(false),
				resilience.New(),
				govulncheck.New(),
			)

			cfg := config.DefaultConfig()
			cfg.Offline = true

			opts := orchestrator.ScanOptions{
				RepoPath: absBenchDir,
				Timeout:  45 * time.Second,
			}

			result, err := scheduler.Execute(context.Background(), cfg, opts)
			if err != nil {
				return fmt.Errorf("benchmark scan failed: %w", err)
			}

			// Map ground truth by matching key (category|file|rule)
			gtMatched := make(map[int]bool)
			catMetrics := make(map[string]*metrics)
			overall := &metrics{}

			getCat := func(cat string) *metrics {
				cat = strings.ToLower(cat)
				if _, ok := catMetrics[cat]; !ok {
					catMetrics[cat] = &metrics{}
				}
				return catMetrics[cat]
			}

			// Count TP and FP from actual findings
			for _, f := range result.Findings {
				relFile := filepath.ToSlash(f.File)
				matchedGTIndex := -1

				for idx, gt := range groundTruth {
					if gtMatched[idx] {
						continue
					}
					gtRel := filepath.ToSlash(gt.File)
					if strings.EqualFold(gt.Category, f.Category) &&
						(strings.HasSuffix(relFile, gtRel) || strings.EqualFold(relFile, gtRel)) {
						matchedGTIndex = idx
						break
					}
				}

				m := getCat(f.Category)
				if matchedGTIndex >= 0 {
					gtMatched[matchedGTIndex] = true
					m.TP++
					overall.TP++
				} else {
					m.FP++
					overall.FP++
				}
			}

			// Count FN from remaining unmatched ground truth
			for idx, gt := range groundTruth {
				if !gtMatched[idx] {
					m := getCat(gt.Category)
					m.FN++
					overall.FN++
				}
			}

			fmt.Fprintf(out, "%-15s | %4s | %4s | %4s | %10s | %10s | %10s\n",
				"CATEGORY", "TP", "FP", "FN", "PRECISION", "RECALL", "F1-SCORE")
			fmt.Fprintf(out, "%s\n", strings.Repeat("-", 75))

			for cat, m := range catMetrics {
				fmt.Fprintf(out, "%-15s | %4d | %4d | %4d | %9.1f%% | %9.1f%% | %10.3f\n",
					strings.ToUpper(cat), m.TP, m.FP, m.FN, m.Precision()*100, m.Recall()*100, m.F1())
			}

			fmt.Fprintf(out, "%s\n", strings.Repeat("-", 75))
			fmt.Fprintf(out, "%-15s | %4d | %4d | %4d | %9.1f%% | %9.1f%% | %10.3f\n\n",
				"OVERALL", overall.TP, overall.FP, overall.FN, overall.Precision()*100, overall.Recall()*100, overall.F1())

			if minScore > 0 && overall.F1() < minScore {
				fmt.Fprintf(errOut, "❌ Benchmark failed: Overall F1-Score %.3f is below required minimum %.3f\n", overall.F1(), minScore)
				return fmt.Errorf("detection benchmark score below threshold")
			}

			fmt.Fprintln(out, "✅ Detection benchmark complete. Baseline performance verified.")
			return nil
		},
	}

	cmd.Flags().Float64Var(&minScore, "min-f1", 0.8, "Minimum acceptable overall F1-score")
	return cmd
}
