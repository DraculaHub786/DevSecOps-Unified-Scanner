package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestBenchmarkScansTimingAndAccuracy executes cold, warm, and incremental scans,
// asserts performance timing thresholds (<10s SLA), and verifies zero false merges.
func TestBenchmarkScansTimingAndAccuracy(t *testing.T) {
	repoPath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-app"))
	if err != nil {
		t.Fatalf("failed to resolve vulnerable-app path: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Scanners.DAST.Enabled = false

	scheduler := orchestrator.NewScheduler(
		gitleaks.New(),
		osv.New(),
		semgrep.New(),
		trivy.New(),
		nuclei.New(),
		resilience.New(),
		govulncheck.New(),
	)

	// 1. Cold Scan (ensuring cache is clean)
	sentinelDir := filepath.Join(repoPath, ".sentinel")
	_ = os.RemoveAll(sentinelDir)

	coldStart := time.Now()
	coldRes, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
		RepoPath: repoPath,
	})
	coldDuration := time.Since(coldStart)

	if err != nil {
		t.Fatalf("cold scan failed: %v", err)
	}
	t.Logf("⏱️ Cold Scan Completed in: %v (Findings: %d)", coldDuration, len(coldRes.Findings))

	if coldDuration > 10*time.Second {
		t.Errorf("cold scan exceeded 10s threshold SLA: took %v", coldDuration)
	}

	// 2. Warm Scan (cached scan state)
	warmStart := time.Now()
	warmRes, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
		RepoPath: repoPath,
	})
	warmDuration := time.Since(warmStart)

	if err != nil {
		t.Fatalf("warm scan failed: %v", err)
	}
	t.Logf("⏱️ Warm Scan Completed in: %v (Findings: %d)", warmDuration, len(warmRes.Findings))

	if warmDuration > 10*time.Second {
		t.Errorf("warm scan exceeded 10s threshold SLA: took %v", warmDuration)
	}

	// 3. Incremental Scan (changed files only)
	incStart := time.Now()
	incRes, err := scheduler.Execute(context.Background(), cfg, orchestrator.ScanOptions{
		RepoPath:     repoPath,
		Incremental:  true,
		ChangedFiles: []string{"app.py"},
	})
	incDuration := time.Since(incStart)

	if err != nil {
		t.Fatalf("incremental scan failed: %v", err)
	}
	t.Logf("⏱️ Incremental Scan Completed in: %v (Findings: %d)", incDuration, len(incRes.Findings))

	if incDuration > 10*time.Second {
		t.Errorf("incremental scan exceeded 10s threshold SLA: took %v", incDuration)
	}

	// 4. Verification of Zero False Merges & Deduplication Accuracy
	incorrectMerges := 0
	mergedCount := 0

	for _, f := range coldRes.Findings {
		// Verify every finding has mandatory fields
		if f.ID == "" || f.File == "" || f.Severity == "" || f.Category == "" {
			t.Errorf("finding missing required fields: %+v", f)
		}

		isMerged := len(f.Sources) > 1 || strings.Contains(f.Source, "+")
		if isMerged {
			mergedCount++

			// Ensure merged findings do not cross unrelated files
			if strings.Contains(f.File, ",") || strings.Contains(f.File, ";") {
				t.Errorf("false merge detected across multiple file targets: %s", f.File)
				incorrectMerges++
			}

			// Ensure secrets are never merged into non-secret categories
			if strings.Contains(f.Source, "gitleaks") && f.Category != orchestrator.CategorySecret {
				t.Errorf("false merge: secret engine merged into non-secret category %s", f.Category)
				incorrectMerges++
			}
		}
	}

	t.Logf("🔍 Deduplication Accuracy Check: Merged Findings = %d, Incorrect Merges = %d", mergedCount, incorrectMerges)

	if incorrectMerges != 0 {
		t.Fatalf("detected %d false/incorrect cross-tool merges (expected zero false merges)", incorrectMerges)
	}
}
