package report

import (
	"os"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestSQLiteStoreRecordListAndCompare(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-sqlite-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewSQLiteStore(tmpDir)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}

	// 1. Record Scan 1 with 2 findings (f1, f2)
	res1 := &orchestrator.ScanResult{
		StartedAt:  time.Now().Add(-10 * time.Minute),
		FinishedAt: time.Now().Add(-9 * time.Minute),
		Summary: orchestrator.SeveritySummary{
			Total:    2,
			Critical: 1,
			High:     1,
		},
		Findings: []orchestrator.Finding{
			{
				ID:          "f-1",
				Fingerprint: "fp-1",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySAST,
				Severity:    "critical",
				File:        "app.go",
				LineStart:   10,
				RiskScore:   90.0,
			},
			{
				ID:          "f-2",
				Fingerprint: "fp-2",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySecret,
				Severity:    "high",
				File:        "app.go",
				LineStart:   20,
				RiskScore:   80.0,
			},
		},
	}

	if err := store.RecordScan(res1, "commit-sha-1"); err != nil {
		t.Fatalf("RecordScan(1) failed: %v", err)
	}

	// 2. Record Scan 2 with 2 findings (f2 unchanged, f3 new, f1 fixed)
	res2 := &orchestrator.ScanResult{
		StartedAt:  time.Now().Add(-5 * time.Minute),
		FinishedAt: time.Now().Add(-4 * time.Minute),
		Summary: orchestrator.SeveritySummary{
			Total:    2,
			Critical: 0,
			High:     2,
		},
		Findings: []orchestrator.Finding{
			{
				ID:          "f-2",
				Fingerprint: "fp-2", // unchanged
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySecret,
				Severity:    "high",
				File:        "app.go",
				LineStart:   20,
				RiskScore:   80.0,
			},
			{
				ID:          "f-3",
				Fingerprint: "fp-3", // new!
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySCA,
				Severity:    "high",
				File:        "go.mod",
				LineStart:   15,
				RiskScore:   75.0,
			},
		},
	}

	if err := store.RecordScan(res2, "commit-sha-2"); err != nil {
		t.Fatalf("RecordScan(2) failed: %v", err)
	}

	// 3. Test ListScans
	scans, err := store.ListScans()
	if err != nil {
		t.Fatalf("ListScans failed: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("Expected 2 recorded scans, got %d", len(scans))
	}
	if scans[0].CommitSHA != "commit-sha-2" {
		t.Errorf("Expected latest scan first (commit-sha-2), got %s", scans[0].CommitSHA)
	}

	// 4. Test CompareScans (scan 1 vs scan 2)
	diff, err := store.CompareScans(scans[1].ID, scans[0].ID)
	if err != nil {
		t.Fatalf("CompareScans failed: %v", err)
	}

	if len(diff.New) != 1 {
		t.Fatalf("Expected 1 new finding in diff, got %d", len(diff.New))
	}
	if diff.New[0].Fingerprint != "fp-3" {
		t.Errorf("Expected new finding fp-3, got %s", diff.New[0].Fingerprint)
	}

	if len(diff.Fixed) != 1 {
		t.Fatalf("Expected 1 fixed finding in diff, got %d", len(diff.Fixed))
	}
	if diff.Fixed[0].Fingerprint != "fp-1" {
		t.Errorf("Expected fixed finding fp-1, got %s", diff.Fixed[0].Fingerprint)
	}

	if len(diff.Unchanged) != 1 {
		t.Fatalf("Expected 1 unchanged finding in diff, got %d", len(diff.Unchanged))
	}
	if diff.Unchanged[0].Fingerprint != "fp-2" {
		t.Errorf("Expected unchanged finding fp-2, got %s", diff.Unchanged[0].Fingerprint)
	}
}
