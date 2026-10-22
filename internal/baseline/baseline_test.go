package baseline

import (
	"os"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestBaselineSaveLoadAndFilter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-baseline-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	findings := []orchestrator.Finding{
		{
			ID:          "f-1",
			Fingerprint: "fp-1",
			Rule:        "rule-1",
			Severity:    "high",
		},
		{
			ID:          "f-2",
			Fingerprint: "fp-2",
			Rule:        "rule-2",
			Severity:    "medium",
		},
	}

	savedPath, err := Save(tmpDir, findings)
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}
	if _, err := os.Stat(savedPath); err != nil {
		t.Fatalf("Expected baseline file to exist at %s: %v", savedPath, err)
	}

	loadedSet, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if len(loadedSet) != 2 {
		t.Fatalf("Expected 2 fingerprints loaded, got %d", len(loadedSet))
	}
	if !loadedSet["fp-1"] || !loadedSet["fp-2"] {
		t.Errorf("Expected fp-1 and fp-2 in baseline set")
	}

	// Now test filtering: existing findings should be filtered out, new ones kept
	currentFindings := []orchestrator.Finding{
		{
			ID:          "f-1",
			Fingerprint: "fp-1", // in baseline
		},
		{
			ID:          "f-3",
			Fingerprint: "fp-3", // new!
		},
	}

	newFindings := FilterNewFindings(currentFindings, loadedSet)
	if len(newFindings) != 1 {
		t.Fatalf("Expected 1 new finding, got %d", len(newFindings))
	}
	if newFindings[0].Fingerprint != "fp-3" {
		t.Errorf("Expected remaining finding to be fp-3, got %s", newFindings[0].Fingerprint)
	}
}

func TestFingerprintStabilityAcrossLineMoves(t *testing.T) {
	// A vulnerability in a file at line 10
	fp1 := orchestrator.GenerateFingerprint(
		orchestrator.CategorySAST,
		"sql-injection",
		"models/user.go",
		"db.Query(\"SELECT * FROM users WHERE id = \" + id)",
	)

	// Developer edits earlier code in the file, shifting the vulnerable line from line 10 to line 45
	// The snippet, category, rule and file remain the same
	fp2 := orchestrator.GenerateFingerprint(
		orchestrator.CategorySAST,
		"sql-injection",
		"models/user.go",
		"  db.Query(\"SELECT * FROM users WHERE id = \" + id)  ", // whitespace differences trimmed
	)

	if fp1 != fp2 {
		t.Errorf("Expected fingerprint to be stable across line moves and whitespace differences, got %s vs %s", fp1, fp2)
	}

	// Saving fp1 to baseline
	tmpDir := t.TempDir()
	f := orchestrator.Finding{
		ID:          "SENT-test1",
		Fingerprint: fp1,
		Rule:        "sql-injection",
		Severity:    orchestrator.SeverityHigh,
		File:        "models/user.go",
		LineStart:   10,
	}
	if _, err := Save(tmpDir, []orchestrator.Finding{f}); err != nil {
		t.Fatalf("Failed to save baseline: %v", err)
	}

	baselineSet, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Failed to load baseline: %v", err)
	}

	// Rescan sees the finding at line 45 with fp2
	fMoved := orchestrator.Finding{
		ID:          "SENT-test2",
		Fingerprint: fp2,
		Rule:        "sql-injection",
		Severity:    orchestrator.SeverityHigh,
		File:        "models/user.go",
		LineStart:   45,
	}

	newFindings := FilterNewFindings([]orchestrator.Finding{fMoved}, baselineSet)
	if len(newFindings) != 0 {
		t.Errorf("Expected finding at moved line to be recognized as existing baseline, but was treated as new: %+v", newFindings)
	}
}

