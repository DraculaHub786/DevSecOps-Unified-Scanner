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
