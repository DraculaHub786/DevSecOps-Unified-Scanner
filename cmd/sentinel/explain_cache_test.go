package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestExplainUsesStoredFindingCacheWithoutInvokingEngine(t *testing.T) {
	tmpDir := t.TempDir()

	storedFinding := orchestrator.Finding{
		ID:          "SENT-CACHED-ID-99",
		Category:    orchestrator.CategorySAST,
		Severity:    orchestrator.SeverityHigh,
		Engine:      orchestrator.EngineExternal,
		Rule:        "org-js-sql-injection-concat",
		File:        "server.js",
		LineStart:   22,
		Message:     "Cached test finding message",
		RiskScore:   85.5,
		FirstSeen:   time.Now().UTC(),
		Fingerprint: "cached-fp-99",
	}

	res := orchestrator.ScanResult{
		StartedAt:  time.Now().UTC(),
		FinishedAt: time.Now().UTC(),
		Mode:       "full",
		Findings:   []orchestrator.Finding{storedFinding},
	}

	dotSentinel := filepath.Join(tmpDir, ".sentinel")
	if err := os.MkdirAll(dotSentinel, 0755); err != nil {
		t.Fatalf("failed to create .sentinel dir: %v", err)
	}

	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal scan result: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dotSentinel, "last-scan.json"), data, 0644); err != nil {
		t.Fatalf("failed to write last-scan.json: %v", err)
	}

	// PATH pointing to an empty directory guarantees no external scanner can be found or run
	fakeBinDir := t.TempDir()
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeBinDir)
	defer os.Setenv("PATH", origPath)

	found, err := lookupFinding(tmpDir, "SENT-CACHED-ID-99")
	if err != nil {
		t.Fatalf("lookupFinding failed on cached ID: %v", err)
	}

	if found.ID != "SENT-CACHED-ID-99" {
		t.Errorf("expected finding ID SENT-CACHED-ID-99, got %s", found.ID)
	}
	if found.LineStart != 22 {
		t.Errorf("expected line 22, got %d", found.LineStart)
	}
	if found.Message != "Cached test finding message" {
		t.Errorf("expected cached message, got %s", found.Message)
	}
}
