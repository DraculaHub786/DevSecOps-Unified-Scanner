package gitleaks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestParseGitleaksGolden(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "gitleaks.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file %s: %v", goldenPath, err)
	}

	cfg := config.DefaultConfig()
	findings, err := ParseReport(data, ".", cfg)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Engine != orchestrator.EngineExternal {
		t.Errorf("Expected engine %s, got %s", orchestrator.EngineExternal, f.Engine)
	}
	if f.Severity != orchestrator.SeverityCritical {
		t.Errorf("Expected severity %s, got %s", orchestrator.SeverityCritical, f.Severity)
	}
	if f.CWE != "CWE-798" {
		t.Errorf("Expected CWE-798, got %s", f.CWE)
	}
	if f.File != ".env" {
		t.Errorf("Expected file .env, got %s", f.File)
	}
	if f.LineStart != 12 {
		t.Errorf("Expected line 12, got %d", f.LineStart)
	}
	if !strings.Contains(f.Message, "AWS Access Key") {
		t.Errorf("Expected message to contain 'AWS Access Key', got %s", f.Message)
	}
}
