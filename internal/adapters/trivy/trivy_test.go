package trivy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestParseTrivyGolden(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "trivy.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file %s: %v", goldenPath, err)
	}

	adapter := New()
	cfg := config.DefaultConfig()
	findings, err := adapter.ParseOutput(data, ".", cfg)
	if err != nil {
		t.Fatalf("ParseOutput failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Engine != orchestrator.EngineExternal {
		t.Errorf("Expected engine %s, got %s", orchestrator.EngineExternal, f.Engine)
	}
	if f.Rule != "AVD-DS-0002" {
		t.Errorf("Expected rule AVD-DS-0002, got %s", f.Rule)
	}
	if f.Severity != orchestrator.SeverityHigh {
		t.Errorf("Expected severity %s, got %s", orchestrator.SeverityHigh, f.Severity)
	}
	if f.File != "Dockerfile" {
		t.Errorf("Expected file Dockerfile, got %s", f.File)
	}
	if !strings.Contains(f.Message, "Root user") {
		t.Errorf("Expected message to contain 'Root user', got %s", f.Message)
	}
}

func TestGitHubActionsWorkflowSecurityRules(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatalf("Failed to create workflow dir: %v", err)
	}

	workflowYAML := `name: CI
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: untrusted/action@main
`
	workflowFile := filepath.Join(workflowDir, "ci.yml")
	if err := os.WriteFile(workflowFile, []byte(workflowYAML), 0644); err != nil {
		t.Fatalf("Failed to write mock workflow: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{filepath.Join(".github", "workflows", "ci.yml")},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}


	foundPRTarget := false
	foundWriteAll := false
	foundUnpinned := false

	for _, f := range findings {
		switch f.Rule {
		case "AVD-GHA-0001":
			foundPRTarget = true
			if f.Severity != orchestrator.SeverityHigh {
				t.Errorf("Expected high severity for pull_request_target, got %s", f.Severity)
			}
		case "AVD-GHA-0002":
			foundUnpinned = true
			if f.Severity != orchestrator.SeverityMedium {
				t.Errorf("Expected medium severity for unpinned action, got %s", f.Severity)
			}
		case "AVD-GHA-0003":
			foundWriteAll = true
			if f.Severity != orchestrator.SeverityHigh {
				t.Errorf("Expected high severity for write-all permissions, got %s", f.Severity)
			}
		}
	}

	if !foundPRTarget {
		t.Errorf("Expected finding AVD-GHA-0001 (pull_request_target) but not found")
	}
	if !foundWriteAll {
		t.Errorf("Expected finding AVD-GHA-0003 (write-all permissions) but not found")
	}
	if !foundUnpinned {
		t.Errorf("Expected finding AVD-GHA-0002 (unpinned action reference) but not found")
	}
}

