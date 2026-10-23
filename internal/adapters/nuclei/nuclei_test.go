package nuclei

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/testdata/dast"
)

func TestParseNucleiGolden(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "nuclei.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file %s: %v", goldenPath, err)
	}

	cfg := config.DefaultConfig()
	findings, err := ParseOutput(data, "https://example.com", cfg)
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
	if f.Rule != "git-config-disclosure" {
		t.Errorf("Expected rule git-config-disclosure, got %s", f.Rule)
	}
	if f.Severity != "medium" {
		t.Errorf("Expected severity medium, got %s", f.Severity)
	}
	if f.File != "https://example.com" {
		t.Errorf("Expected file https://example.com, got %s", f.File)
	}
	if !strings.Contains(f.Message, ".git/config exposed") {
		t.Errorf("Expected message to contain '.git/config exposed', got %s", f.Message)
	}
}

func TestNucleiIsApplicable(t *testing.T) {
	adapter := New()

	// 1. Nil discovery -> false
	if adapter.IsApplicable(nil) {
		t.Errorf("Expected IsApplicable(nil) to be false")
	}

	// 2. Empty target -> false
	discoveryNoTarget := &orchestrator.DiscoveryResult{
		RepoPath:  ".",
		TargetURL: "",
	}
	if adapter.IsApplicable(discoveryNoTarget) {
		t.Errorf("Expected IsApplicable to be false when TargetURL is empty")
	}

	// 3. Valid target -> true
	discoveryWithTarget := &orchestrator.DiscoveryResult{
		RepoPath:  ".",
		TargetURL: "https://example.com",
	}
	if !adapter.IsApplicable(discoveryWithTarget) {
		t.Errorf("Expected IsApplicable to be true when TargetURL is set")
	}
}

func TestNucleiPassiveChecksAgainstVulnerableDASTTarget(t *testing.T) {
	server := dast.NewVulnerableDASTServer()
	defer server.Close()

	adapter := NewWithAuth(true)
	cfg := config.DefaultConfig()
	cfg.Scanners.DAST.Enabled = true
	cfg.Scanners.DAST.Target = server.URL
	cfg.Scanners.DAST.AllowPrivate = true // Localhost testing allowed in test suite
	cfg.Engine = "embedded"

	findings, err := adapter.runPassiveNativeChecks(context.Background(), server.URL, cfg)
	if err != nil {
		t.Fatalf("runPassiveNativeChecks failed: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range findings {
		foundRules[f.Rule] = true
	}

	expectedRules := []string{
		"missing-csp-header",
		"missing-x-frame-options",
		"missing-x-content-type-options",
		"cors-wildcard-origin",
		"sensitive-env-endpoint-exposed",
	}

	for _, rule := range expectedRules {
		if !foundRules[rule] {
			t.Errorf("Expected rule %q to be detected on vulnerable DAST target, got findings: %v", rule, findings)
		}
	}
}
