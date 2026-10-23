package govulncheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestParseGovulncheckGolden(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "testdata", "golden", "govulncheck.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read govulncheck golden fixture: %v", err)
	}

	cfg := config.DefaultConfig()
	findings, err := ParseGovulncheckOutput(data, ".", cfg)
	if err != nil {
		t.Fatalf("ParseGovulncheckOutput failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(findings))
	}

	var reachableFinding, unreachableFinding *orchestrator.Finding
	for i := range findings {
		f := &findings[i]
		if f.CVE == "CVE-2023-24538" {
			reachableFinding = f
		} else if f.CVE == "CVE-2022-27191" {
			unreachableFinding = f
		}
	}

	if reachableFinding == nil {
		t.Fatalf("Expected finding for CVE-2023-24538 not found")
	}
	if unreachableFinding == nil {
		t.Fatalf("Expected finding for CVE-2022-27191 not found")
	}

	// 1. Verify reachable finding properties
	if reachableFinding.Reachable == nil || !*reachableFinding.Reachable {
		t.Errorf("Expected CVE-2023-24538 to be reachable (Reachable=true), got %v", reachableFinding.Reachable)
	}
	if !strings.Contains(reachableFinding.Snippet, "main.main") || !strings.Contains(reachableFinding.Snippet, "Parse") {
		t.Errorf("Expected call stack snippet to contain main.main and Parse, got: %s", reachableFinding.Snippet)
	}
	if !strings.Contains(reachableFinding.Message, "[Reachability: proven (govulncheck)]") {
		t.Errorf("Expected message to indicate proven reachability, got: %s", reachableFinding.Message)
	}

	// 2. Verify unreachable finding properties
	if unreachableFinding.Reachable == nil || *unreachableFinding.Reachable {
		t.Errorf("Expected CVE-2022-27191 to be unreachable (Reachable=false), got %v", unreachableFinding.Reachable)
	}
	if !strings.Contains(unreachableFinding.Message, "[Reachability: unreachable (govulncheck)]") {
		t.Errorf("Expected message to indicate unreachable, got: %s", unreachableFinding.Message)
	}

	// 3. Verify risk score elevation (reachable has 1.35x multiplier, unreachable has 0.65x multiplier)
	if reachableFinding.RiskScore <= unreachableFinding.RiskScore {
		t.Errorf("Expected reachable finding score (%.1f) > unreachable finding score (%.1f)",
			reachableFinding.RiskScore, unreachableFinding.RiskScore)
	}
}

func TestGovulncheckIsApplicable(t *testing.T) {
	adapter := New()

	goDiscovery := &orchestrator.DiscoveryResult{
		Languages: []string{"go"},
		Manifests: []string{"go.mod"},
	}
	if !adapter.IsApplicable(goDiscovery) {
		t.Errorf("Expected IsApplicable=true for Go repository")
	}

	nodeDiscovery := &orchestrator.DiscoveryResult{
		Languages: []string{"javascript"},
		Manifests: []string{"package.json"},
	}
	if adapter.IsApplicable(nodeDiscovery) {
		t.Errorf("Expected IsApplicable=false for Node.js repository")
	}
}

func TestGovulncheckReturnsErrSkippedWhenNoGoMod(t *testing.T) {
	adapter := New()
	emptyDir := t.TempDir()
	cfg := config.DefaultConfig()

	_, err := adapter.Run(context.Background(), emptyDir, cfg, nil)
	if err == nil {
		t.Fatal("Expected Run to return error on empty directory, got nil")
	}
	if !strings.Contains(err.Error(), "scanner skipped") {
		t.Errorf("Expected ErrSkipped, got: %v", err)
	}
}
