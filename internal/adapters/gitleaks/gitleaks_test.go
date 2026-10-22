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

func TestGitleaksCleanRepoZeroFindings(t *testing.T) {
	cfg := config.DefaultConfig()
	// Empty data means clean exit with 0 findings
	findings, err := ParseReport([]byte("[]"), ".", cfg)
	if err != nil {
		t.Fatalf("ParseReport failed on clean report: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings on clean report, got %d", len(findings))
	}
}

func TestRedactSecret(t *testing.T) {
	shortSecret := "abcdef"
	redactedShort := redactSecret(shortSecret)
	if !strings.HasPrefix(redactedShort, "sha256:") {
		t.Errorf("Expected 'sha256:...' for short secret, got %q", redactedShort)
	}

	longSecret := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	redactedLong := redactSecret(longSecret)
	if !strings.HasPrefix(redactedLong, "ghp") {
		t.Errorf("Expected prefix 'ghp', got %q", redactedLong)
	}
	if !strings.HasSuffix(redactedLong, "xyz") {
		t.Errorf("Expected suffix 'xyz', got %q", redactedLong)
	}
	if strings.Contains(redactedLong, "1234567890abcdef") {
		t.Errorf("Secret middle must be redacted, but was exposed: %q", redactedLong)
	}
}

func TestGitleaksDetectsSyntheticFixtureSecrets(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "testdata", "vulnerable-app")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skipf("Fixture directory %s not found: %v", fixturePath, err)
	}

	adapter := New()
	cfg := config.DefaultConfig()
	findings, err := adapter.runNativeFallback(fixturePath, cfg)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range findings {
		if f.Category != orchestrator.CategorySecret {
			t.Errorf("expected CategorySecret, got %s", f.Category)
		}
		foundRules[f.Rule] = true
	}

	requiredRules := []string{
		"aws-access-key-id",
		"aws-secret-access-key",
		"github-pat",
		"slack-token",
		"slack-webhook",
	}

	for _, rule := range requiredRules {
		if !foundRules[rule] {
			t.Errorf("expected synthetic fixture to trigger secret rule %q, but it was not found in %v", rule, foundRules)
		}
	}
}
