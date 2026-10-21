package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigLoadDefault(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-cfg-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load on empty dir should return default config, got err: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("Expected version 1, got %d", cfg.Version)
	}
	if cfg.Thresholds.FailOn != "high" {
		t.Errorf("Expected fail_on 'high', got %q", cfg.Thresholds.FailOn)
	}
}

func TestConfigLoadValid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-cfg-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	yamlData := `
version: 1
thresholds:
  fail_on: high
  risk_score_max: 75
scanners:
  dast:
    enabled: true
    allowlist:
      - staging.internal.corp
    allow_private: false
ignore:
  paths:
    - "node_modules/**"
    - "testdata/**"
  findings:
    - id: "FINDING-123"
      reason: "Verified false positive by security team"
      expires: "2099-01-01"
    - id: "FINDING-EXPIRED"
      reason: "Old exemption"
      expires: "2020-01-01"
`
	if err := os.WriteFile(filepath.Join(tmpDir, ".sentinel.yml"), []byte(yamlData), 0644); err != nil {
		t.Fatalf("Failed to write .sentinel.yml: %v", err)
	}

	cfg, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Thresholds.FailOn != "high" {
		t.Errorf("Expected fail_on 'high', got %s", cfg.Thresholds.FailOn)
	}

	// Test ignore paths
	if !cfg.ShouldIgnorePath("node_modules/express/index.js") {
		t.Errorf("Expected node_modules/express/index.js to be ignored")
	}
	if cfg.ShouldIgnorePath("src/index.js") {
		t.Errorf("Expected src/index.js not to be ignored")
	}

	// Test ignore findings
	if !cfg.ShouldIgnoreFinding("FINDING-123") {
		t.Errorf("Expected FINDING-123 to be ignored (unexpired)")
	}
	if cfg.ShouldIgnoreFinding("FINDING-EXPIRED") {
		t.Errorf("Expected FINDING-EXPIRED not to be ignored (expired in 2020)")
	}
	if cfg.ShouldIgnoreFinding("NON-EXISTENT") {
		t.Errorf("Expected NON-EXISTENT finding not to be ignored")
	}
}

func TestConfigLoadUnknownFieldsFail(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-cfg-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	yamlData := `
version: 1
unknown_key_typo: "something"
`
	if err := os.WriteFile(filepath.Join(tmpDir, ".sentinel.yml"), []byte(yamlData), 0644); err != nil {
		t.Fatalf("Failed to write .sentinel.yml: %v", err)
	}

	_, err = Load(tmpDir)
	if err == nil {
		t.Fatalf("Expected error for unknown field in .sentinel.yml, got nil")
	}
	if !strings.Contains(err.Error(), "field unknown_key_typo not found") && !strings.Contains(err.Error(), "unknown") {
		t.Errorf("Error should mention unknown field, got: %v", err)
	}
}

func TestConfigLoadMissingSuppressionReasonFail(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sentinel-cfg-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	yamlData := `
version: 1
ignore:
  findings:
    - id: "FINDING-NO-REASON"
`
	if err := os.WriteFile(filepath.Join(tmpDir, ".sentinel.yml"), []byte(yamlData), 0644); err != nil {
		t.Fatalf("Failed to write .sentinel.yml: %v", err)
	}

	_, err = Load(tmpDir)
	if err == nil {
		t.Fatalf("Expected error when suppression has no reason, got nil")
	}
	if !strings.Contains(err.Error(), "requires a justification reason") {
		t.Errorf("Expected justification reason error, got: %v", err)
	}
}

func TestConfigLoadInvalidThresholds(t *testing.T) {
	// Test invalid fail_on
	tmpDir1 := t.TempDir()
	yaml1 := `
version: 1
thresholds:
  fail_on: "ultra-critical"
`
	if err := os.WriteFile(filepath.Join(tmpDir1, ".sentinel.yml"), []byte(yaml1), 0644); err != nil {
		t.Fatalf("Failed to write .sentinel.yml: %v", err)
	}
	_, err := Load(tmpDir1)
	if err == nil || !strings.Contains(err.Error(), "invalid thresholds.fail_on") {
		t.Errorf("Expected error for invalid fail_on threshold, got: %v", err)
	}

	// Test invalid risk_score_max
	tmpDir2 := t.TempDir()
	yaml2 := `
version: 1
thresholds:
  risk_score_max: 150.0
`
	if err := os.WriteFile(filepath.Join(tmpDir2, ".sentinel.yml"), []byte(yaml2), 0644); err != nil {
		t.Fatalf("Failed to write .sentinel.yml: %v", err)
	}
	_, err = Load(tmpDir2)
	if err == nil || !strings.Contains(err.Error(), "invalid thresholds.risk_score_max") {
		t.Errorf("Expected error for out-of-range risk_score_max, got: %v", err)
	}
}

