package osv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestParseOSVGolden(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "osv.json")
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
	if f.CVE != "CVE-2021-23337" {
		t.Errorf("Expected CVE-2021-23337, got %s", f.CVE)
	}
	if f.File != "package-lock.json" {
		t.Errorf("Expected package-lock.json, got %s", f.File)
	}
	if !strings.Contains(f.Message, "[Reachability: imported]") {
		t.Errorf("Expected message to carry reachability label, got %s", f.Message)
	}
}

func TestFailOnLicense(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()
	cfg.Scanners.SCA.FailOnLicense = []string{"MIT"}

	tmpDir := t.TempDir()
	pkgJSON := `{
  "dependencies": {
    "lodash": "4.17.15"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("Failed to write mock package.json: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		Manifests: []string{"package.json"},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundLicViolation := false
	for _, f := range findings {
		if strings.HasPrefix(f.Rule, "license/") {
			foundLicViolation = true
			if f.License != "MIT" {
				t.Errorf("Expected license MIT, got %s", f.License)
			}
			if f.Severity != orchestrator.SeverityHigh {
				t.Errorf("Expected severity high for license violation, got %s", f.Severity)
			}
		}
	}

	if !foundLicViolation {
		t.Errorf("Expected a license violation finding for disallowed license MIT, but none was found")
	}
}

func TestSupplyChainChecks(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	tmpDir := t.TempDir()
	pkgJSON := `{
  "dependencies": {
    "lodashs": "4.17.21",
    "express": "*"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("Failed to write mock package.json: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		Manifests: []string{"package.json"},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundTyposquat := false
	foundUnpinned := false

	for _, f := range findings {
		if f.Rule == "SUPPLY-CHAIN-TYPOSQUAT" {
			foundTyposquat = true
			if f.Severity != orchestrator.SeverityHigh {
				t.Errorf("Expected high severity for typosquatting, got %s", f.Severity)
			}
		}
		if f.Rule == "SUPPLY-CHAIN-UNPINNED" {
			foundUnpinned = true
			if f.Severity != orchestrator.SeverityMedium {
				t.Errorf("Expected medium severity for unpinned dependency, got %s", f.Severity)
			}
		}
	}

	if !foundTyposquat {
		t.Errorf("Expected SUPPLY-CHAIN-TYPOSQUAT finding for 'lodashs', but none found")
	}
	if !foundUnpinned {
		t.Errorf("Expected SUPPLY-CHAIN-UNPINNED finding for 'express: *', but none found")
	}
}

func TestReachabilityHeuristic(t *testing.T) {
	adapter := New()
	tmpDir := t.TempDir()

	// JS file with require('lodash')
	jsCode := `const _ = require('lodash'); console.log(_.chunk([1, 2, 3], 2));`
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("Failed to write app.js: %v", err)
	}

	if !adapter.checkReachability("lodash", tmpDir) {
		t.Errorf("Expected lodash to be reachable when required in app.js")
	}
	if adapter.checkReachability("axios", tmpDir) {
		t.Errorf("Expected axios to not be reachable when never imported")
	}

	// Python file with import requests
	pyCode := `import requests\nres = requests.get('https://example.com')`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.py"), []byte(pyCode), 0644); err != nil {
		t.Fatalf("Failed to write main.py: %v", err)
	}
	if !adapter.checkReachability("requests", tmpDir) {
		t.Errorf("Expected requests to be reachable when imported in main.py")
	}
	if adapter.checkReachability("urllib3", tmpDir) {
		t.Errorf("Expected urllib3 to not be reachable when never imported")
	}
}

func TestNoLockfileSkipped(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	// Run with no lockfiles and no manifests
	discovery := &orchestrator.DiscoveryResult{}
	_, err := adapter.runNativeFallback(t.TempDir(), cfg, discovery)
	if err == nil {
		t.Fatal("Expected runNativeFallback to return ErrSkipped when no lockfiles exist")
	}
	if !errors.Is(err, orchestrator.ErrSkipped) {
		t.Errorf("Expected error to wrap orchestrator.ErrSkipped, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no lockfile found") {
		t.Errorf("Expected error to mention 'no lockfile found', got: %v", err)
	}
}

func TestOSVOfflineDegrade(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()
	cfg.Offline = true

	tmpDir := t.TempDir()
	pkgJSON := `{
  "dependencies": {
    "lodash": "4.17.15"
  }
}`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("Failed to write mock package.json: %v", err)
	}
	discovery := &orchestrator.DiscoveryResult{Manifests: []string{"package.json"}}

	findings, err := adapter.Run(context.Background(), tmpDir, cfg, discovery)
	if !errors.Is(err, orchestrator.ErrDegraded) {
		t.Fatalf("Expected Run to return ErrDegraded in offline mode, got: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Expected findings from embedded advisory list in degraded mode")
	}
}
