package semgrep

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestParseSemgrepGolden(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "semgrep.json")
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file %s: %v", goldenPath, err)
	}

	cfg := config.DefaultConfig()
	findings, err := ParseOutput(data, ".", cfg)
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
	if f.Severity != orchestrator.SeverityHigh {
		t.Errorf("Expected severity %s, got %s", orchestrator.SeverityHigh, f.Severity)
	}
	if f.CWE != "CWE-79" {
		t.Errorf("Expected CWE-79, got %s", f.CWE)
	}
	if f.File != "server.js" {
		t.Errorf("Expected file server.js, got %s", f.File)
	}
	if f.LineStart != 42 {
		t.Errorf("Expected line 42, got %d", f.LineStart)
	}
}

func TestResolveRulesConfig_Table(t *testing.T) {
	tests := []struct {
		name         string
		setupRepo    func(t *testing.T) string
		setupConfig  func() *config.Config
		checkResult  func(t *testing.T, ruleTarget string, cleanup func(), err error)
	}{
		{
			name: "explicit ruleset passthrough",
			setupRepo: func(t *testing.T) string {
				return t.TempDir()
			},
			setupConfig: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Scanners.SAST.Ruleset = "p/security-audit"
				return cfg
			},
			checkResult: func(t *testing.T, ruleTarget string, cleanup func(), err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if ruleTarget != "p/security-audit" {
					t.Errorf("expected 'p/security-audit', got %q", ruleTarget)
				}
				if cleanup != nil {
					t.Errorf("cleanup should be nil for explicit ruleset passthrough")
				}
			},
		},
		{
			name: "local rules/ priority",
			setupRepo: func(t *testing.T) string {
				dir := t.TempDir()
				rulesDir := filepath.Join(dir, "rules")
				if err := os.MkdirAll(rulesDir, 0755); err != nil {
					t.Fatalf("failed to create local rules dir: %v", err)
				}
				return dir
			},
			setupConfig: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Scanners.SAST.Ruleset = ""
				return cfg
			},
			checkResult: func(t *testing.T, ruleTarget string, cleanup func(), err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.HasSuffix(filepath.ToSlash(ruleTarget), "/rules") {
					t.Errorf("expected local rules dir path, got %q", ruleTarget)
				}
				if cleanup != nil {
					t.Errorf("cleanup should be nil for local rules")
				}
			},
		},
		{
			name: "offline extraction of embedded *.yml files with cleanup",
			setupRepo: func(t *testing.T) string {
				return t.TempDir()
			},
			setupConfig: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Offline = true
				cfg.Scanners.SAST.Ruleset = ""
				return cfg
			},
			checkResult: func(t *testing.T, ruleTarget string, cleanup func(), err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if cleanup == nil {
					t.Fatalf("cleanup must not be nil for offline extracted embedded rules")
				}

				// Verify extracted directory exists and contains *.yml files
				fi, statErr := os.Stat(ruleTarget)
				if statErr != nil || !fi.IsDir() {
					t.Fatalf("extracted ruleTarget %q does not exist or is not a directory", ruleTarget)
				}

				entries, readErr := os.ReadDir(ruleTarget)
				if readErr != nil || len(entries) == 0 {
					t.Fatalf("expected embedded rule files in %q, got err=%v, count=%d", ruleTarget, readErr, len(entries))
				}

				foundYML := false
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".yml") {
						foundYML = true
						break
					}
				}
				if !foundYML {
					t.Errorf("expected *.yml files in extracted ruleTarget %q", ruleTarget)
				}

				// Invoke cleanup and verify directory is removed
				cleanup()
				if _, statErr := os.Stat(ruleTarget); !os.IsNotExist(statErr) {
					t.Errorf("expected ruleTarget %q to be deleted after cleanup, stat err: %v", ruleTarget, statErr)
				}
			},
		},
		{
			name: "default auto result",
			setupRepo: func(t *testing.T) string {
				return t.TempDir()
			},
			setupConfig: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Offline = false
				cfg.Scanners.SAST.Ruleset = ""
				return cfg
			},
			checkResult: func(t *testing.T, ruleTarget string, cleanup func(), err error) {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if ruleTarget != "auto" {
					t.Errorf("expected 'auto', got %q", ruleTarget)
				}
				if cleanup != nil {
					t.Errorf("cleanup should be nil for auto")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := tc.setupRepo(t)
			cfg := tc.setupConfig()
			target, cleanup, err := resolveRulesConfig(repo, cfg)
			tc.checkResult(t, target, cleanup, err)
		})
	}
}

func TestSemgrepStderrNoiseWithValidJSON(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "semgrep.json")
	goldenData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file: %v", err)
	}

	tmpDir := t.TempDir()
	goldenDataFile := filepath.Join(tmpDir, "golden.json")
	if err := os.WriteFile(goldenDataFile, goldenData, 0644); err != nil {
		t.Fatalf("Failed to write golden data file: %v", err)
	}

	fakeSrc := filepath.Join(tmpDir, "fake_semgrep.go")
	escapedGoldenFile := filepath.ToSlash(goldenDataFile)

	// Write helper program that prints warnings to stderr and reads golden JSON from file to stdout
	code := fmt.Sprintf(`package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "WARNING: rule semgrep-rule-001 has been deprecated")
	fmt.Fprintln(os.Stderr, "WARNING: skipping .git directory")
	data, err := os.ReadFile("%s")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to read golden file: %%v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(data)
	os.Exit(0)
}
`, escapedGoldenFile)

	if err := os.WriteFile(fakeSrc, []byte(code), 0644); err != nil {
		t.Fatalf("Failed to write fake semgrep source: %v", err)
	}

	fakeBin := filepath.Join(tmpDir, "fake_semgrep.exe")
	buildCmd := exec.Command("go", "build", "-o", fakeBin, fakeSrc)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to compile fake semgrep helper: %v (output: %s)", err, string(out))
	}

	adapter := New()
	cfg := config.DefaultConfig()

	findings, err := adapter.runCLI(context.Background(), fakeBin, tmpDir, cfg)
	if err != nil {
		t.Fatalf("runCLI failed despite valid JSON on stdout: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding from fake semgrep run, got %d", len(findings))
	}

	if findings[0].Engine != orchestrator.EngineExternal {
		t.Errorf("Expected engine %s, got %s", orchestrator.EngineExternal, findings[0].Engine)
	}
}
