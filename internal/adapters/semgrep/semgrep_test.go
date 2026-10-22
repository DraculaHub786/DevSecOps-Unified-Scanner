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

func TestResolveRulesConfig(t *testing.T) {
	t.Run("explicit ruleset passes through", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Scanners.SAST.Ruleset = "p/security-audit"
		got, cleanup, err := resolveRulesConfig(t.TempDir(), cfg)
		if err != nil || got != "p/security-audit" || cleanup != nil {
			t.Fatalf("got %q cleanup=%v err=%v", got, cleanup != nil, err)
		}
	})

	t.Run("bundled rules are used and a repo rules directory is never trusted", func(t *testing.T) {
		repo := t.TempDir()
		hostile := filepath.Join(repo, "rules")
		if err := os.MkdirAll(hostile, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(hostile, "x.yml"), []byte("not: [semgrep"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := config.DefaultConfig()
		cfg.Scanners.SAST.Ruleset = ""
		got, cleanup, err := resolveRulesConfig(repo, cfg)
		if err != nil || cleanup == nil {
			t.Fatalf("err=%v cleanup=%v", err, cleanup != nil)
		}
		if got == hostile || strings.HasPrefix(got, repo) {
			t.Fatalf("used repository rules %q", got)
		}
		if _, err := os.Stat(filepath.Join(got, "sast-rules.yml")); err != nil {
			t.Errorf("bundled sast rules missing: %v", err)
		}
		if _, err := os.Stat(filepath.Join(got, "resilience-rules.yml")); err == nil {
			t.Error("resilience rules must not run in the SAST adapter")
		}
		cleanup()
		if _, err := os.Stat(got); !os.IsNotExist(err) {
			t.Error("cleanup must remove the extracted rules")
		}
	})
}

func TestConfinedPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.yml"), []byte("rules: []"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := confinedPath(root, "ok.yml"); !ok {
		t.Error("file inside the repo must be allowed")
	}
	if _, ok := confinedPath(root, "../../etc/passwd"); ok {
		t.Error("path traversal must be refused")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err == nil {
		_ = os.WriteFile(filepath.Join(outside, "r.yml"), []byte("x"), 0600)
		if _, ok := confinedPath(root, "link/r.yml"); ok {
			t.Error("symlink escaping the repo must be refused")
		}
	}
}

func TestNormalizeRuleID(t *testing.T) {
	if got := normalizeRuleID("tmp.sentinel-rules-3392925030.org-js-command-injection-exec"); got != "org-js-command-injection-exec" {
		t.Fatalf("got %q", got)
	}
	reg := "javascript.express.security.audit.xss.direct-response-write"
	if got := normalizeRuleID(reg); got != reg {
		t.Fatalf("registry id changed: %q", got)
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
