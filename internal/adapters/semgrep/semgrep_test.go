package semgrep

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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

func TestSemgrepStderrNoiseWithValidJSON(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "semgrep.json")
	goldenData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Failed to read golden file: %v", err)
	}

	tmpDir := t.TempDir()
	fakeSrc := filepath.Join(tmpDir, "fake_semgrep.go")
	jsonStr := string(goldenData)

	// Write small helper program that prints warnings to stderr and golden JSON to stdout
	code := `package main
import (
	"fmt"
	"os"
)
func main() {
	fmt.Fprintln(os.Stderr, "WARNING: rule semgrep-rule-001 has been deprecated")
	fmt.Fprintln(os.Stderr, "WARNING: skipping .git directory")
	fmt.Print(` + "`" + jsonStr + "`" + `)
	os.Exit(0)
}
`
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

