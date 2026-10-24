package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesTestOutputWhenSemgrepMissing(t *testing.T) {
	root := newTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"rules", "test"})

	err := root.Execute()
	if err != nil {
		t.Fatalf("rules test unexpected error: %v (output: %s)", err, buf.String())
	}

	out := buf.String()
	// When semgrep is missing, must print SKIPPED and never claim 100% full verification
	if findSemgrepExecutable() == "" {
		if !strings.Contains(out, "SKIPPED (semgrep not installed)") {
			t.Errorf("Expected output to report SKIPPED (semgrep not installed), got:\n%s", out)
		}
		if strings.Contains(out, "✅ All 66 rules passed metadata, parse, and behavioral verification (100%)") {
			t.Errorf("Rules test claimed full 100%% behavioral pass when semgrep was not installed:\n%s", out)
		}
	}
}

func TestRulesTestFailsOnBrokenRule(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a deliberately broken rule file with missing metadata and invalid severity
	brokenYAML := `
rules:
  - id: broken-test-rule
    pattern: "eval($X)"
    message: ""
    severity: CRITICAL_INVALID
    languages: []
    metadata:
      cwe: ""
`
	if err := os.WriteFile(filepath.Join(tmpDir, "broken-rule.yml"), []byte(brokenYAML), 0644); err != nil {
		t.Fatalf("failed to write broken rule: %v", err)
	}

	root := newTestRootCmd()
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"rules", "test", tmpDir})

	err := root.Execute()
	if err == nil {
		t.Fatalf("Expected rules test to fail on broken rule, but it succeeded! Output:\n%s", buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "FAIL broken-test-rule") {
		t.Errorf("Expected output to contain failure for broken-test-rule, got:\n%s", out)
	}
}
