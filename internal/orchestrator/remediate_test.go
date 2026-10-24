package orchestrator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type groundTruthBenchmark struct {
	Category string `json:"category"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Rule     string `json:"rule"`
}

func TestPhase5BenchmarkCoverageActionableFixes(t *testing.T) {
	// Acceptance test for Phase 5 Exit Gate:
	// "≥ 70 % of High/Critical findings in the benchmark corpus have an actionable fix (patch or precise manual steps)"
	gtPath := filepath.Join("..", "..", "testdata", "benchmark", "ground_truth.json")
	data, err := os.ReadFile(gtPath)
	if err != nil {
		t.Fatalf("failed to read benchmark ground truth: %v", err)
	}

	var groundTruth []groundTruthBenchmark
	if err := json.Unmarshal(data, &groundTruth); err != nil {
		t.Fatalf("failed to unmarshal ground truth: %v", err)
	}

	if len(groundTruth) == 0 {
		t.Fatalf("expected benchmark ground truth to contain findings")
	}

	repoPath, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "benchmark"))
	actionableCount := 0

	for _, gt := range groundTruth {
		f := Finding{
			ID:        GenerateID("test", gt.Rule, gt.File, gt.Line),
			Category:  gt.Category,
			Rule:      gt.Rule,
			Severity:  SeverityHigh,
			File:      gt.File,
			LineStart: gt.Line,
			LineEnd:   gt.Line,
			Message:   "benchmark flaw: " + gt.Rule,
		}

		fix := GenerateRemediation(repoPath, &f)
		if fix != nil && (fix.Diff != "" || len(fix.Description) > 20) {
			actionableCount++
		} else {
			t.Logf("finding %s:%d (%s) lacking actionable fix", gt.File, gt.Line, gt.Rule)
		}
	}

	ratio := float64(actionableCount) / float64(len(groundTruth))
	t.Logf("Phase 5 Actionable Fix Ratio: %d/%d (%.1f%%)", actionableCount, len(groundTruth), ratio*100)

	if ratio < 0.70 {
		t.Errorf("expected ≥ 70%% of High/Critical findings to have actionable fix, got %.1f%%", ratio*100)
	}
}

func TestApplyFixDeterministicPatches(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Python subprocess shell=True patch
	pyFile := filepath.Join(tmpDir, "app.py")
	pyContent := `import subprocess
def run_cmd(user_input):
    return subprocess.run(f"python {user_input}", shell=True)
`
	if err := os.WriteFile(pyFile, []byte(pyContent), 0644); err != nil {
		t.Fatalf("failed to write test app.py: %v", err)
	}

	pyFinding := Finding{
		ID:        "test-py-1",
		Category:  CategorySAST,
		Rule:      "sast-command-injection",
		File:      "app.py",
		LineStart: 3,
		LineEnd:   3,
		Message:   "Potential command injection using subprocess with shell=True",
	}

	fixPy := GenerateRemediation(tmpDir, &pyFinding)
	if fixPy == nil || fixPy.Diff == "" {
		t.Fatalf("expected non-empty diff for python subprocess shell=True")
	}
	pyFinding.FixSuggestion = fixPy

	appliedDiff, err := ApplyFix(tmpDir, &pyFinding)
	if err != nil {
		t.Fatalf("ApplyFix failed: %v", err)
	}
	if !strings.Contains(appliedDiff, "shell=False") {
		t.Errorf("expected applied diff to substitute shell=False, got: %s", appliedDiff)
	}

	patchedBytes, _ := os.ReadFile(pyFile)
	if strings.Contains(string(patchedBytes), "shell=True") {
		t.Errorf("expected shell=True to be removed from app.py")
	}
	if !strings.Contains(string(patchedBytes), "shell=False") {
		t.Errorf("expected shell=False to be present in app.py")
	}

	// 2. Dockerfile USER patch
	dockerFile := filepath.Join(tmpDir, "Dockerfile")
	dockerContent := `FROM node:20-alpine
WORKDIR /app
CMD ["node", "server.js"]
`
	if err := os.WriteFile(dockerFile, []byte(dockerContent), 0644); err != nil {
		t.Fatalf("failed to write test Dockerfile: %v", err)
	}

	dockerFinding := Finding{
		ID:        "test-docker-1",
		Category:  CategoryIaC,
		Rule:      "AVD-DS-0002",
		File:      "Dockerfile",
		LineStart: 3,
		LineEnd:   3,
		Message:   "Specify at least 1 USER command in Dockerfile with non-root UID",
	}

	fixDocker := GenerateRemediation(tmpDir, &dockerFinding)
	if fixDocker == nil || fixDocker.Diff == "" {
		t.Fatalf("expected non-empty diff for Dockerfile missing USER")
	}
	dockerFinding.FixSuggestion = fixDocker

	_, err = ApplyFix(tmpDir, &dockerFinding)
	if err != nil {
		t.Fatalf("ApplyFix for Dockerfile failed: %v", err)
	}

	patchedDockerBytes, _ := os.ReadFile(dockerFile)
	if !strings.Contains(string(patchedDockerBytes), "USER 10001:10001") {
		t.Errorf("expected USER 10001:10001 to be added to Dockerfile, got:\n%s", string(patchedDockerBytes))
	}
}
