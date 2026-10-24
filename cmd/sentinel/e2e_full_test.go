package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/gitleaks"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/govulncheck"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/nuclei"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/osv"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/resilience"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/semgrep"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters/trivy"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/testdata/dast"
)

type expectedFinding struct {
	Rule     string `json:"rule"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

func (e expectedFinding) Key() string {
	return fmt.Sprintf("%s|%s|%d|%s", e.Category, filepath.ToSlash(e.File), e.Line, e.Rule)
}

func findingKey(f orchestrator.Finding) string {
	return fmt.Sprintf("%s|%s|%d|%s", f.Category, filepath.ToSlash(f.File), f.LineStart, f.Rule)
}

func newTestScheduler() *orchestrator.Scheduler {
	return orchestrator.NewScheduler(
		gitleaks.New(),
		osv.New(),
		semgrep.New(),
		trivy.New(),
		nuclei.NewWithAuth(true),
		resilience.New(),
		govulncheck.New(),
	)
}

func TestE2EExpectedFindingsVulnerableApp(t *testing.T) {
	rootDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to resolve root dir: %v", err)
	}

	expectedPath := filepath.Join(rootDir, "testdata", "expected", "vulnerable-app.json")
	expectedBytes, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read expected findings file %s: %v", expectedPath, err)
	}

	var expectedList []expectedFinding
	if err := json.Unmarshal(expectedBytes, &expectedList); err != nil {
		t.Fatalf("failed to unmarshal expected findings: %v", err)
	}

	expectedMap := make(map[string]expectedFinding)
	for _, ef := range expectedList {
		expectedMap[ef.Key()] = ef
	}

	vulnerableAppPath := filepath.Join(rootDir, "testdata", "vulnerable-app")
	cfg := config.DefaultConfig()
	cfg.Offline = true

	scheduler := newTestScheduler()
	opts := orchestrator.ScanOptions{
		RepoPath: vulnerableAppPath,
		Timeout:  60 * time.Second,
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("scan on vulnerable-app failed: %v", err)
	}

	actualMap := make(map[string]orchestrator.Finding)
	for _, f := range result.Findings {
		actualMap[findingKey(f)] = f
	}

	// 1. Assert all expected findings are present
	var missing []string
	for k, ef := range expectedMap {
		if _, found := actualMap[k]; !found {
			missing = append(missing, fmt.Sprintf("Missing [%s] %s:%d (%s - %s)", ef.Category, ef.File, ef.Line, ef.Rule, ef.Severity))
		}
	}

	// 2. Assert no unexpected findings are present
	var unexpected []string
	for k, f := range actualMap {
		if _, found := expectedMap[k]; !found {
			unexpected = append(unexpected, fmt.Sprintf("Unexpected [%s] %s:%d (%s - %s)", f.Category, f.File, f.LineStart, f.Rule, f.Severity))
		}
	}

	if len(missing) > 0 || len(unexpected) > 0 {
		for _, m := range missing {
			t.Errorf("  • %s", m)
		}
		for _, u := range unexpected {
			t.Errorf("  • %s", u)
		}
		t.Fatalf("e2e vulnerable-app mismatch: %d missing, %d unexpected findings out of %d expected",
			len(missing), len(unexpected), len(expectedList))
	}

	t.Logf("✅ e2e vulnerable-app matched all %d expected findings perfectly", len(expectedList))
}

func TestE2ESafeAppZeroFindings(t *testing.T) {
	rootDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to resolve root dir: %v", err)
	}

	safeAppPath := filepath.Join(rootDir, "testdata", "safe-app")
	cfg := config.DefaultConfig()
	cfg.Offline = true

	scheduler := newTestScheduler()
	opts := orchestrator.ScanOptions{
		RepoPath: safeAppPath,
		Timeout:  30 * time.Second,
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("scan on safe-app failed: %v", err)
	}

	if len(result.Findings) != 0 {
		for _, f := range result.Findings {
			t.Errorf("Unexpected finding in safe-app: [%s] %s:%d (%s - %s): %s",
				f.Category, f.File, f.LineStart, f.Rule, f.Severity, f.Message)
		}
		t.Fatalf("Expected safe-app to have 0 findings, but got %d", len(result.Findings))
	}

	t.Logf("✅ e2e safe-app clean scan verified: 0 findings reported")
}

func TestE2EDASTPassiveTargetServer(t *testing.T) {
	server := dast.NewVulnerableDASTServer()
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Scanners.DAST.Enabled = true
	cfg.Scanners.DAST.Target = server.URL
	cfg.Scanners.DAST.Allowlist = []string{"127.0.0.1", "localhost"}
	cfg.Scanners.DAST.AllowPrivate = true

	adapter := nuclei.NewWithAuth(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := adapter.Run(ctx, ".", cfg, &orchestrator.DiscoveryResult{TargetURL: server.URL})
	if err != nil {
		t.Fatalf("DAST run failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected DAST passive scan on vulnerable server to identify findings, got 0")
	}

	t.Logf("✅ DAST passive scan identified %d findings on vulnerable server", len(findings))
	hasHeaderCheck := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Rule), "header") || strings.Contains(strings.ToLower(f.Message), "header") {
			hasHeaderCheck = true
			break
		}
	}
	if !hasHeaderCheck {
		t.Logf("Note: DAST findings returned: %+v", findings)
	}
}
