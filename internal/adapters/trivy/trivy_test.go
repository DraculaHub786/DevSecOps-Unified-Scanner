package trivy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestParseTrivyGolden(t *testing.T) {
	goldenPath := filepath.Join("..", "..", "..", "testdata", "golden", "trivy.json")
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
	if f.Rule != "AVD-DS-0002" {
		t.Errorf("Expected rule AVD-DS-0002, got %s", f.Rule)
	}
	if f.Severity != orchestrator.SeverityHigh {
		t.Errorf("Expected severity %s, got %s", orchestrator.SeverityHigh, f.Severity)
	}
	if f.File != "Dockerfile" {
		t.Errorf("Expected file Dockerfile, got %s", f.File)
	}
	if !strings.Contains(f.Message, "Root user") {
		t.Errorf("Expected message to contain 'Root user', got %s", f.Message)
	}
}

func TestGitHubActionsWorkflowSecurityRules(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	tmpDir := t.TempDir()
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		t.Fatalf("Failed to create workflow dir: %v", err)
	}

	workflowYAML := `name: CI
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: untrusted/action@main
      - name: Greet
        run: echo "Issue title ${{ github.event.issue.title }}"
`
	workflowFile := filepath.Join(workflowDir, "ci.yml")
	if err := os.WriteFile(workflowFile, []byte(workflowYAML), 0644); err != nil {
		t.Fatalf("Failed to write mock workflow: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{filepath.Join(".github", "workflows", "ci.yml")},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundPRTarget := false
	foundWriteAll := false
	foundUnpinned := false
	foundInjection := false

	for _, f := range findings {
		switch f.Rule {
		case "AVD-GHA-0001":
			foundPRTarget = true
			if f.Severity != orchestrator.SeverityHigh {
				t.Errorf("Expected high severity for pull_request_target, got %s", f.Severity)
			}
		case "AVD-GHA-0002":
			foundUnpinned = true
			if f.Severity != orchestrator.SeverityMedium {
				t.Errorf("Expected medium severity for unpinned action, got %s", f.Severity)
			}
		case "AVD-GHA-0003":
			foundWriteAll = true
			if f.Severity != orchestrator.SeverityHigh {
				t.Errorf("Expected high severity for write-all permissions, got %s", f.Severity)
			}
		case "AVD-GHA-0004":
			foundInjection = true
			if f.Severity != orchestrator.SeverityCritical {
				t.Errorf("Expected critical severity for expression injection, got %s", f.Severity)
			}
		}
	}

	if !foundPRTarget {
		t.Errorf("Expected finding AVD-GHA-0001 (pull_request_target) but not found")
	}
	if !foundWriteAll {
		t.Errorf("Expected finding AVD-GHA-0003 (write-all permissions) but not found")
	}
	if !foundUnpinned {
		t.Errorf("Expected finding AVD-GHA-0002 (unpinned action reference) but not found")
	}
	if !foundInjection {
		t.Errorf("Expected finding AVD-GHA-0004 (expression injection) but not found")
	}

	// Verify safe fixture produces zero findings
	safeFixturePath := filepath.Join("..", "..", "..", "testdata", "gha", "safe-workflow.yml")
	safeData, err := os.ReadFile(safeFixturePath)
	if err == nil {
		safeDir := t.TempDir()
		safeWorkflows := filepath.Join(safeDir, ".github", "workflows")
		_ = os.MkdirAll(safeWorkflows, 0755)
		_ = os.WriteFile(filepath.Join(safeWorkflows, "safe.yml"), safeData, 0644)
		safeDiscovery := &orchestrator.DiscoveryResult{
			IaCFiles: []string{filepath.Join(".github", "workflows", "safe.yml")},
		}
		safeFindings, err := adapter.runNativeFallback(safeDir, cfg, safeDiscovery)
		if err != nil {
			t.Fatalf("runNativeFallback on safe fixture failed: %v", err)
		}
		if len(safeFindings) != 0 {
			t.Errorf("Expected 0 findings on safe workflow fixture, got %d: %v", len(safeFindings), safeFindings)
		}
	}
}

func TestTrivyDetectsFixtureIaCVulnerabilities(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "testdata", "vulnerable-app")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skipf("Fixture directory %s not found: %v", fixturePath, err)
	}

	adapter := New()
	cfg := config.DefaultConfig()
	discovery, err := orchestrator.Discover(fixturePath)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	findings, err := adapter.runNativeFallback(fixturePath, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range findings {
		if f.Category != orchestrator.CategoryIaC {
			t.Errorf("expected CategoryIaC, got %s", f.Category)
		}
		foundRules[f.Rule] = true
	}

	// In testdata/vulnerable-app: Dockerfile (AVD-DS-0001, AVD-DS-0002), main.tf (AVD-AWS-0107)
	expectedRules := []string{"AVD-DS-0001", "AVD-DS-0002", "AVD-AWS-0107"}
	for _, r := range expectedRules {
		if !foundRules[r] {
			t.Errorf("expected finding %s in fixture scan, but got rules: %v", r, foundRules)
		}
	}
}

func TestTrivyIsVulnDBUnavailableDetection(t *testing.T) {
	cases := []struct {
		stderr string
		stdout string
		want   bool
	}{
		{"FATAL --offline-scan cannot be used without database", "", true},
		{"failed to download vulnerability DB: connection refused", "", true},
		{"error: database download error", "", true},
		{"dial tcp 1.2.3.4:443: i/o timeout", "", true},
		{"dial tcp: lookup ghcr.io: no such host", "", true},
		{"context deadline exceeded", "", true},
		{"failed to open db: no such file or directory", "", true},
		{"unrecognized flag --bogus", "", false},
		{"syntax error on line 42", "", false},
		{"segmentation fault", "", false},
	}

	for _, c := range cases {
		got := isVulnDBUnavailable(c.stderr, c.stdout)
		if got != c.want {
			t.Errorf("isVulnDBUnavailable(%q, %q) = %v; want %v", c.stderr, c.stdout, got, c.want)
		}
	}
}

func TestTrivyParseOutputWithSecrets(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	mockJSON := `{
		"Results": [
			{
				"Target": "config/secrets.env",
				"Class": "secret",
				"Secrets": [
					{
						"RuleID": "generic-api-key",
						"Category": "secret",
						"Severity": "CRITICAL",
						"Title": "AWS API Key",
						"StartLine": 5,
						"EndLine": 5,
						"Match": "AKIAIOSFODNN7EXAMPLE"
					}
				]
			}
		]
	}`

	findings, err := adapter.ParseOutput([]byte(mockJSON), ".", cfg)
	if err != nil {
		t.Fatalf("ParseOutput failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 secret finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Category != orchestrator.CategorySecret {
		t.Errorf("Expected category %s, got %s", orchestrator.CategorySecret, f.Category)
	}
	if f.Severity != orchestrator.SeverityCritical {
		t.Errorf("Expected severity %s, got %s", orchestrator.SeverityCritical, f.Severity)
	}
	if f.Rule != "generic-api-key" {
		t.Errorf("Expected rule generic-api-key, got %s", f.Rule)
	}
	if f.CWE != "CWE-798" {
		t.Errorf("Expected CWE-798, got %s", f.CWE)
	}
	if f.Snippet == "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Expected secret snippet to be redacted, got %s", f.Snippet)
	}
}

func TestTrivyNativeFallbackReturnsErrSkippedOnEmptyIaC(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()
	emptyDir := t.TempDir()

	discovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{},
	}

	_, err := adapter.runNativeFallback(emptyDir, cfg, discovery)
	if err == nil {
		t.Fatal("Expected runNativeFallback to return error when no IaC files exist, got nil")
	}

	if !strings.Contains(err.Error(), "scanner skipped") {
		t.Errorf("Expected ErrSkipped error, got: %v", err)
	}
}

func TestTrivySupplyChainSecurityRules(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	// Positive test on vulnerable Dockerfile fixture
	vulnFixturePath := filepath.Join("..", "..", "..", "testdata", "supplychain", "vulnerable", "Dockerfile")
	vulnData, err := os.ReadFile(vulnFixturePath)
	if err != nil {
		t.Fatalf("Failed to read vulnerable Dockerfile fixture: %v", err)
	}

	vulnDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(vulnDir, "Dockerfile"), vulnData, 0644)
	vulnDiscovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{"Dockerfile"},
	}

	vulnFindings, err := adapter.runNativeFallback(vulnDir, cfg, vulnDiscovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed on vulnerable fixture: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range vulnFindings {
		foundRules[f.Rule] = true
	}

	if !foundRules["AVD-DS-0001"] {
		t.Errorf("Expected AVD-DS-0001 (:latest tag) on vulnerable fixture, got: %v", vulnFindings)
	}
	if !foundRules["AVD-DS-0002"] {
		t.Errorf("Expected AVD-DS-0002 (root user) on vulnerable fixture, got: %v", vulnFindings)
	}
	if !foundRules["AVD-DS-0003"] {
		t.Errorf("Expected AVD-DS-0003 (curl | sh) on vulnerable fixture, got: %v", vulnFindings)
	}

	// Negative test on safe Dockerfile fixture
	safeFixturePath := filepath.Join("..", "..", "..", "testdata", "supplychain", "safe", "Dockerfile")
	safeData, err := os.ReadFile(safeFixturePath)
	if err != nil {
		t.Fatalf("Failed to read safe Dockerfile fixture: %v", err)
	}

	safeDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(safeDir, "Dockerfile"), safeData, 0644)
	safeDiscovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{"Dockerfile"},
	}

	safeFindings, err := adapter.runNativeFallback(safeDir, cfg, safeDiscovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed on safe fixture: %v", err)
	}

	if len(safeFindings) != 0 {
		t.Errorf("Expected 0 findings on safe fixture, got %d: %v", len(safeFindings), safeFindings)
	}
}

func TestTrivyDetectsKubernetesAndHelmFixtures(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	k8sFixture := filepath.Join("..", "..", "..", "testdata", "iac", "k8s-pod.yaml")
	helmFixture := filepath.Join("..", "..", "..", "testdata", "iac", "helm", "templates", "deployment.yaml")

	k8sData, err := os.ReadFile(k8sFixture)
	if err != nil {
		t.Fatalf("Failed to read k8s fixture %s: %v", k8sFixture, err)
	}
	helmData, err := os.ReadFile(helmFixture)
	if err != nil {
		t.Fatalf("Failed to read helm fixture %s: %v", helmFixture, err)
	}

	tmpDir := t.TempDir()
	helmDir := filepath.Join(tmpDir, "templates")
	if err := os.MkdirAll(helmDir, 0755); err != nil {
		t.Fatalf("Failed to create helm dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "k8s-pod.yaml"), k8sData, 0644); err != nil {
		t.Fatalf("Failed to write k8s-pod.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(helmDir, "deployment.yaml"), helmData, 0644); err != nil {
		t.Fatalf("Failed to write deployment.yaml: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{
			"k8s-pod.yaml",
			filepath.Join("templates", "deployment.yaml"),
		},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range findings {
		foundRules[f.Rule] = true
	}

	expectedRules := []string{"AVD-KSV-0017", "AVD-KSV-0014", "AVD-KSV-0005", "AVD-KSV-0015"}
	for _, r := range expectedRules {
		if !foundRules[r] {
			t.Errorf("Expected Kubernetes rule %s to be detected, found rules: %v", r, foundRules)
		}
	}
}

func TestTrivyDetectsDockerComposeFixtures(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	composeFixture := filepath.Join("..", "..", "..", "testdata", "iac", "docker-compose.yml")
	composeData, err := os.ReadFile(composeFixture)
	if err != nil {
		t.Fatalf("Failed to read docker-compose fixture %s: %v", composeFixture, err)
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "docker-compose.yml"), composeData, 0644); err != nil {
		t.Fatalf("Failed to write docker-compose.yml: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{"docker-compose.yml"},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range findings {
		foundRules[f.Rule] = true
	}

	expectedRules := []string{"AVD-DCP-0001", "AVD-DCP-0002", "AVD-DCP-0003", "AVD-DCP-0004"}
	for _, r := range expectedRules {
		if !foundRules[r] {
			t.Errorf("Expected Docker Compose rule %s to be detected, found rules: %v", r, foundRules)
		}
	}
}

func TestTrivyDetectsTerraformS3Fixtures(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()

	tfFixture := filepath.Join("..", "..", "..", "testdata", "iac", "terraform", "s3.tf")
	tfData, err := os.ReadFile(tfFixture)
	if err != nil {
		t.Fatalf("Failed to read terraform s3 fixture %s: %v", tfFixture, err)
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "s3.tf"), tfData, 0644); err != nil {
		t.Fatalf("Failed to write s3.tf: %v", err)
	}

	discovery := &orchestrator.DiscoveryResult{
		IaCFiles: []string{"s3.tf"},
	}

	findings, err := adapter.runNativeFallback(tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("runNativeFallback failed: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, f := range findings {
		foundRules[f.Rule] = true
	}

	expectedRules := []string{"AVD-AWS-0086", "AVD-AWS-0107"}
	for _, r := range expectedRules {
		if !foundRules[r] {
			t.Errorf("Expected Terraform rule %s to be detected, found rules: %v", r, foundRules)
		}
	}
}
