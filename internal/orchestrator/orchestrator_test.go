package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

func TestCorrelateAndDeduplicate(t *testing.T) {
	reachableTrue := true
	findings := []Finding{
		{
			ID:        "1",
			Source:    "osv",
			Category:  CategorySCA,
			Rule:      "CVE-2021-23337",
			Severity:  SeverityMedium,
			CVE:       "CVE-2021-23337",
			CVSS:      5.0,
			File:      "package.json",
			LineStart: 10,
			Message:   "Command injection in lodash",
			Reachable: &reachableTrue,
			FirstSeen: time.Now(),
		},
		{
			ID:        "2",
			Source:    "trivy",
			Category:  CategorySCA,
			Rule:      "CVE-2021-23337",
			Severity:  SeverityHigh,
			CVE:       "CVE-2021-23337",
			CVSS:      7.2,
			File:      "package.json",
			LineStart: 10,
			Message:   "Critical command injection in lodash package",
			FirstSeen: time.Now(),
		},
	}

	deduped := CorrelateAndDeduplicate(findings)
	if len(deduped) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(deduped))
	}

	res := deduped[0]
	if res.Severity != SeverityHigh {
		t.Errorf("expected highest severity %s, got %s", SeverityHigh, res.Severity)
	}
	if res.Source != "osv+trivy" {
		t.Errorf("expected merged source 'osv+trivy', got '%s'", res.Source)
	}
	if res.CVSS != 7.2 {
		t.Errorf("expected highest CVSS 7.2, got %f", res.CVSS)
	}
	if res.Reachable == nil || !*res.Reachable {
		t.Errorf("expected reachability to be preserved")
	}
}

func TestCalculateRiskScore(t *testing.T) {
	reachable := true
	exposed := true
	f := &Finding{
		ID:        "TEST-01",
		Severity:  SeverityCritical,
		Category:  CategorySecret,
		CVSS:      9.8,
		Reachable: &reachable,
		Exposed:   &exposed,
	}

	score := CalculateRiskScore(f)
	if score <= 50.0 {
		t.Errorf("expected high risk score for exposed critical secret with CVSS 9.8, got %.1f", score)
	}
	if score > 100.0 {
		t.Errorf("risk score must be clamped at 100.0, got %.1f", score)
	}
}

func TestDiscoveryMultiLanguageAndFixtureScan(t *testing.T) {
	fixturePath := "../../testdata/vulnerable-app"
	discovery, err := Discover(fixturePath)
	if err != nil {
		t.Fatalf("Discover failed on vulnerable fixture: %v", err)
	}

	langs := make(map[string]bool)
	for _, l := range discovery.Languages {
		langs[l] = true
	}
	for _, requiredLang := range []string{"go", "javascript", "python", "terraform"} {
		if !langs[requiredLang] {
			t.Errorf("Expected language %q in discovery results, got: %v", requiredLang, discovery.Languages)
		}
	}

	manifests := make(map[string]bool)
	for _, m := range discovery.Manifests {
		manifests[m] = true
	}
	if !manifests["package.json"] {
		t.Errorf("Expected package.json in discovery manifests, got: %v", discovery.Manifests)
	}
	if !manifests["requirements.txt"] {
		t.Errorf("Expected requirements.txt in discovery manifests, got: %v", discovery.Manifests)
	}

	if len(discovery.IaCFiles) < 2 {
		t.Errorf("Expected at least 2 IaC files (Dockerfile, infra.tf), got: %v", discovery.IaCFiles)
	}
}

func TestDiscoveryEntryPointExclusions(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Normal Go file with route -> should be detected
	mainGo := filepath.Join(tmpDir, "main.go")
	_ = os.WriteFile(mainGo, []byte("package main\nfunc main() { http.HandleFunc(\"/api\", nil) }"), 0644)

	// 2. _test.go with route -> should be SKIPPED
	testGo := filepath.Join(tmpDir, "server_test.go")
	_ = os.WriteFile(testGo, []byte("package main\nfunc TestServer(t *testing.T) { http.HandleFunc(\"/test\", nil) }"), 0644)

	// 3. File > 1 MiB -> should be SKIPPED
	largeGo := filepath.Join(tmpDir, "large.go")
	f, err := os.Create(largeGo)
	if err != nil {
		t.Fatalf("failed to create large file: %v", err)
	}
	_ = f.Truncate(1024*1024 + 10) // 1 MiB + 10 bytes
	_, _ = f.WriteAt([]byte("http.HandleFunc(\"/large\", nil)"), 0)
	_ = f.Close()

	// 4. Dockerfile with EXPOSE -> should be detected
	dockerfile := filepath.Join(tmpDir, "Dockerfile")
	_ = os.WriteFile(dockerfile, []byte("FROM alpine\nEXPOSE 8080\n"), 0644)

	discovery, err := Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	entryMap := make(map[string]bool)
	for _, ep := range discovery.EntryPoints {
		entryMap[ep] = true
	}

	if !entryMap["main.go"] {
		t.Errorf("expected main.go to be an entry point")
	}
	if !entryMap["Dockerfile"] {
		t.Errorf("expected Dockerfile to be an entry point")
	}
	if entryMap["server_test.go"] {
		t.Errorf("server_test.go should be excluded from entry points")
	}
	if entryMap["large.go"] {
		t.Errorf("large.go (> 1 MiB) should be excluded from entry points")
	}
}

type panickingAdapter struct{}

func (p *panickingAdapter) Name() string                         { return "panic-bot" }
func (p *panickingAdapter) Category() string                     { return "sast" }
func (p *panickingAdapter) IsApplicable(d *DiscoveryResult) bool { return true }
func (p *panickingAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, d *DiscoveryResult) ([]Finding, error) {
	panic("unexpected fatal crash inside adapter")
}

type healthyAdapter struct{}

func (h *healthyAdapter) Name() string                         { return "healthy-bot" }
func (h *healthyAdapter) Category() string                     { return "secrets" }
func (h *healthyAdapter) IsApplicable(d *DiscoveryResult) bool { return true }
func (h *healthyAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, d *DiscoveryResult) ([]Finding, error) {
	return []Finding{
		{
			ID:          "HEALTHY-1",
			Source:      "healthy-bot",
			Category:    CategorySecret,
			Severity:    SeverityMedium,
			File:        "config.json",
			LineStart:   5,
			Fingerprint: "fp-healthy-1",
		},
	}, nil
}

func TestSchedulerPanicRecovery(t *testing.T) {
	scheduler := NewScheduler(&panickingAdapter{}, &healthyAdapter{})
	cfg := config.DefaultConfig()
	opts := ScanOptions{
		RepoPath: t.TempDir(),
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Scheduler Execute should not fail when an adapter panics: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding from healthy adapter, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != "HEALTHY-1" {
		t.Errorf("Expected finding HEALTHY-1, got %s", result.Findings[0].ID)
	}

	// Verify panic was converted to a warning
	foundPanicWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "panic-bot panicked") {
			foundPanicWarning = true
			break
		}
	}
	if !foundPanicWarning {
		t.Errorf("Expected warning about panic-bot panic, got warnings: %v", result.Warnings)
	}
}

type orderingAdapter struct{}

func (o *orderingAdapter) Name() string                         { return "order-bot" }
func (o *orderingAdapter) Category() string                     { return "sast" }
func (o *orderingAdapter) IsApplicable(d *DiscoveryResult) bool { return true }
func (o *orderingAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, d *DiscoveryResult) ([]Finding, error) {
	return []Finding{
		{ID: "f-low", Severity: SeverityLow, File: "b.go", LineStart: 10, Fingerprint: "fp-l"},
		{ID: "f-crit-2", Severity: SeverityCritical, File: "z.go", LineStart: 5, Fingerprint: "fp-c2"},
		{ID: "f-crit-1", Severity: SeverityCritical, File: "a.go", LineStart: 12, Fingerprint: "fp-c1"},
		{ID: "f-crit-3", Severity: SeverityCritical, File: "a.go", LineStart: 25, Fingerprint: "fp-c3"},
		{ID: "f-high", Severity: SeverityHigh, File: "c.go", LineStart: 1, Fingerprint: "fp-h"},
	}, nil
}

func TestSchedulerStableOrdering(t *testing.T) {
	scheduler := NewScheduler(&orderingAdapter{})
	cfg := config.DefaultConfig()
	opts := ScanOptions{
		RepoPath: t.TempDir(),
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if len(result.Findings) != 5 {
		t.Fatalf("Expected 5 findings, got %d", len(result.Findings))
	}

	// Severity descending: Critical (a.go:12, a.go:25, z.go:5), High (c.go:1), Low (b.go:10)
	expectedIDs := []string{"f-crit-1", "f-crit-3", "f-crit-2", "f-high", "f-low"}
	for i, expID := range expectedIDs {
		if result.Findings[i].ID != expID {
			t.Errorf("At index %d: expected %s, got %s (Severity: %s, File: %s, Line: %d)",
				i, expID, result.Findings[i].ID, result.Findings[i].Severity, result.Findings[i].File, result.Findings[i].LineStart)
		}
	}
}

type mockOSVEmbeddedAdapter struct{}

func (m *mockOSVEmbeddedAdapter) Name() string                         { return "osv" }
func (m *mockOSVEmbeddedAdapter) Category() string                     { return "sca" }
func (m *mockOSVEmbeddedAdapter) IsApplicable(d *DiscoveryResult) bool { return true }
func (m *mockOSVEmbeddedAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, d *DiscoveryResult) ([]Finding, error) {
	return []Finding{
		{
			ID:          "OSV-LITE-1",
			Source:      "osv",
			Engine:      EngineEmbedded,
			Category:    CategorySCA,
			Severity:    SeverityHigh,
			File:        "package.json",
			LineStart:   1,
			Fingerprint: "fp-osv-lite",
		},
	}, nil
}

func TestSchedulerOSVLiteWarningAndEngineDetermination(t *testing.T) {
	scheduler := NewScheduler(&mockOSVEmbeddedAdapter{})
	cfg := config.DefaultConfig()
	opts := ScanOptions{
		RepoPath: t.TempDir(),
	}

	result, err := scheduler.Execute(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if result.Engines["osv"] != EngineEmbedded {
		t.Errorf("expected engine for osv to be %q, got %q", EngineEmbedded, result.Engines["osv"])
	}

	if result.Mode != "lite" {
		t.Errorf("expected overall mode to be 'lite', got %q", result.Mode)
	}

	foundOSVWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "osv: embedded advisory list has 7 entries; install osv-scanner for full coverage") {
			foundOSVWarning = true
			break
		}
	}
	if !foundOSVWarning {
		t.Errorf("expected warning about OSV embedded advisory count, got: %v", result.Warnings)
	}
}
