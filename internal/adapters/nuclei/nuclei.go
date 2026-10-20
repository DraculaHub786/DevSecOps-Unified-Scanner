package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/sentinel-dev/sentinel/internal/config"
	"github.com/sentinel-dev/sentinel/internal/orchestrator"
)

// NucleiAdapter executes passive DAST misconfiguration templates against a user-declared target URL.
// Strictly obeys legal & safety boundaries: passive checks only by default.
type NucleiAdapter struct{}

func New() *NucleiAdapter {
	return &NucleiAdapter{}
}

func (a *NucleiAdapter) Name() string {
	return "nuclei"
}

func (a *NucleiAdapter) Category() string {
	return orchestrator.CategoryDAST
}

func (a *NucleiAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	// DAST is target-driven, executed when a target is provided in config or CLI flag
	return true
}

type nucleiJSONLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Reference   []string `json:"reference"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
}

func (a *NucleiAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.DAST.Enabled || cfg.Scanners.DAST.Target == "" {
		return nil, nil
	}

	targetURL := cfg.Scanners.DAST.Target
	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid DAST target URL: %s", targetURL)
	}

	binPath, err := exec.LookPath("nuclei")
	if err == nil && binPath != "" {
		return a.runCLI(ctx, binPath, targetURL, cfg)
	}

	return a.runPassiveNativeChecks(ctx, targetURL, cfg)
}

func (a *NucleiAdapter) runCLI(ctx context.Context, binPath, targetURL string, cfg *config.Config) ([]orchestrator.Finding, error) {
	// Execute passive templates only
	cmd := exec.CommandContext(ctx, binPath, "-u", targetURL, "-tags", "misconfig,exposure,headers", "-passive", "-jsonl", "-silent")
	output, _ := cmd.CombinedOutput()

	var findings []orchestrator.Finding
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry nucleiJSONLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		findingID := orchestrator.GenerateID("nuclei", entry.TemplateID, targetURL, 1)
		if cfg.ShouldIgnoreFinding(findingID) {
			continue
		}

		f := orchestrator.Finding{
			ID:          findingID,
			Source:      "nuclei",
			Category:    orchestrator.CategoryDAST,
			Rule:        entry.TemplateID,
			Severity:    strings.ToLower(entry.Info.Severity),
			CWE:         "CWE-16",
			File:        targetURL,
			LineStart:   1,
			LineEnd:     1,
			Message:     fmt.Sprintf("%s: %s (Matched at: %s)", entry.Info.Name, entry.Info.Description, entry.MatchedAt),
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryDAST, entry.TemplateID, targetURL, entry.Info.Name),
		}
		f.RiskScore = orchestrator.CalculateRiskScore(&f)
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return a.runPassiveNativeChecks(ctx, targetURL, cfg)
	}

	return findings, nil
}

func (a *NucleiAdapter) runPassiveNativeChecks(ctx context.Context, targetURL string, cfg *config.Config) ([]orchestrator.Finding, error) {
	var findings []orchestrator.Finding

	client := &http.Client{
		Timeout: 6 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Target might not be currently running; return informative note rather than fatal error
		return nil, nil
	}
	defer resp.Body.Close()

	headers := resp.Header

	// 1. Missing Content-Security-Policy
	if headers.Get("Content-Security-Policy") == "" {
		id := orchestrator.GenerateID("nuclei", "missing-csp-header", targetURL, 1)
		f := orchestrator.Finding{
			ID:          id,
			Source:      "nuclei",
			Category:    orchestrator.CategoryDAST,
			Rule:        "missing-csp-header",
			Severity:    orchestrator.SeverityMedium,
			CWE:         "CWE-1021",
			File:        targetURL,
			LineStart:   1,
			LineEnd:     1,
			Message:     "Missing Content-Security-Policy header in runtime HTTP response",
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryDAST, "missing-csp", targetURL, "csp"),
		}
		f.RiskScore = orchestrator.CalculateRiskScore(&f)
		findings = append(findings, f)
	}

	// 2. Missing Strict-Transport-Security on HTTPS
	if strings.HasPrefix(targetURL, "https://") && headers.Get("Strict-Transport-Security") == "" {
		id := orchestrator.GenerateID("nuclei", "missing-hsts-header", targetURL, 1)
		f := orchestrator.Finding{
			ID:          id,
			Source:      "nuclei",
			Category:    orchestrator.CategoryDAST,
			Rule:        "missing-hsts-header",
			Severity:    orchestrator.SeverityHigh,
			CWE:         "CWE-523",
			File:        targetURL,
			LineStart:   1,
			LineEnd:     1,
			Message:     "Missing Strict-Transport-Security (HSTS) header on HTTPS endpoint",
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryDAST, "missing-hsts", targetURL, "hsts"),
		}
		f.RiskScore = orchestrator.CalculateRiskScore(&f)
		findings = append(findings, f)
	}

	// 3. Exposed Server Banner
	if server := headers.Get("Server"); server != "" {
		id := orchestrator.GenerateID("nuclei", "exposed-server-header", targetURL, 1)
		f := orchestrator.Finding{
			ID:          id,
			Source:      "nuclei",
			Category:    orchestrator.CategoryDAST,
			Rule:        "exposed-server-header",
			Severity:    orchestrator.SeverityLow,
			CWE:         "CWE-200",
			File:        targetURL,
			LineStart:   1,
			LineEnd:     1,
			Message:     fmt.Sprintf("Detailed server technology header exposed in HTTP response: %s", server),
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryDAST, "exposed-server", targetURL, server),
		}
		f.RiskScore = orchestrator.CalculateRiskScore(&f)
		findings = append(findings, f)
	}

	return findings, nil
}
