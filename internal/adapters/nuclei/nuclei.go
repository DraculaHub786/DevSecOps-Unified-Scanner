package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/safety"
)

// NucleiAdapter executes passive DAST misconfiguration templates against a user-declared target URL.
// Strictly obeys legal & safety boundaries: passive checks only, requires explicit authorization and allowlist.
type NucleiAdapter struct {
	Authorized bool
}

func New() *NucleiAdapter {
	return &NucleiAdapter{Authorized: false}
}

func NewWithAuth(authorized bool) *NucleiAdapter {
	return &NucleiAdapter{Authorized: authorized}
}

func (a *NucleiAdapter) Name() string {
	return "nuclei"
}

func (a *NucleiAdapter) Category() string {
	return orchestrator.CategoryDAST
}

func (a *NucleiAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	// DAST is target-driven; applicable only when an explicit target is specified
	return discovery != nil && strings.TrimSpace(discovery.TargetURL) != ""
}

type nucleiJSONLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
}

func (a *NucleiAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.DAST.Enabled || strings.TrimSpace(cfg.Scanners.DAST.Target) == "" {
		return nil, nil
	}

	targetURL := strings.TrimSpace(cfg.Scanners.DAST.Target)

	// Enforce strict authorization and IP safety boundaries
	if err := safety.ValidateTarget(targetURL, cfg.Scanners.DAST.Allowlist, a.Authorized, cfg.Scanners.DAST.AllowPrivate); err != nil {
		return nil, fmt.Errorf("DAST safety refusal: %w", err)
	}

	binPath, err := exec.LookPath("nuclei")
	if err != nil || binPath == "" {
		if cfg.Engine == "external" {
			return nil, fmt.Errorf("nuclei executable not found in PATH and engine is configured as 'external'")
		}
		return a.runPassiveNativeChecks(ctx, targetURL, cfg)
	}

	return a.runCLI(ctx, binPath, targetURL, cfg)
}

func (a *NucleiAdapter) runCLI(ctx context.Context, binPath, targetURL string, cfg *config.Config) ([]orchestrator.Finding, error) {
	// Passive templates only with strict rate cap; no active attacks or load testing
	toolRes, err := adapters.RunTool(ctx, binPath, "-u", targetURL, "-tags", "misconfig,exposure,headers", "-passive", "-rate-limit", "10", "-jsonl", "-silent")
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	if toolRes.ExitCode >= 2 {
		errLine := strings.TrimSpace(string(toolRes.Stderr))
		return nil, fmt.Errorf("nuclei error (exit %d): %s", toolRes.ExitCode, errLine)
	}

	return ParseOutput(toolRes.Stdout, targetURL, cfg)
}

// ParseOutput parses line-delimited JSON output from Nuclei and produces normalized findings.
func ParseOutput(data []byte, targetURL string, cfg *config.Config) ([]orchestrator.Finding, error) {
	var findings []orchestrator.Finding
	lines := strings.Split(string(data), "\n")
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
			Engine:      orchestrator.EngineExternal,
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

	return findings, nil
}

func (a *NucleiAdapter) runPassiveNativeChecks(ctx context.Context, targetURL string, cfg *config.Config) ([]orchestrator.Finding, error) {
	var findings []orchestrator.Finding

	// Safe transport preventing DNS rebinding attacks at connect time
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			ips, err := net.LookupIP(host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if safety.IsDisallowedIP(ip, cfg.Scanners.DAST.AllowPrivate) {
					return nil, fmt.Errorf("connection refused: %s resolves to restricted/internal IP %s", host, ip)
				}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil // target unreachable or connection refused
	}
	defer resp.Body.Close()

	headers := resp.Header

	// 1. Missing Content-Security-Policy
	if headers.Get("Content-Security-Policy") == "" {
		id := orchestrator.GenerateID("nuclei", "missing-csp-header", targetURL, 1)
		if !cfg.ShouldIgnoreFinding(id) {
			f := orchestrator.Finding{
				ID:          id,
				Source:      "nuclei",
				Engine:      orchestrator.EngineEmbedded,
				Category:    orchestrator.CategoryDAST,
				Rule:        "missing-csp-header",
				Severity:    orchestrator.SeverityMedium,
				CWE:         "CWE-1021",
				File:        targetURL,
				LineStart:   1,
				LineEnd:     1,
				Message:     "Missing Content-Security-Policy header in runtime HTTP response [Embedded Lite Check]",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryDAST, "missing-csp", targetURL, "csp"),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			findings = append(findings, f)
		}
	}

	// 2. Missing Strict-Transport-Security on HTTPS
	if strings.HasPrefix(targetURL, "https://") && headers.Get("Strict-Transport-Security") == "" {
		id := orchestrator.GenerateID("nuclei", "missing-hsts-header", targetURL, 1)
		if !cfg.ShouldIgnoreFinding(id) {
			f := orchestrator.Finding{
				ID:          id,
				Source:      "nuclei",
				Engine:      orchestrator.EngineEmbedded,
				Category:    orchestrator.CategoryDAST,
				Rule:        "missing-hsts-header",
				Severity:    orchestrator.SeverityHigh,
				CWE:         "CWE-523",
				File:        targetURL,
				LineStart:   1,
				LineEnd:     1,
				Message:     "Missing Strict-Transport-Security (HSTS) header on HTTPS endpoint [Embedded Lite Check]",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryDAST, "missing-hsts", targetURL, "hsts"),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}
