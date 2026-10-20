package gitleaks

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// GitleaksAdapter wraps the Gitleaks CLI for secrets scanning, with an embedded
// high-entropy pattern scanner fallback when the binary is not present in PATH.
type GitleaksAdapter struct{}

func New() *GitleaksAdapter {
	return &GitleaksAdapter{}
}

func (a *GitleaksAdapter) Name() string {
	return "gitleaks"
}

func (a *GitleaksAdapter) Category() string {
	return orchestrator.CategorySecret
}

func (a *GitleaksAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	return true
}

type gitleaksReportEntry struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
	Secret      string `json:"Secret"`
	Match       string `json:"Match"`
}

func (a *GitleaksAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.Secrets.Enabled {
		return nil, nil
	}

	binPath, err := exec.LookPath("gitleaks")
	if err != nil || binPath == "" {
		if cfg.Engine == "external" {
			return nil, fmt.Errorf("gitleaks executable not found in PATH and engine is configured as 'external'")
		}
		return a.runNativeFallback(repoPath, cfg)
	}

	return a.runCLI(ctx, binPath, repoPath, cfg)
}

func (a *GitleaksAdapter) runCLI(ctx context.Context, binPath, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	tmpReport, err := os.CreateTemp("", "sentinel-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp report file for gitleaks: %w", err)
	}
	tmpReportPath := tmpReport.Name()
	tmpReport.Close()
	defer os.Remove(tmpReportPath)

	args := []string{
		"detect",
		"--source", repoPath,
		"--report-format", "json",
		"--report-path", tmpReportPath,
		"--redact",
		"--exit-code", "0",
	}

	if !cfg.Scanners.Secrets.ScanHistory || !discoveryHasGit(repoPath) {
		args = append(args, "--no-git")
	}

	toolRes, err := adapters.RunTool(ctx, binPath, args...)
	if err != nil {
		return nil, fmt.Errorf("gitleaks execution failed: %w", err)
	}

	if toolRes.ExitCode != 0 {
		return nil, fmt.Errorf("gitleaks error (exit %d): %s", toolRes.ExitCode, strings.TrimSpace(string(toolRes.Stderr)))
	}

	data, err := os.ReadFile(tmpReportPath)
	if err != nil || len(data) == 0 {
		// Clean exit with 0 findings is completely normal!
		return []orchestrator.Finding{}, nil
	}

	return ParseReport(data, repoPath, cfg)
}

// ParseReport parses JSON output from Gitleaks and converts to normalized findings.
func ParseReport(data []byte, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	if len(data) == 0 {
		return []orchestrator.Finding{}, nil
	}

	var entries []gitleaksReportEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse gitleaks output report: %w", err)
	}

	findings := make([]orchestrator.Finding, 0, len(entries))
	for _, entry := range entries {
		relFile, _ := filepath.Rel(repoPath, entry.File)
		if relFile == "" {
			relFile = entry.File
		}
		relFile = filepath.ToSlash(relFile)

		if cfg.ShouldIgnorePath(relFile) {
			continue
		}

		redacted := redactSecret(entry.Secret)
		findingID := orchestrator.GenerateID("gitleaks", entry.RuleID, relFile, entry.StartLine)
		if cfg.ShouldIgnoreFinding(findingID) {
			continue
		}

		f := orchestrator.Finding{
			ID:          findingID,
			Source:      "gitleaks",
			Engine:      orchestrator.EngineExternal,
			Category:    orchestrator.CategorySecret,
			Rule:        entry.RuleID,
			Severity:    orchestrator.SeverityCritical,
			CWE:         "CWE-798", // Use of Hard-coded Credentials
			File:        relFile,
			LineStart:   entry.StartLine,
			LineEnd:     entry.EndLine,
			Message:     fmt.Sprintf("%s (Redacted: %s)", entry.Description, redacted),
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySecret, entry.RuleID, relFile, redacted),
		}
		f.RiskScore = orchestrator.CalculateRiskScore(&f)
		f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
		findings = append(findings, f)
	}

	return findings, nil
}

type secretRule struct {
	ID          string
	Description string
	Pattern     *regexp.Regexp
	CWE         string
}

func (a *GitleaksAdapter) runNativeFallback(repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	rules := []secretRule{
		{
			ID:          "aws-access-key-id",
			Description: "Identified hardcoded AWS Access Key ID",
			Pattern:     regexp.MustCompile(`(?i)(?:aws_access_key_id|aws_key|aws_access_key)[\s=:'"]*(AKIA[0-9A-Z]{16})`),
			CWE:         "CWE-798",
		},
		{
			ID:          "aws-secret-access-key",
			Description: "Identified hardcoded AWS Secret Access Key",
			Pattern:     regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret|secret_key)[\s=:'"]*([0-9a-zA-Z/+]{40})`),
			CWE:         "CWE-798",
		},
		{
			ID:          "github-pat",
			Description: "Identified GitHub Personal Access Token",
			Pattern:     regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
			CWE:         "CWE-798",
		},
		{
			ID:          "slack-token",
			Description: "Identified Slack API Bot/User Token",
			Pattern:     regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
			CWE:         "CWE-798",
		},
		{
			ID:          "private-key",
			Description: "Identified unencrypted Private Key header",
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----`),
			CWE:         "CWE-312",
		},
		{
			ID:          "generic-secret-assignment",
			Description: "Identified hardcoded secret, API key, or credential assignment",
			Pattern:     regexp.MustCompile(`(?i)(?:api_key|apikey|secret_token|auth_token|client_secret|db_password)\s*[:=]\s*["']([a-zA-Z0-9_\-\.\$]{12,})["']`),
			CWE:         "CWE-798",
		},
	}

	var findings []orchestrator.Finding

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".sentinel" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(repoPath, path)
		rel = filepath.ToSlash(rel)

		if cfg.ShouldIgnorePath(rel) {
			return nil
		}

		if info.Size() > 2*1024*1024 {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, r := range rules {
				if r.Pattern.MatchString(line) {
					sub := r.Pattern.FindStringSubmatch(line)
					secretVal := ""
					if len(sub) > 1 {
						secretVal = sub[1]
					} else if len(sub) > 0 {
						secretVal = sub[0]
					}

					redacted := redactSecret(secretVal)
					findingID := orchestrator.GenerateID("gitleaks", r.ID, rel, lineNum)
					if cfg.ShouldIgnoreFinding(findingID) {
						continue
					}

					f := orchestrator.Finding{
						ID:          findingID,
						Source:      "gitleaks",
						Engine:      orchestrator.EngineEmbedded,
						Category:    orchestrator.CategorySecret,
						Rule:        r.ID,
						Severity:    orchestrator.SeverityCritical,
						CWE:         r.CWE,
						File:        rel,
						LineStart:   lineNum,
						LineEnd:     lineNum,
						Message:     fmt.Sprintf("%s (Redacted: %s)", r.Description, redacted),
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySecret, r.ID, rel, redacted),
					}
					f.RiskScore = orchestrator.CalculateRiskScore(&f)
					f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
					findings = append(findings, f)
				}
			}
		}

		return nil
	})

	return findings, err
}

func redactSecret(secret string) string {
	if len(secret) <= 6 {
		h := sha256.Sum256([]byte(secret))
		return fmt.Sprintf("sha256:%x", h[:4])
	}
	prefix := secret[:3]
	suffix := secret[len(secret)-3:]
	return fmt.Sprintf("%s%s%s", prefix, strings.Repeat("*", len(secret)-6), suffix)
}

func discoveryHasGit(repoPath string) bool {
	fi, err := os.Stat(filepath.Join(repoPath, ".git"))
	return err == nil && fi.IsDir()
}
