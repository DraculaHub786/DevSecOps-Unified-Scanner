package trivy

import (
	"bufio"
	"context"
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

// TrivyAdapter executes Trivy for Container & IaC scanning, with an embedded
// configuration parser fallback for Dockerfile and Terraform files.
type TrivyAdapter struct{}

func New() *TrivyAdapter {
	return &TrivyAdapter{}
}

func (a *TrivyAdapter) Name() string {
	return "trivy"
}

func (a *TrivyAdapter) Category() string {
	return orchestrator.CategoryIaC
}

func (a *TrivyAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	return len(discovery.IaCFiles) > 0
}

type trivyOutput struct {
	Results []struct {
		Target            string `json:"Target"`
		Misconfigurations []struct {
			ID          string `json:"ID"`
			Title       string `json:"Title"`
			Description string `json:"Description"`
			Message     string `json:"Message"`
			Resolution  string `json:"Resolution"`
			Severity    string `json:"Severity"`
			PrimaryURL  string `json:"PrimaryURL"`
			Lines       struct {
				Start int `json:"Start"`
				End   int `json:"End"`
			} `json:"Lines"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
				EndLine   int `json:"EndLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
	} `json:"Results"`
}

func (a *TrivyAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.IaC.Enabled {
		return nil, nil
	}

	binPath, err := exec.LookPath("trivy")
	if err != nil || binPath == "" {
		if cfg.Engine == "external" {
			return nil, fmt.Errorf("trivy executable not found in PATH and engine is configured as 'external'")
		}
		return a.runNativeFallback(repoPath, cfg, discovery)
	}

	return a.runCLI(ctx, binPath, repoPath, cfg)
}

func (a *TrivyAdapter) runCLI(ctx context.Context, binPath, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	toolRes, err := adapters.RunTool(ctx, binPath, "fs", "--format", "json", "--scanners", "misconfig", repoPath)
	if err != nil {
		return nil, fmt.Errorf("trivy execution failed: %w", err)
	}

	if toolRes.ExitCode >= 2 {
		errLine := strings.TrimSpace(string(toolRes.Stderr))
		return nil, fmt.Errorf("trivy error (exit %d): %s", toolRes.ExitCode, errLine)
	}

	return a.ParseOutput(toolRes.Stdout, repoPath, cfg)
}

// ParseOutput parses raw JSON from Trivy and maps to normalized findings.
func (a *TrivyAdapter) ParseOutput(data []byte, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	var report trivyOutput
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON output: %w", err)
	}

	var findings []orchestrator.Finding
	for _, res := range report.Results {
		relFile, _ := filepath.Rel(repoPath, res.Target)
		if relFile == "" || relFile == "." {
			relFile = res.Target
		}
		relFile = filepath.ToSlash(relFile)

		if cfg.ShouldIgnorePath(relFile) {
			continue
		}

		for _, mis := range res.Misconfigurations {
			startLine := mis.Lines.Start
			if startLine <= 0 {
				startLine = mis.CauseMetadata.StartLine
			}
			if startLine <= 0 {
				startLine = 1
			}

			endLine := mis.Lines.End
			if endLine <= 0 {
				endLine = mis.CauseMetadata.EndLine
			}
			if endLine <= 0 {
				endLine = startLine
			}

			findingID := orchestrator.GenerateID("trivy", mis.ID, relFile, startLine)
			if cfg.ShouldIgnoreFinding(findingID) {
				continue
			}

			sev := orchestrator.SeverityMedium
			switch strings.ToUpper(mis.Severity) {
			case "CRITICAL":
				sev = orchestrator.SeverityCritical
			case "HIGH":
				sev = orchestrator.SeverityHigh
			case "MEDIUM":
				sev = orchestrator.SeverityMedium
			case "LOW":
				sev = orchestrator.SeverityLow
			}

			f := orchestrator.Finding{
				ID:          findingID,
				Source:      "trivy",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategoryIaC,
				Rule:        mis.ID,
				Severity:    sev,
				CWE:         "CWE-16", // Configuration
				File:        relFile,
				LineStart:   startLine,
				LineEnd:     endLine,
				Message:     fmt.Sprintf("%s: %s", mis.Title, mis.Message),
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, mis.ID, relFile, mis.Title),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// ScanImage executes a container image vulnerability scan using Trivy.
func ScanImage(ctx context.Context, imageName string) ([]orchestrator.Finding, error) {
	binPath, err := exec.LookPath("trivy")
	if err != nil || binPath == "" {
		return nil, fmt.Errorf("trivy is required for container image scanning (install trivy or use docker image)")
	}

	toolRes, err := adapters.RunTool(ctx, binPath, "image", "--format", "json", imageName)
	if err != nil {
		return nil, fmt.Errorf("trivy image scan failed: %w", err)
	}

	var report trivyOutput
	if err := json.Unmarshal(toolRes.Stdout, &report); err != nil {
		return nil, fmt.Errorf("failed to parse trivy image report: %w", err)
	}

	var findings []orchestrator.Finding
	for _, res := range report.Results {
		for _, mis := range res.Misconfigurations {
			f := orchestrator.Finding{
				ID:        orchestrator.GenerateID("trivy", mis.ID, imageName, 1),
				Source:    "trivy",
				Engine:    orchestrator.EngineExternal,
				Category:  orchestrator.CategoryIaC,
				Rule:      mis.ID,
				Severity:  strings.ToLower(mis.Severity),
				File:      imageName,
				LineStart: 1,
				LineEnd:   1,
				Message:   fmt.Sprintf("[%s] %s: %s", imageName, mis.Title, mis.Message),
				FirstSeen: time.Now().UTC(),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// GenerateSBOM outputs a software bill of materials in CycloneDX or SPDX format.
func GenerateSBOM(ctx context.Context, repoPath, format, outputPath string) error {
	binPath, err := exec.LookPath("trivy")
	if err != nil || binPath == "" {
		return fmt.Errorf("trivy is required for SBOM generation (install trivy)")
	}

	if format == "" {
		format = "cyclonedx"
	}

	args := []string{"fs", "--format", format}
	if outputPath != "" {
		args = append(args, "--output", outputPath)
	}
	args = append(args, repoPath)

	toolRes, err := adapters.RunTool(ctx, binPath, args...)
	if err != nil {
		return fmt.Errorf("SBOM generation failed: %w", err)
	}
	if toolRes.ExitCode != 0 {
		return fmt.Errorf("trivy sbom error (exit %d): %s", toolRes.ExitCode, string(toolRes.Stderr))
	}

	if outputPath == "" {
		fmt.Println(string(toolRes.Stdout))
	} else {
		fmt.Printf("✅ SBOM successfully generated in %s format: %s\n", format, outputPath)
	}

	return nil
}

func (a *TrivyAdapter) runNativeFallback(repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	var findings []orchestrator.Finding

	var targetFiles []string
	if discovery != nil && len(discovery.IaCFiles) > 0 {
		targetFiles = discovery.IaCFiles
	} else {
		_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			base := strings.ToLower(info.Name())
			if strings.Contains(base, "dockerfile") || strings.HasSuffix(base, ".tf") {
				rel, _ := filepath.Rel(repoPath, path)
				targetFiles = append(targetFiles, filepath.ToSlash(rel))
			}
			return nil
		})
	}

	for _, rel := range targetFiles {
		if cfg.ShouldIgnorePath(rel) {
			continue
		}

		fullPath := filepath.Join(repoPath, rel)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		content := string(data)
		base := strings.ToLower(filepath.Base(rel))

		if strings.Contains(base, "dockerfile") {
			// Check if runs as root (missing USER nonroot)
			if !regexp.MustCompile(`(?m)^\s*USER\s+[^\s]+`).MatchString(content) {
				findingID := orchestrator.GenerateID("trivy", "AVD-DS-0002", rel, 1)
				if !cfg.ShouldIgnoreFinding(findingID) {
					f := orchestrator.Finding{
						ID:          findingID,
						Source:      "trivy",
						Engine:      orchestrator.EngineEmbedded,
						Category:    orchestrator.CategoryIaC,
						Rule:        "AVD-DS-0002",
						Severity:    orchestrator.SeverityHigh,
						CWE:         "CWE-250",
						File:        rel,
						LineStart:   1,
						LineEnd:     1,
						Message:     "Dockerfile does not specify a non-root USER instruction; container will execute as root",
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DS-0002", rel, "root"),
					}
					f.RiskScore = orchestrator.CalculateRiskScore(&f)
					f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
					findings = append(findings, f)
				}
			}

			// Check for latest tag
			lines := strings.Split(content, "\n")
			for idx, line := range lines {
				if match := regexp.MustCompile(`(?i)^\s*FROM\s+([^\s:]+)(?::latest)?\s*$`).FindStringSubmatch(line); len(match) > 0 {
					if strings.Contains(line, ":latest") || !strings.Contains(match[0], ":") {
						findingID := orchestrator.GenerateID("trivy", "AVD-DS-0001", rel, idx+1)
						if !cfg.ShouldIgnoreFinding(findingID) {
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-DS-0001",
								Severity:    orchestrator.SeverityMedium,
								CWE:         "CWE-1188",
								File:        rel,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("Base image '%s' uses mutable :latest or untagged version; pin exact digest or semver tag", strings.TrimSpace(line)),
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DS-0001", rel, line),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}
				}
			}
		}

		if strings.HasSuffix(base, ".tf") {
			// Check for open ingress 0.0.0.0/0
			file, err := os.Open(fullPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(file)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				if strings.Contains(line, `"0.0.0.0/0"`) && (strings.Contains(line, "cidr_blocks") || strings.Contains(line, "cidr")) {
					findingID := orchestrator.GenerateID("trivy", "AVD-AWS-0107", rel, lineNum)
					if !cfg.ShouldIgnoreFinding(findingID) {
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-AWS-0107",
							Severity:    orchestrator.SeverityHigh,
							CWE:         "CWE-284",
							File:        rel,
							LineStart:   lineNum,
							LineEnd:     lineNum,
							Message:     "Security group rule exposes open ingress to 0.0.0.0/0 (entire public internet)",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-AWS-0107", rel, line),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}
			}
			file.Close()
		}
	}

	return findings, nil
}
