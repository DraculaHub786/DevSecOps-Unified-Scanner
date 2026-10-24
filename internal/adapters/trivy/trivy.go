package trivy

import (
	"bufio"
	"bytes"
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
		Class             string `json:"Class"`
		Type              string `json:"Type"`
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
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			Severity         string   `json:"Severity"`
			PrimaryURL       string   `json:"PrimaryURL"`
			CweIDs           []string `json:"CweIDs"`
		} `json:"Vulnerabilities"`
		Licenses []struct {
			Severity string `json:"Severity"`
			Category string `json:"Category"`
			PkgName  string `json:"PkgName"`
			Name     string `json:"Name"`
		} `json:"Licenses"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Category  string `json:"Category"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
			EndLine   int    `json:"EndLine"`
			Match     string `json:"Match"`
		} `json:"Secrets"`
	} `json:"Results"`
}

func isVulnDBUnavailable(stderr, stdout string) bool {
	combined := strings.ToLower(stderr + " " + stdout)
	dbPatterns := []string{
		"failed to download vulnerability db",
		"database download error",
		"cannot be used without database",
		"offline-scan cannot be used without database",
		"failed to download db",
		"download error",
		"vulnerability db",
		"failed to open db",
		"connection refused",
		"network is unreachable",
		"i/o timeout",
		"no such host",
		"context deadline exceeded",
		"client.timeout exceeded",
	}
	for _, p := range dbPatterns {
		if strings.Contains(combined, p) {
			return true
		}
	}
	return false
}

func (a *TrivyAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.IaC.Enabled && !cfg.Scanners.SCA.Enabled {
		return nil, nil
	}

	binPath, err := exec.LookPath("trivy")
	if err != nil || binPath == "" {
		if cfg.Engine == "external" {
			return nil, fmt.Errorf("trivy executable not found in PATH and engine is configured as 'external'")
		}
		return a.runNativeFallback(repoPath, cfg, discovery)
	}

	return a.runCLI(ctx, binPath, repoPath, cfg, discovery)
}

func (a *TrivyAdapter) runCLI(ctx context.Context, binPath, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	var (
		allFindings []orchestrator.Finding
		hasIaC      bool
		iacRan      bool
		partialErr  error
	)

	// 1. IaC & Secrets Pass (Fully offline-safe, decoupled from vulnerability DB)
	if cfg.Scanners.IaC.Enabled {
		iacRan = true
		args := []string{"fs", "--format", "json", "--scanners", "misconfig,secret", "--skip-db-update", "--skip-check-update"}
		if cfg.Offline {
			args = append(args, "--offline-scan")
		}
		args = append(args, repoPath)

		toolRes, err := adapters.RunTool(ctx, binPath, args...)
		if err != nil {
			return nil, fmt.Errorf("trivy iac execution failed: %w", err)
		}

		if toolRes.ExitCode >= 2 {
			errLine := strings.TrimSpace(string(toolRes.Stderr))
			return nil, fmt.Errorf("trivy iac error (exit %d): %s", toolRes.ExitCode, errLine)
		}

		findings, err := a.ParseOutput(toolRes.Stdout, repoPath, cfg)
		if err != nil {
			return nil, err
		}
		if len(findings) > 0 {
			hasIaC = true
			allFindings = append(allFindings, findings...)
		}

		// Check for non-fatal parse errors reported in stderr
		errStr := strings.ToLower(string(toolRes.Stderr))
		if strings.Contains(errStr, "failed to parse") || strings.Contains(errStr, "syntax error") {
			partialErr = fmt.Errorf("%w: %s", orchestrator.ErrPartial, strings.TrimSpace(string(toolRes.Stderr)))
		}
	}

	// 2. Vulnerability & License (SCA) Pass (Requires CVE database)
	if cfg.Scanners.SCA.Enabled {
		if cfg.Offline {
			// In offline mode, attempt scan with existing cached DB.
			scaArgs := []string{"fs", "--format", "json", "--scanners", "vuln,license", "--offline-scan", "--skip-db-update", "--skip-check-update", repoPath}
			scaRes, err := adapters.RunTool(ctx, binPath, scaArgs...)
			if err != nil || scaRes.ExitCode != 0 {
				// DB is unavailable or missing in offline mode
				if !iacRan || (!hasIaC && discovery != nil && len(discovery.IaCFiles) == 0) {
					return nil, fmt.Errorf("%w: trivy vulnerability database unavailable in --offline mode", orchestrator.ErrSkipped)
				}
				fmt.Fprintln(os.Stderr, "trivy: vulnerability database unavailable in --offline mode; skipped vulnerability scanning")
			} else {
				scaFindings, _ := a.ParseOutput(scaRes.Stdout, repoPath, cfg)
				allFindings = append(allFindings, scaFindings...)
			}
		} else {
			// Online mode: run SCA scan
			scaArgs := []string{"fs", "--format", "json", "--scanners", "vuln,license", "--skip-check-update", repoPath}
			scaRes, err := adapters.RunTool(ctx, binPath, scaArgs...)
			if err != nil {
				if isVulnDBUnavailable(err.Error(), "") {
					if !iacRan || (!hasIaC && discovery != nil && len(discovery.IaCFiles) == 0) {
						return nil, fmt.Errorf("%w: trivy vulnerability database unavailable: %v", orchestrator.ErrSkipped, err)
					}
					fmt.Fprintf(os.Stderr, "trivy: vulnerability database unavailable (%v); skipped vulnerability scanning\n", err)
				} else {
					return nil, fmt.Errorf("trivy sca execution failed: %w", err)
				}
			} else if scaRes.ExitCode >= 2 {
				errLine := strings.TrimSpace(string(scaRes.Stderr))
				if isVulnDBUnavailable(errLine, string(scaRes.Stdout)) {
					if !iacRan || (!hasIaC && discovery != nil && len(discovery.IaCFiles) == 0) {
						return nil, fmt.Errorf("%w: trivy vulnerability database unavailable (%s)", orchestrator.ErrSkipped, errLine)
					}
					fmt.Fprintf(os.Stderr, "trivy: vulnerability database download failed: %s; skipped vulnerability scanning\n", errLine)
				} else {
					// Actual scanner failure!
					return nil, fmt.Errorf("trivy sca error (exit %d): %s", scaRes.ExitCode, errLine)
				}
			} else {
				scaFindings, _ := a.ParseOutput(scaRes.Stdout, repoPath, cfg)
				allFindings = append(allFindings, scaFindings...)
			}
		}
	}

	if partialErr != nil {
		return allFindings, partialErr
	}
	return allFindings, nil
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

			sev := mapTrivySeverity(mis.Severity)

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
				Snippet:     mis.Title,
				OWASP:       "A05:2021-Security Misconfiguration",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, mis.ID, relFile, mis.Title),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
			findings = append(findings, f)
		}

		// Vulnerabilities (SCA second opinion engine - T-056)
		for _, vuln := range res.Vulnerabilities {
			findingID := orchestrator.GenerateID("trivy", vuln.VulnerabilityID, relFile, 1)
			if cfg.ShouldIgnoreFinding(findingID) {
				continue
			}
			snippet := fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion)
			cwe := "CWE-1395"
			if len(vuln.CweIDs) > 0 {
				cwe = vuln.CweIDs[0]
			}
			msg := vuln.Title
			if msg == "" {
				msg = fmt.Sprintf("Vulnerability %s in dependency %s (fixed in: %s)", vuln.VulnerabilityID, snippet, vuln.FixedVersion)
			}
			f := orchestrator.Finding{
				ID:          findingID,
				Source:      "trivy",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySCA,
				Rule:        vuln.VulnerabilityID,
				Severity:    mapTrivySeverity(vuln.Severity),
				CVE:         vuln.VulnerabilityID,
				CWE:         cwe,
				File:        relFile,
				LineStart:   1,
				LineEnd:     1,
				Message:     msg,
				Snippet:     snippet,
				OWASP:       "A06:2021-Vulnerable and Outdated Components",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, vuln.VulnerabilityID, relFile, snippet),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
			findings = append(findings, f)
		}

		// Licenses compliance (T-057)
		for _, lic := range res.Licenses {
			if isDisallowedLicense(lic.Name, cfg.Scanners.SCA.FailOnLicense) {
				findingID := orchestrator.GenerateID("trivy", "license/"+lic.Name, relFile, 1)
				if cfg.ShouldIgnoreFinding(findingID) {
					continue
				}
				snippet := fmt.Sprintf("%s (%s)", lic.PkgName, lic.Name)
				f := orchestrator.Finding{
					ID:          findingID,
					Source:      "trivy",
					Engine:      orchestrator.EngineExternal,
					Category:    orchestrator.CategorySCA,
					Rule:        "license/" + lic.Name,
					Severity:    orchestrator.SeverityHigh,
					License:     lic.Name,
					File:        relFile,
					LineStart:   1,
					LineEnd:     1,
					Message:     fmt.Sprintf("Dependency %s uses forbidden license %q (configured in scanners.sca.fail_on_license)", lic.PkgName, lic.Name),
					Snippet:     snippet,
					OWASP:       "A06:2021-Vulnerable and Outdated Components",
					FirstSeen:   time.Now().UTC(),
					Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "license", relFile, snippet),
				}
				f.RiskScore = orchestrator.CalculateRiskScore(&f)
				findings = append(findings, f)
			}
		}

		// Secrets (from Trivy secrets scanner)
		for _, sec := range res.Secrets {
			startLine := sec.StartLine
			if startLine <= 0 {
				startLine = 1
			}
			endLine := sec.EndLine
			if endLine <= 0 {
				endLine = startLine
			}
			findingID := orchestrator.GenerateID("trivy", sec.RuleID, relFile, startLine)
			if cfg.ShouldIgnoreFinding(findingID) {
				continue
			}
			snippet := sec.Match
			if snippet == "" {
				snippet = sec.Title
			}
			f := orchestrator.Finding{
				ID:          findingID,
				Source:      "trivy",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySecret,
				Rule:        sec.RuleID,
				Severity:    mapTrivySeverity(sec.Severity),
				CWE:         "CWE-798",
				File:        relFile,
				LineStart:   startLine,
				LineEnd:     endLine,
				Message:     fmt.Sprintf("Hardcoded secret detected: %s", sec.Title),
				Snippet:     orchestrator.RedactSecret(snippet),
				OWASP:       "A07:2021-Identification and Authentication Failures",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySecret, sec.RuleID, relFile, snippet),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

func mapTrivySeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return orchestrator.SeverityCritical
	case "HIGH":
		return orchestrator.SeverityHigh
	case "MEDIUM":
		return orchestrator.SeverityMedium
	case "LOW":
		return orchestrator.SeverityLow
	default:
		return orchestrator.SeverityMedium
	}
}

func isDisallowedLicense(lic string, disallowed []string) bool {
	if lic == "" || len(disallowed) == 0 {
		return false
	}
	licLower := strings.ToLower(strings.TrimSpace(lic))
	for _, d := range disallowed {
		dLower := strings.ToLower(strings.TrimSpace(d))
		if dLower != "" && (licLower == dLower || strings.Contains(licLower, dLower)) {
			return true
		}
	}
	return false
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

		for _, vuln := range res.Vulnerabilities {
			findingID := orchestrator.GenerateID("trivy", vuln.VulnerabilityID, imageName, 1)
			snippet := fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion)
			cwe := "CWE-1395"
			if len(vuln.CweIDs) > 0 {
				cwe = vuln.CweIDs[0]
			}
			msg := vuln.Title
			if msg == "" {
				msg = fmt.Sprintf("Vulnerability %s in package %s (fixed in: %s)", vuln.VulnerabilityID, snippet, vuln.FixedVersion)
			}
			f := orchestrator.Finding{
				ID:          findingID,
				Source:      "trivy",
				Engine:      orchestrator.EngineExternal,
				Category:    orchestrator.CategorySCA,
				Rule:        vuln.VulnerabilityID,
				Severity:    mapTrivySeverity(vuln.Severity),
				CVE:         vuln.VulnerabilityID,
				CWE:         cwe,
				File:        imageName,
				LineStart:   1,
				LineEnd:     1,
				Message:     fmt.Sprintf("[%s] %s", imageName, msg),
				Snippet:     snippet,
				OWASP:       "A06:2021-Vulnerable and Outdated Components",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, vuln.VulnerabilityID, imageName, snippet),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

// GenerateSBOM outputs a software bill of materials in CycloneDX or SPDX format.
func GenerateSBOM(ctx context.Context, repoPath, format, outputPath string) error {
	if format == "" {
		format = "cyclonedx"
	}

	binPath, err := exec.LookPath("trivy")
	if err == nil && binPath != "" {
		args := []string{"fs", "--format", format}
		if outputPath != "" {
			args = append(args, "--output", outputPath)
		}
		args = append(args, repoPath)

		toolRes, err := adapters.RunTool(ctx, binPath, args...)
		if err == nil && toolRes.ExitCode == 0 {
			if outputPath == "" {
				fmt.Println(string(toolRes.Stdout))
			} else {
				fmt.Printf("✅ SBOM successfully generated in %s format: %s\n", format, outputPath)
			}
			return nil
		}
	}

	// Native embedded fallback when external Trivy is not installed or unavailable
	return generateNativeSBOM(repoPath, format, outputPath)
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []cdxTool    `json:"tools"`
	Component cdxComponent `json:"component"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

func generateNativeSBOM(repoPath, format, outputPath string) error {
	var components []cdxComponent
	seen := make(map[string]bool)

	_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		base := info.Name()
		if base == "package.json" {
			data, err := os.ReadFile(path)
			if err == nil {
				var pkg struct {
					Dependencies    map[string]string `json:"dependencies"`
					DevDependencies map[string]string `json:"devDependencies"`
				}
				if json.Unmarshal(data, &pkg) == nil {
					for dep, ver := range pkg.Dependencies {
						ver = strings.TrimPrefix(ver, "^")
						ver = strings.TrimPrefix(ver, "~")
						key := "npm:" + dep + "@" + ver
						if !seen[key] {
							seen[key] = true
							components = append(components, cdxComponent{
								Type:    "library",
								Name:    dep,
								Version: ver,
								PURL:    fmt.Sprintf("pkg:npm/%s@%s", dep, ver),
							})
						}
					}
					for dep, ver := range pkg.DevDependencies {
						ver = strings.TrimPrefix(ver, "^")
						ver = strings.TrimPrefix(ver, "~")
						key := "npm:" + dep + "@" + ver
						if !seen[key] {
							seen[key] = true
							components = append(components, cdxComponent{
								Type:    "library",
								Name:    dep,
								Version: ver,
								PURL:    fmt.Sprintf("pkg:npm/%s@%s", dep, ver),
							})
						}
					}
				}
			}
		} else if base == "requirements.txt" {
			f, err := os.Open(path)
			if err == nil {
				sc := bufio.NewScanner(f)
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.Split(line, "==")
					if len(parts) == 2 {
						pkgName := strings.TrimSpace(parts[0])
						pkgVer := strings.TrimSpace(parts[1])
						key := "pypi:" + pkgName + "@" + pkgVer
						if !seen[key] {
							seen[key] = true
							components = append(components, cdxComponent{
								Type:    "library",
								Name:    pkgName,
								Version: pkgVer,
								PURL:    fmt.Sprintf("pkg:pypi/%s@%s", pkgName, pkgVer),
							})
						}
					}
				}
				_ = sc.Err()
				f.Close()
			}
		} else if base == "go.mod" {
			f, err := os.Open(path)
			if err == nil {
				sc := bufio.NewScanner(f)
				inRequire := false
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if strings.HasPrefix(line, "require (") {
						inRequire = true
						continue
					}
					if inRequire && line == ")" {
						inRequire = false
						continue
					}
					if inRequire || strings.HasPrefix(line, "require ") {
						trimmed := strings.TrimPrefix(line, "require ")
						fields := strings.Fields(trimmed)
						if len(fields) >= 2 {
							mod := fields[0]
							ver := fields[1]
							key := "golang:" + mod + "@" + ver
							if !seen[key] {
								seen[key] = true
								components = append(components, cdxComponent{
									Type:    "library",
									Name:    mod,
									Version: ver,
									PURL:    fmt.Sprintf("pkg:golang/%s@%s", mod, ver),
								})
							}
						}
					}
				}
				_ = sc.Err()
				f.Close()
			}
		}
		return nil
	})

	repoBase := filepath.Base(repoPath)
	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{
					Vendor:  "Sentinel",
					Name:    "sentinel-lite-sbom",
					Version: "1.0.1",
				},
			},
			Component: cdxComponent{
				Type: "application",
				Name: repoBase,
			},
		},
		Components: components,
	}

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode CycloneDX SBOM: %w", err)
	}

	if outputPath == "" {
		fmt.Println(string(data))
	} else {
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write SBOM output to %s: %w", outputPath, err)
		}
		fmt.Printf("✅ SBOM successfully generated in CycloneDX format (lite engine): %s\n", outputPath)
	}

	return nil
}

func (a *TrivyAdapter) runNativeFallback(repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	var findings []orchestrator.Finding

	var targetFiles []string
	if discovery != nil && len(discovery.IaCFiles) > 0 {
		targetFiles = discovery.IaCFiles
	} else if discovery != nil && len(discovery.IaCFiles) == 0 {
		return nil, fmt.Errorf("%w: no IaC configuration files found for native fallback", orchestrator.ErrSkipped)
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

	if len(targetFiles) == 0 {
		return nil, fmt.Errorf("%w: no IaC configuration files found", orchestrator.ErrSkipped)
	}

	for _, rel := range targetFiles {
		rel = filepath.ToSlash(rel)
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
			// Check if runs as root (missing USER instruction or explicitly root/0)
			userMatch := regexp.MustCompile(`(?m)^\s*USER\s+([^\s]+)`).FindStringSubmatch(content)
			isRoot := false
			if len(userMatch) == 0 {
				isRoot = true
			} else {
				userVal := strings.ToLower(strings.TrimSpace(userMatch[1]))
				if userVal == "root" || userVal == "0" {
					isRoot = true
				}
			}
			if isRoot {
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
						Message:     "Dockerfile executes as root (missing non-root USER instruction or explicitly set to root)",
						Snippet:     "USER root",
						OWASP:       "A05:2021-Security Misconfiguration",
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DS-0002", rel, "USER root"),
					}
					f.RiskScore = orchestrator.CalculateRiskScore(&f)
					f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
					findings = append(findings, f)
				}
			}

			// Check for latest tag and insecure curl | sh pipes
			lines := strings.Split(content, "\n")
			curlPipeRegex := regexp.MustCompile(`(?i)(?:curl|wget)\s+[^|;` + "`" + `\n]+\|\s*(?:sh|bash)`)
			for idx, line := range lines {
				if match := regexp.MustCompile(`(?i)^\s*FROM\s+([^\s:]+)(?::latest)?\s*$`).FindStringSubmatch(line); len(match) > 0 {
					if strings.Contains(line, ":latest") || !strings.Contains(match[0], ":") {
						findingID := orchestrator.GenerateID("trivy", "AVD-DS-0001", rel, idx+1)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
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
								Message:     fmt.Sprintf("Base image '%s' uses mutable :latest or untagged version; pin exact digest or semver tag", snippet),
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DS-0001", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}
				}

				if curlPipeRegex.MatchString(line) {
					findingID := orchestrator.GenerateID("trivy", "AVD-DS-0003", rel, idx+1)
					if !cfg.ShouldIgnoreFinding(findingID) {
						snippet := strings.TrimSpace(line)
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-DS-0003",
							Severity:    orchestrator.SeverityHigh,
							CWE:         "CWE-494",
							File:        rel,
							LineStart:   idx + 1,
							LineEnd:     idx + 1,
							Message:     "Insecure download pipe to shell ('curl | sh' or 'wget | bash') in Dockerfile bypasses integrity verification and allows arbitrary code execution",
							Snippet:     snippet,
							OWASP:       "A08:2021-Software and Data Integrity Failures",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DS-0003", rel, snippet),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}
			}
		}

		if strings.HasSuffix(base, ".tf") {
			contentBytes, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(bytes.NewReader(contentBytes))
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				// Open ingress 0.0.0.0/0
				if strings.Contains(line, `"0.0.0.0/0"`) && (strings.Contains(line, "cidr_blocks") || strings.Contains(line, "cidr")) {
					findingID := orchestrator.GenerateID("trivy", "AVD-AWS-0107", rel, lineNum)
					if !cfg.ShouldIgnoreFinding(findingID) {
						snippet := strings.TrimSpace(line)
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
							Snippet:     snippet,
							OWASP:       "A05:2021-Security Misconfiguration",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-AWS-0107", rel, snippet),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}

				// S3 bucket public read ACL
				if strings.Contains(line, `"public-read"`) && strings.Contains(line, "acl") {
					findingID := orchestrator.GenerateID("trivy", "AVD-AWS-0086", rel, lineNum)
					if !cfg.ShouldIgnoreFinding(findingID) {
						snippet := strings.TrimSpace(line)
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-AWS-0086",
							Severity:    orchestrator.SeverityHigh,
							CWE:         "CWE-284",
							File:        rel,
							LineStart:   lineNum,
							LineEnd:     lineNum,
							Message:     "S3 bucket configured with public-read ACL exposing data to the public internet",
							Snippet:     snippet,
							OWASP:       "A05:2021-Security Misconfiguration",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-AWS-0086", rel, snippet),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}
			}
		}

		// Docker Compose scanning
		if strings.Contains(base, "compose") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
			contentBytes, err := os.ReadFile(fullPath)
			if err == nil {
				scanner := bufio.NewScanner(bytes.NewReader(contentBytes))
				lineNum := 0
				hasHealthcheck := false
				for scanner.Scan() {
					lineNum++
					line := scanner.Text()

					if strings.Contains(line, "privileged: true") {
						findingID := orchestrator.GenerateID("trivy", "AVD-DCP-0001", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-DCP-0001",
								Severity:    orchestrator.SeverityCritical,
								CWE:         "CWE-250",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Docker Compose service executes in privileged mode, disabling host isolation",
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DCP-0001", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}

					if strings.Contains(line, "0.0.0.0:22:22") || strings.Contains(line, `"22:22"`) {
						findingID := orchestrator.GenerateID("trivy", "AVD-DCP-0002", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-DCP-0002",
								Severity:    orchestrator.SeverityHigh,
								CWE:         "CWE-284",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Docker Compose service exposes SSH port 22 directly to public interface",
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DCP-0002", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}

					if strings.Contains(line, "/var/run/docker.sock") {
						findingID := orchestrator.GenerateID("trivy", "AVD-DCP-0003", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-DCP-0003",
								Severity:    orchestrator.SeverityCritical,
								CWE:         "CWE-250",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Docker daemon socket /var/run/docker.sock mounted into container; enables root container breakout",
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DCP-0003", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}

					if strings.Contains(line, "healthcheck:") {
						hasHealthcheck = true
					}
				}

				if !hasHealthcheck && strings.Contains(string(contentBytes), "services:") {
					findingID := orchestrator.GenerateID("trivy", "AVD-DCP-0004", rel, 1)
					if !cfg.ShouldIgnoreFinding(findingID) {
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-DCP-0004",
							Severity:    orchestrator.SeverityMedium,
							CWE:         "CWE-657",
							File:        rel,
							LineStart:   1,
							LineEnd:     1,
							Message:     "Docker Compose configuration missing healthcheck specification",
							Snippet:     "healthcheck: (missing)",
							OWASP:       "A05:2021-Security Misconfiguration",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-DCP-0004", rel, "missing-healthcheck"),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}
			}
		}

		// Kubernetes & Helm chart scanning
		if (strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")) &&
			(strings.Contains(rel, "k8s") || strings.Contains(rel, "templates") || strings.Contains(content, "apiVersion:")) {
			contentBytes, err := os.ReadFile(fullPath)
			if err == nil {
				scanner := bufio.NewScanner(bytes.NewReader(contentBytes))
				lineNum := 0
				hasResources := false
				for scanner.Scan() {
					lineNum++
					line := scanner.Text()

					if strings.Contains(line, "privileged: true") {
						findingID := orchestrator.GenerateID("trivy", "AVD-KSV-0017", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-KSV-0017",
								Severity:    orchestrator.SeverityCritical,
								CWE:         "CWE-250",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Pod container runs in privileged mode, disabling container isolation barriers",
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-KSV-0017", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}

					if strings.Contains(line, "CAP_SYS_ADMIN") || strings.Contains(line, `"SYS_ADMIN"`) || strings.Contains(line, "SYS_ADMIN") || (strings.Contains(line, "- ALL") && strings.Contains(content, "add:")) {
						findingID := orchestrator.GenerateID("trivy", "AVD-KSV-0005", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-KSV-0005",
								Severity:    orchestrator.SeverityHigh,
								CWE:         "CWE-250",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Dangerous container capability granted (CAP_SYS_ADMIN or ALL)",
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-KSV-0005", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}

					if strings.Contains(line, "readOnlyRootFilesystem: false") {
						findingID := orchestrator.GenerateID("trivy", "AVD-KSV-0014", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-KSV-0014",
								Severity:    orchestrator.SeverityMedium,
								CWE:         "CWE-732",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Container root filesystem is not mounted read-only",
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-KSV-0014", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}

					if strings.Contains(line, "resources:") {
						hasResources = true
					}
				}

				if !hasResources && (strings.Contains(string(contentBytes), "containers:") || strings.Contains(string(contentBytes), "kind: Pod") || strings.Contains(string(contentBytes), "kind: Deployment")) {
					findingID := orchestrator.GenerateID("trivy", "AVD-KSV-0015", rel, 1)
					if !cfg.ShouldIgnoreFinding(findingID) {
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-KSV-0015",
							Severity:    orchestrator.SeverityMedium,
							CWE:         "CWE-400",
							File:        rel,
							LineStart:   1,
							LineEnd:     1,
							Message:     "Container does not specify CPU/memory resource limits",
							Snippet:     "resources: (missing)",
							OWASP:       "A05:2021-Security Misconfiguration",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-KSV-0015", rel, "missing-resources"),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}
			}
		}

		if (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) && strings.Contains(rel, ".github/workflows") {
			contentBytes, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(bytes.NewReader(contentBytes))
			lineNum := 0
			actionRefRegex := regexp.MustCompile(`(?i)^\s*(?:-\s*)?uses:\s*([a-zA-Z0-9_\-\/]+)@([^\s]+)`)
			shaRegex := regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
			untrustedEventRegex := regexp.MustCompile(`(?i)\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit|review|discussion)\.(?:title|body|message|head\.ref|author_association)`)

			for scanner.Scan() {
				lineNum++
				line := scanner.Text()

				// 1. Dangerous pull_request_target
				if strings.Contains(line, "pull_request_target") {
					findingID := orchestrator.GenerateID("trivy", "AVD-GHA-0001", rel, lineNum)
					if !cfg.ShouldIgnoreFinding(findingID) {
						snippet := strings.TrimSpace(line)
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-GHA-0001",
							Severity:    orchestrator.SeverityHigh,
							CWE:         "CWE-284",
							File:        rel,
							LineStart:   lineNum,
							LineEnd:     lineNum,
							Message:     "Workflow uses dangerous 'pull_request_target' trigger; this may expose repository secrets or execute untrusted code from forks",
							Snippet:     snippet,
							OWASP:       "A05:2021-Security Misconfiguration",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-GHA-0001", rel, snippet),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}

				// 2. Overly broad permissions
				if strings.Contains(line, "write-all") {
					findingID := orchestrator.GenerateID("trivy", "AVD-GHA-0003", rel, lineNum)
					if !cfg.ShouldIgnoreFinding(findingID) {
						snippet := strings.TrimSpace(line)
						f := orchestrator.Finding{
							ID:          findingID,
							Source:      "trivy",
							Engine:      orchestrator.EngineEmbedded,
							Category:    orchestrator.CategoryIaC,
							Rule:        "AVD-GHA-0003",
							Severity:    orchestrator.SeverityHigh,
							CWE:         "CWE-732",
							File:        rel,
							LineStart:   lineNum,
							LineEnd:     lineNum,
							Message:     "Overly broad workflow permission 'write-all' detected; enforce least-privilege permissions",
							Snippet:     snippet,
							OWASP:       "A05:2021-Security Misconfiguration",
							FirstSeen:   time.Now().UTC(),
							Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-GHA-0003", rel, snippet),
						}
						f.RiskScore = orchestrator.CalculateRiskScore(&f)
						f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
						findings = append(findings, f)
					}
				}

				// 3. Unpinned GitHub Actions reference
				if m := actionRefRegex.FindStringSubmatch(line); len(m) > 2 {
					actionName := m[1]
					actionRef := m[2]
					// Exclude local action references (./.github/actions/...) and pinned 40-char SHAs
					if !strings.HasPrefix(actionName, ".") && !shaRegex.MatchString(actionRef) {
						findingID := orchestrator.GenerateID("trivy", "AVD-GHA-0002", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-GHA-0002",
								Severity:    orchestrator.SeverityMedium,
								CWE:         "CWE-1357",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     fmt.Sprintf("GitHub Action '%s@%s' is not pinned to a commit SHA; pin to full 40-character SHA to prevent supply-chain tampering", actionName, actionRef),
								Snippet:     snippet,
								OWASP:       "A05:2021-Security Misconfiguration",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-GHA-0002", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}
				}

				// 4. Unsafe use of untrusted event data inside shell commands (Expression Injection)
				if untrustedEventRegex.MatchString(line) {
					trimmed := strings.TrimSpace(line)
					parts := strings.SplitN(trimmed, ":", 2)
					isEnvAssign := false
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						val := strings.TrimSpace(parts[1])
						isIdentifier := true
						for _, r := range key {
							if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
								isIdentifier = false
								break
							}
						}
						if isIdentifier && key != "run" && key != "uses" && strings.HasPrefix(val, "${{") {
							isEnvAssign = true
						}
					}

					if !isEnvAssign {
						findingID := orchestrator.GenerateID("trivy", "AVD-GHA-0004", rel, lineNum)
						if !cfg.ShouldIgnoreFinding(findingID) {
							snippet := strings.TrimSpace(line)
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "trivy",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategoryIaC,
								Rule:        "AVD-GHA-0004",
								Severity:    orchestrator.SeverityCritical,
								CWE:         "CWE-78",
								File:        rel,
								LineStart:   lineNum,
								LineEnd:     lineNum,
								Message:     "Unsafe GitHub Actions expression injection: untrusted event data is interpolated directly into workflow commands; pass through an intermediate environment variable (env: VAR: ${{ ... }}) instead",
								Snippet:     snippet,
								OWASP:       "A03:2021-Injection",
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryIaC, "AVD-GHA-0004", rel, snippet),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}
				}
			}
		}
	}

	return findings, nil
}
