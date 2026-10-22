package osv

import (
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

// OSVAdapter wraps osv-scanner for SCA / dependency vulnerability detection,
// with an embedded lockfile parsing engine for offline or fallback usage.
type OSVAdapter struct{}

func New() *OSVAdapter {
	return &OSVAdapter{}
}

func (a *OSVAdapter) Name() string {
	return "osv"
}

func (a *OSVAdapter) Category() string {
	return orchestrator.CategorySCA
}

func (a *OSVAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	return len(discovery.Lockfiles) > 0 || len(discovery.Manifests) > 0
}

type osvScanOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"source"`
		PackageSource struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"package_source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			License  string   `json:"license,omitempty"`
			Licenses []string `json:"licenses,omitempty"`
			Vulnerabilities []struct {
				ID      string   `json:"id"`
				Summary string   `json:"summary"`
				Details string   `json:"details"`
				Aliases []string `json:"aliases"`
				Severities []struct {
					Type  string `json:"type"`
					Score string `json:"score"`
				} `json:"severity"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

func (a *OSVAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.SCA.Enabled {
		return nil, nil
	}

	binPath, err := exec.LookPath("osv-scanner")
	if err != nil || binPath == "" {
		if cfg.Engine == "external" {
			return nil, fmt.Errorf("osv-scanner executable not found in PATH and engine is configured as 'external'")
		}
		return a.runNativeFallback(repoPath, cfg, discovery)
	}

	return a.runCLI(ctx, binPath, repoPath, cfg, discovery)
}

func (a *OSVAdapter) runCLI(ctx context.Context, binPath, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	toolRes, err := adapters.RunTool(ctx, binPath, "--format", "json", "-r", repoPath)
	if err != nil {
		return nil, fmt.Errorf("osv-scanner failed to execute: %w", err)
	}

	// OSV-scanner returns 0 for clean, 1 when vulnerabilities are identified. 2+ is error.
	if toolRes.ExitCode >= 2 {
		errLine := strings.TrimSpace(string(toolRes.Stderr))
		return nil, fmt.Errorf("osv-scanner exited with error %d: %s", toolRes.ExitCode, errLine)
	}

	return a.ParseOutput(toolRes.Stdout, repoPath, cfg)
}

// ParseOutput parses raw JSON output from osv-scanner and creates normalized findings.
func (a *OSVAdapter) ParseOutput(data []byte, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	var report osvScanOutput
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse osv-scanner JSON output: %w", err)
	}

	var findings []orchestrator.Finding
	for _, res := range report.Results {
		srcPath := res.Source.Path
		if srcPath == "" {
			srcPath = res.PackageSource.Path
		}
		relFile, _ := filepath.Rel(repoPath, srcPath)
		if relFile == "" || relFile == "." {
			relFile = srcPath
		}
		relFile = filepath.ToSlash(relFile)

		if cfg.ShouldIgnorePath(relFile) {
			continue
		}

		for _, pkg := range res.Packages {
			pkgLicense := pkg.License
			if pkgLicense == "" && len(pkg.Licenses) > 0 {
				pkgLicense = strings.Join(pkg.Licenses, ", ")
			}

			// Check license compliance against fail_on_license
			if isDisallowedLicense(pkgLicense, cfg.Scanners.SCA.FailOnLicense) {
				licID := orchestrator.GenerateID("license", pkgLicense, relFile, 1)
				if !cfg.ShouldIgnoreFinding(licID) {
					lf := orchestrator.Finding{
						ID:          licID,
						Source:      "osv",
						Engine:      orchestrator.EngineExternal,
						Category:    orchestrator.CategorySCA,
						Rule:        "license/" + pkgLicense,
						Severity:    orchestrator.SeverityHigh,
						License:     pkgLicense,
						File:        relFile,
						LineStart:   1,
						LineEnd:     1,
						Message:     fmt.Sprintf("Dependency %s uses forbidden license %q (configured in scanners.sca.fail_on_license)", pkg.Package.Name, pkgLicense),
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "license", relFile, pkg.Package.Name),
					}
					lf.RiskScore = orchestrator.CalculateRiskScore(&lf)
					findings = append(findings, lf)
				}
			}

			for _, vuln := range pkg.Vulnerabilities {
				cve := vuln.ID
				for _, alias := range vuln.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cve = alias
						break
					}
				}

				sev := orchestrator.SeverityHigh
				cvss := 7.5

				// Check reachability with heuristic label
				reachable := a.checkReachability(pkg.Package.Name, repoPath)

				findingID := orchestrator.GenerateID("osv", cve, relFile, 1)
				if cfg.ShouldIgnoreFinding(findingID) {
					continue
				}

				msg := vuln.Summary
				if msg == "" {
					msg = fmt.Sprintf("Vulnerable dependency %s@%s has advisory %s [Reachability: heuristic]", pkg.Package.Name, pkg.Package.Version, cve)
				} else {
					msg = fmt.Sprintf("%s [Reachability: heuristic]", msg)
				}

				f := orchestrator.Finding{
					ID:          findingID,
					Source:      "osv",
					Engine:      orchestrator.EngineExternal,
					Category:    orchestrator.CategorySCA,
					Rule:        cve,
					Severity:    sev,
					CVE:         cve,
					CVSS:        cvss,
					License:     pkgLicense,
					File:        relFile,
					LineStart:   1,
					LineEnd:     1,
					Message:     msg,
					Reachable:   &reachable,
					FirstSeen:   time.Now().UTC(),
					Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, cve, relFile, pkg.Package.Name),
				}
				f.RiskScore = orchestrator.CalculateRiskScore(&f)
				f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

type knownVuln struct {
	Ecosystem   string
	Package     string
	Vulnerable  string // regex pattern
	FixedVer    string
	CVE         string
	Severity    string
	CVSS        float64
	License     string
	Description string
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

func (a *OSVAdapter) runNativeFallback(repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	vulnDB := []knownVuln{
		{
			Ecosystem:   "npm",
			Package:     "lodash",
			Vulnerable:  `^4\.(?:17\.(?:[0-9]|1[0-9]|20))$`,
			FixedVer:    "4.17.21",
			CVE:         "CVE-2021-23337",
			Severity:    orchestrator.SeverityHigh,
			CVSS:        7.2,
			License:     "MIT",
			Description: "Command Injection via template in lodash",
		},
		{
			Ecosystem:   "npm",
			Package:     "axios",
			Vulnerable:  `^0\.(?:[0-9]|1[0-9]|2[01])\.[0-9]+$`,
			FixedVer:    "0.21.2",
			CVE:         "CVE-2020-28168",
			Severity:    orchestrator.SeverityMedium,
			CVSS:        5.9,
			License:     "MIT",
			Description: "Server-Side Request Forgery (SSRF) bypass in axios",
		},
		{
			Ecosystem:   "npm",
			Package:     "express",
			Vulnerable:  `^4\.(?:[0-9]|1[0-8])\.[0-9]+$`,
			FixedVer:    "4.19.2",
			CVE:         "CVE-2024-29041",
			Severity:    orchestrator.SeverityMedium,
			CVSS:        6.5,
			License:     "MIT",
			Description: "Open redirect vulnerability in express router",
		},
		{
			Ecosystem:   "pypi",
			Package:     "requests",
			Vulnerable:  `^2\.(?:[0-9]|1[0-9]|2[0-9]|30)\.[0-9]+$`,
			FixedVer:    "2.31.0",
			CVE:         "CVE-2023-32681",
			Severity:    orchestrator.SeverityMedium,
			CVSS:        6.1,
			License:     "Apache-2.0",
			Description: "Unintended leak of Proxy-Authorization headers in requests",
		},
		{
			Ecosystem:   "pypi",
			Package:     "urllib3",
			Vulnerable:  `^1\.26\.(?:[0-9]|1[0-8])$`,
			FixedVer:    "1.26.19",
			CVE:         "CVE-2024-37891",
			Severity:    orchestrator.SeverityHigh,
			CVSS:        7.5,
			License:     "MIT",
			Description: "Proxy-Authorization header leak on cross-origin redirects in urllib3",
		},
		{
			Ecosystem:   "golang",
			Package:     "golang.org/x/crypto",
			Vulnerable:  `v0\.0\.0-2020[0-9]+`,
			FixedVer:    "v0.31.0",
			CVE:         "CVE-2020-29652",
			Severity:    orchestrator.SeverityHigh,
			CVSS:        7.5,
			License:     "BSD-3-Clause",
			Description: "Panic in SSH server when receiving malformed packet in golang.org/x/crypto",
		},
	}

	var findings []orchestrator.Finding

	for _, manifest := range discovery.Manifests {
		if cfg.ShouldIgnorePath(manifest) {
			continue
		}
		base := strings.ToLower(filepath.Base(manifest))
		fullPath := filepath.Join(repoPath, manifest)
		contentBytes, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}
		content := string(contentBytes)
		lines := strings.Split(content, "\n")

		// Basic supply-chain checks: unpinned versions and typosquatting
		var knownTyposquats = map[string]string{
			"lodas-h":  "lodash",
			"lodashs":  "lodash",
			"requsts":  "requests",
			"reqeusts": "requests",
			"expresss": "express",
			"crossenv": "cross-env",
			"collor":   "colors",
		}

		depRegex := regexp.MustCompile(`"([^"]+)"\s*:\s*"([^"]+)"`)
		if base == "package.json" {
			for idx, line := range lines {
				if m := depRegex.FindStringSubmatch(line); len(m) > 2 {
					pkgName := strings.TrimSpace(m[1])
					ver := strings.TrimSpace(m[2])
					if pkgName == "dependencies" || pkgName == "devDependencies" || pkgName == "name" || pkgName == "version" || pkgName == "scripts" {
						continue
					}

					// Typosquatting check
					if target, isTyposquat := knownTyposquats[strings.ToLower(pkgName)]; isTyposquat {
						fID := orchestrator.GenerateID("osv", "SUPPLY-CHAIN-TYPOSQUAT", manifest, idx+1)
						if !cfg.ShouldIgnoreFinding(fID) {
							f := orchestrator.Finding{
								ID:          fID,
								Source:      "osv",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategorySCA,
								Rule:        "SUPPLY-CHAIN-TYPOSQUAT",
								Severity:    orchestrator.SeverityHigh,
								CWE:         "CWE-1357",
								File:        manifest,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("Dependency %q closely resembles popular package %q (potential typosquatting supply-chain attack)", pkgName, target),
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "SUPPLY-CHAIN-TYPOSQUAT", manifest, pkgName),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							findings = append(findings, f)
						}
					}

					// Unpinned check
					if ver == "*" || ver == "latest" || strings.HasPrefix(ver, ">") {
						fID := orchestrator.GenerateID("osv", "SUPPLY-CHAIN-UNPINNED", manifest, idx+1)
						if !cfg.ShouldIgnoreFinding(fID) {
							f := orchestrator.Finding{
								ID:          fID,
								Source:      "osv",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategorySCA,
								Rule:        "SUPPLY-CHAIN-UNPINNED",
								Severity:    orchestrator.SeverityMedium,
								CWE:         "CWE-1104",
								File:        manifest,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("Dependency %q uses unpinned or wildcard version %q; pin to an exact or bounded semver range", pkgName, ver),
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "SUPPLY-CHAIN-UNPINNED", manifest, pkgName),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							findings = append(findings, f)
						}
					}
				}
			}
		} else if base == "requirements.txt" {
			reqLineRegex := regexp.MustCompile(`^\s*([a-zA-Z0-9_\-\.]+)\s*([^\s#]*)`)
			for idx, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if m := reqLineRegex.FindStringSubmatch(trimmed); len(m) > 1 {
					pkgName := m[1]
					spec := ""
					if len(m) > 2 {
						spec = m[2]
					}

					// Typosquatting check
					if target, isTyposquat := knownTyposquats[strings.ToLower(pkgName)]; isTyposquat {
						fID := orchestrator.GenerateID("osv", "SUPPLY-CHAIN-TYPOSQUAT", manifest, idx+1)
						if !cfg.ShouldIgnoreFinding(fID) {
							f := orchestrator.Finding{
								ID:          fID,
								Source:      "osv",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategorySCA,
								Rule:        "SUPPLY-CHAIN-TYPOSQUAT",
								Severity:    orchestrator.SeverityHigh,
								CWE:         "CWE-1357",
								File:        manifest,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("Python package %q closely resembles popular package %q (potential typosquatting supply-chain attack)", pkgName, target),
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "SUPPLY-CHAIN-TYPOSQUAT", manifest, pkgName),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							findings = append(findings, f)
						}
					}

					// Unpinned check
					if spec == "" || !strings.Contains(spec, "==") {
						fID := orchestrator.GenerateID("osv", "SUPPLY-CHAIN-UNPINNED", manifest, idx+1)
						if !cfg.ShouldIgnoreFinding(fID) {
							f := orchestrator.Finding{
								ID:          fID,
								Source:      "osv",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategorySCA,
								Rule:        "SUPPLY-CHAIN-UNPINNED",
								Severity:    orchestrator.SeverityMedium,
								CWE:         "CWE-1104",
								File:        manifest,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("Python package %q is unpinned (%q); pin to an exact version using ==", pkgName, trimmed),
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "SUPPLY-CHAIN-UNPINNED", manifest, pkgName),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							findings = append(findings, f)
						}
					}
				}
			}
		}

		for _, dbEntry := range vulnDB {
			switch base {
			case "package.json":
				if dbEntry.Ecosystem != "npm" {
					continue
				}
				re := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*["\^~]?([^"]+)["']`, regexp.QuoteMeta(dbEntry.Package)))
				for idx, line := range lines {
					if match := re.FindStringSubmatch(line); len(match) > 1 {
						ver := match[1]

						// Check license policy
						if isDisallowedLicense(dbEntry.License, cfg.Scanners.SCA.FailOnLicense) {
							licID := orchestrator.GenerateID("license", dbEntry.License, manifest, idx+1)
							if !cfg.ShouldIgnoreFinding(licID) {
								lf := orchestrator.Finding{
									ID:          licID,
									Source:      "osv",
									Engine:      orchestrator.EngineEmbedded,
									Category:    orchestrator.CategorySCA,
									Rule:        "license/" + dbEntry.License,
									Severity:    orchestrator.SeverityHigh,
									License:     dbEntry.License,
									File:        manifest,
									LineStart:   idx + 1,
									LineEnd:     idx + 1,
									Message:     fmt.Sprintf("Dependency %s uses forbidden license %q (configured in scanners.sca.fail_on_license)", dbEntry.Package, dbEntry.License),
									FirstSeen:   time.Now().UTC(),
									Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "license", manifest, dbEntry.Package),
								}
								lf.RiskScore = orchestrator.CalculateRiskScore(&lf)
								findings = append(findings, lf)
							}
						}

						checkRe := regexp.MustCompile(dbEntry.Vulnerable)
						if checkRe.MatchString(ver) {
							reachable := a.checkReachability(dbEntry.Package, repoPath)
							findingID := orchestrator.GenerateID("osv", dbEntry.CVE, manifest, idx+1)
							if cfg.ShouldIgnoreFinding(findingID) {
								continue
							}
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "osv",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategorySCA,
								Rule:        dbEntry.CVE,
								Severity:    dbEntry.Severity,
								CVE:         dbEntry.CVE,
								CVSS:        dbEntry.CVSS,
								License:     dbEntry.License,
								File:        manifest,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("%s (%s@%s) - Upgrade package to %s [Reachability: heuristic] [Embedded Lite Engine: install osv-scanner for full advisory coverage]", dbEntry.Description, dbEntry.Package, ver, dbEntry.FixedVer),
								Reachable:   &reachable,
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, dbEntry.CVE, manifest, dbEntry.Package),
							}
							f.RiskScore = orchestrator.CalculateRiskScore(&f)
							f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
							findings = append(findings, f)
						}
					}
				}

			case "requirements.txt":
				if dbEntry.Ecosystem != "pypi" {
					continue
				}
				re := regexp.MustCompile(fmt.Sprintf(`(?i)^%s\s*==\s*([^\s]+)`, regexp.QuoteMeta(dbEntry.Package)))
				for idx, line := range lines {
					if match := re.FindStringSubmatch(line); len(match) > 1 {
						ver := match[1]

						// Check license policy
						if isDisallowedLicense(dbEntry.License, cfg.Scanners.SCA.FailOnLicense) {
							licID := orchestrator.GenerateID("license", dbEntry.License, manifest, idx+1)
							if !cfg.ShouldIgnoreFinding(licID) {
								lf := orchestrator.Finding{
									ID:          licID,
									Source:      "osv",
									Engine:      orchestrator.EngineEmbedded,
									Category:    orchestrator.CategorySCA,
									Rule:        "license/" + dbEntry.License,
									Severity:    orchestrator.SeverityHigh,
									License:     dbEntry.License,
									File:        manifest,
									LineStart:   idx + 1,
									LineEnd:     idx + 1,
									Message:     fmt.Sprintf("Dependency %s uses forbidden license %q (configured in scanners.sca.fail_on_license)", dbEntry.Package, dbEntry.License),
									FirstSeen:   time.Now().UTC(),
									Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, "license", manifest, dbEntry.Package),
								}
								lf.RiskScore = orchestrator.CalculateRiskScore(&lf)
								findings = append(findings, lf)
							}
						}

						checkRe := regexp.MustCompile(dbEntry.Vulnerable)
						if checkRe.MatchString(ver) {
							reachable := a.checkReachability(dbEntry.Package, repoPath)
							findingID := orchestrator.GenerateID("osv", dbEntry.CVE, manifest, idx+1)
							if cfg.ShouldIgnoreFinding(findingID) {
								continue
							}
							f := orchestrator.Finding{
								ID:          findingID,
								Source:      "osv",
								Engine:      orchestrator.EngineEmbedded,
								Category:    orchestrator.CategorySCA,
								Rule:        dbEntry.CVE,
								Severity:    dbEntry.Severity,
								CVE:         dbEntry.CVE,
								CVSS:        dbEntry.CVSS,
								License:     dbEntry.License,
								File:        manifest,
								LineStart:   idx + 1,
								LineEnd:     idx + 1,
								Message:     fmt.Sprintf("%s (%s==%s) - Upgrade package to %s [Reachability: heuristic] [Embedded Lite Engine: install osv-scanner for full advisory coverage]", dbEntry.Description, dbEntry.Package, ver, dbEntry.FixedVer),
								Reachable:   &reachable,
								FirstSeen:   time.Now().UTC(),
								Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySCA, dbEntry.CVE, manifest, dbEntry.Package),
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

func (a *OSVAdapter) checkReachability(pkgName, repoPath string) bool {
	if pkgName == "" {
		return false
	}
	found := false
	_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || found {
			return nil
		}
		if info.IsDir() {
			base := info.Name()
			if base == "node_modules" || base == ".git" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".js" || ext == ".ts" || ext == ".py" || ext == ".go" {
			data, err := os.ReadFile(path)
			if err == nil && strings.Contains(string(data), pkgName) {
				found = true
			}
		}
		return nil
	})
	return found
}
