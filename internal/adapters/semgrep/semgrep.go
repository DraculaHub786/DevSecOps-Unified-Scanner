package semgrep

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

// SemgrepAdapter executes Semgrep for static application security testing (SAST),
// with an embedded AST/pattern inspection engine when Semgrep is not installed.
type SemgrepAdapter struct{}

func New() *SemgrepAdapter {
	return &SemgrepAdapter{}
}

func (a *SemgrepAdapter) Name() string {
	return "semgrep"
}

func (a *SemgrepAdapter) Category() string {
	return orchestrator.CategorySAST
}

func (a *SemgrepAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	return len(discovery.Languages) > 0
}

type semgrepOutput struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
			Col  int `json:"col"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				CWE  interface{} `json:"cwe"`
				CVSS float64     `json:"cvss"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func (a *SemgrepAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.SAST.Enabled {
		return nil, nil
	}

	binPath, err := exec.LookPath("semgrep")
	if err != nil || binPath == "" {
		if cfg.Engine == "external" {
			return nil, fmt.Errorf("semgrep executable not found in PATH and engine is configured as 'external'")
		}
		return a.runNativeFallback(repoPath, cfg)
	}

	return a.runCLI(ctx, binPath, repoPath, cfg)
}

func (a *SemgrepAdapter) runCLI(ctx context.Context, binPath, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	args := []string{"scan", "--json", "--quiet", "--metrics=off"}

	if cfg.Scanners.SAST.Ruleset != "" && cfg.Scanners.SAST.Ruleset != "auto" {
		args = append(args, "--config", cfg.Scanners.SAST.Ruleset)
	} else {
		// Use local rules if available or auto
		localRules := filepath.Join(repoPath, "rules")
		if fi, err := os.Stat(localRules); err == nil && fi.IsDir() {
			args = append(args, "--config", localRules)
		} else {
			args = append(args, "--config", "auto")
		}
	}

	for _, extraRule := range cfg.Scanners.SAST.ExtraRules {
		fullRulePath := filepath.Join(repoPath, extraRule)
		if _, err := os.Stat(fullRulePath); err == nil {
			args = append(args, "--config", fullRulePath)
		}
	}

	args = append(args, repoPath)

	toolRes, err := adapters.RunTool(ctx, binPath, args...)
	if err != nil {
		return nil, fmt.Errorf("semgrep failed to execute: %w", err)
	}

	// Exit code 0 (clean) and exit code 1 (findings found) are standard. 2+ is a runtime error.
	if toolRes.ExitCode >= 2 {
		errLine := strings.TrimSpace(string(toolRes.Stderr))
		if len(errLine) > 120 {
			errLine = errLine[:117] + "..."
		}
		return nil, fmt.Errorf("semgrep exited with error code %d: %s", toolRes.ExitCode, errLine)
	}

	return ParseOutput(toolRes.Stdout, repoPath, cfg)
}

// ParseOutput parses raw JSON from Semgrep and maps it into normalized findings.
func ParseOutput(data []byte, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	var report semgrepOutput
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep JSON output: %w", err)
	}

	findings := make([]orchestrator.Finding, 0, len(report.Results))
	for _, res := range report.Results {
		relFile, _ := filepath.Rel(repoPath, res.Path)
		if relFile == "" {
			relFile = res.Path
		}
		relFile = filepath.ToSlash(relFile)

		if cfg.ShouldIgnorePath(relFile) {
			continue
		}

		findingID := orchestrator.GenerateID("semgrep", res.CheckID, relFile, res.Start.Line)
		if cfg.ShouldIgnoreFinding(findingID) {
			continue
		}

		sev := orchestrator.SeverityMedium
		switch strings.ToUpper(res.Extra.Severity) {
		case "ERROR":
			sev = orchestrator.SeverityHigh
		case "WARNING":
			sev = orchestrator.SeverityMedium
		case "INFO":
			sev = orchestrator.SeverityLow
		}

		cweStr := "CWE-20"
		if res.Extra.Metadata.CWE != nil {
			cweStr = fmt.Sprintf("%v", res.Extra.Metadata.CWE)
		}

		f := orchestrator.Finding{
			ID:          findingID,
			Source:      "semgrep",
			Engine:      orchestrator.EngineExternal,
			Category:    orchestrator.CategorySAST,
			Rule:        res.CheckID,
			Severity:    sev,
			CWE:         cweStr,
			CVSS:        res.Extra.Metadata.CVSS,
			File:        relFile,
			LineStart:   res.Start.Line,
			LineEnd:     res.End.Line,
			Message:     res.Extra.Message,
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySAST, res.CheckID, relFile, res.Extra.Message),
		}
		f.RiskScore = orchestrator.CalculateRiskScore(&f)
		f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
		findings = append(findings, f)
	}

	return findings, nil
}

type sastRule struct {
	ID       string
	Severity string
	CWE      string
	Message  string
	Pattern  *regexp.Regexp
	Exts     []string
}

func (a *SemgrepAdapter) runNativeFallback(repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	rules := []sastRule{
		{
			ID:       "sast-sql-injection-concat",
			Severity: orchestrator.SeverityHigh,
			CWE:      "CWE-89",
			Message:  "Potential SQL Injection: detected dynamic string concatenation or formatting inside database query call",
			Pattern:  regexp.MustCompile(`(?i)(?:db\.(?:Query|Exec|QueryRow|Raw)|cursor\.execute)\s*\(\s*(?:fmt\.Sprintf|["'].*\+.*["']|` + "`" + `.*\$` + "`" + `)`),
			Exts:     []string{".go", ".js", ".ts", ".py"},
		},
		{
			ID:       "sast-command-injection",
			Severity: orchestrator.SeverityCritical,
			CWE:      "CWE-78",
			Message:  "Potential Command Injection: subprocess or shell execution invoked with unescaped variable",
			Pattern:  regexp.MustCompile(`(?i)(?:exec\.Command|os\.system|child_process\.exec|subprocess\.Popen|subprocess\.call)\s*\([^"'\)]+`),
			Exts:     []string{".go", ".js", ".ts", ".py"},
		},
		{
			ID:       "sast-tls-skip-verify",
			Severity: orchestrator.SeverityHigh,
			CWE:      "CWE-295",
			Message:  "Disabled TLS certificate validation detected (InsecureSkipVerify: true / rejectUnauthorized: false)",
			Pattern:  regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false|verify\s*=\s*False)`),
			Exts:     []string{".go", ".js", ".ts", ".py"},
		},
		{
			ID:       "sast-insecure-eval",
			Severity: orchestrator.SeverityCritical,
			CWE:      "CWE-95",
			Message:  "Use of eval() or dynamic code execution on variable input",
			Pattern:  regexp.MustCompile(`(?i)\beval\s*\([a-zA-Z0-9_\$]+\)`),
			Exts:     []string{".js", ".ts", ".py"},
		},
		{
			ID:       "sast-path-traversal",
			Severity: orchestrator.SeverityHigh,
			CWE:      "CWE-22",
			Message:  "Potential Path Traversal: user input directly used in filesystem path without filepath.Clean or boundary check",
			Pattern:  regexp.MustCompile(`(?i)(?:os\.Open|ioutil\.ReadFile|fs\.readFile|open)\s*\(\s*(?:req\.|r\.URL|request\.|param|filename)`),
			Exts:     []string{".go", ".js", ".ts", ".py"},
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

		ext := strings.ToLower(filepath.Ext(path))

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
				extMatch := false
				for _, e := range r.Exts {
					if e == ext {
						extMatch = true
						break
					}
				}
				if !extMatch {
					continue
				}

				if r.Pattern.MatchString(line) {
					findingID := orchestrator.GenerateID("semgrep", r.ID, rel, lineNum)
					if cfg.ShouldIgnoreFinding(findingID) {
						continue
					}

					f := orchestrator.Finding{
						ID:          findingID,
						Source:      "semgrep",
						Engine:      orchestrator.EngineEmbedded,
						Category:    orchestrator.CategorySAST,
						Rule:        r.ID,
						Severity:    r.Severity,
						CWE:         r.CWE,
						CVSS:        7.8,
						File:        rel,
						LineStart:   lineNum,
						LineEnd:     lineNum,
						Message:     fmt.Sprintf("%s: %s", r.Message, strings.TrimSpace(line)),
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySAST, r.ID, rel, line),
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
