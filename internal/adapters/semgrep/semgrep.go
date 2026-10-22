package semgrep

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/rules"
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
			Lines    string `json:"lines"`
			Metadata struct {
				CWE        interface{} `json:"cwe"`
				OWASP      interface{} `json:"owasp"`
				Category   string      `json:"category"`
				Confidence string      `json:"confidence"`
				CVSS       float64     `json:"cvss"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []struct {
		Level   string `json:"level"`
		Message string `json:"message"`
		Path    string `json:"path"`
	} `json:"errors"`
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

// resolveRulesConfig returns the Semgrep config to use. Sentinel's bundled rules are
// always extracted from the binary; a rules/ directory inside the scanned repository
// (or the working directory) is never trusted as configuration. An explicit ruleset
// (a registry pack or a path the user chose) replaces the bundle.
func resolveRulesConfig(repoPath string, cfg *config.Config) (string, func(), error) {
	if rs := cfg.Scanners.SAST.Ruleset; rs != "" && rs != "auto" {
		return rs, nil, nil
	}
	tmpDir, err := os.MkdirTemp("", "sentinel-rules-*")
	if err != nil {
		return "", nil, fmt.Errorf("cannot create rules directory: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }
	entries, err := rules.Content.ReadDir(".")
	if err != nil {
		cleanup()
		return "", nil, err
	}
	for _, entry := range entries {
		// resilience-*.yml belongs to the resilience adapter; running it here would
		// report every resilience issue twice.
		if entry.IsDir() || strings.HasPrefix(entry.Name(), "resilience") {
			continue
		}
		data, err := rules.Content.ReadFile(entry.Name())
		if err != nil {
			cleanup()
			return "", nil, err
		}
		if err := os.WriteFile(filepath.Join(tmpDir, entry.Name()), data, 0600); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return tmpDir, cleanup, nil
}

// confinedPath resolves rel inside root and reports false if the result (after
// following symlinks) escapes root.
func confinedPath(root, rel string) (string, bool) {
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	full, err := filepath.EvalSymlinks(filepath.Join(root, rel))
	if err != nil {
		return "", false
	}
	r, err := filepath.Rel(rootReal, full)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", false
	}
	return full, true
}

// registryReachable is a quick probe so an offline or firewalled run does not wait
// for the full adapter timeout.
func registryReachable() bool {
	conn, err := net.DialTimeout("tcp", "semgrep.dev:443", 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Semgrep prefixes rule IDs with the directory of the config file. Bundled rules are
// extracted to a random temp dir, so strip that prefix to keep rule IDs (and the
// fingerprints, baselines and suppressions built from them) stable between runs.
var tempRulesPrefix = regexp.MustCompile(`^.*sentinel-rules-\d+\.`)

func normalizeRuleID(id string) string { return tempRulesPrefix.ReplaceAllString(id, "") }

func (a *SemgrepAdapter) runCLI(ctx context.Context, binPath, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	// --disable-version-check stops Semgrep phoning home (and stalling when offline).
	args := []string{"scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"}

	ruleTarget, cleanupRules, err := resolveRulesConfig(repoPath, cfg)
	if err != nil {
		return nil, fmt.Errorf("semgrep rules: %w", err)
	}
	if cleanupRules != nil {
		defer cleanupRules()
	}
	args = append(args, "--config", ruleTarget)

	// "--config auto" cannot be combined with --metrics=off (Semgrep exits 2), so add the
	// registry's default pack explicitly, only when online and reachable.
	if rs := cfg.Scanners.SAST.Ruleset; (rs == "" || rs == "auto") && !cfg.Offline {
		if registryReachable() {
			args = append(args, "--config", "p/default")
		} else {
			fmt.Fprintln(os.Stderr, "semgrep: registry unreachable, running bundled rules only")
		}
	}

	for _, extraRule := range cfg.Scanners.SAST.ExtraRules {
		fullRulePath, ok := confinedPath(repoPath, extraRule)
		if !ok {
			fmt.Fprintf(os.Stderr, "semgrep: ignoring extra rule %q (missing or outside the repository)\n", extraRule)
			continue
		}
		args = append(args, "--config", fullRulePath)
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

	var rawReport semgrepOutput
	if err := json.Unmarshal(toolRes.Stdout, &rawReport); err == nil && len(rawReport.Errors) > 0 {
		var parseErrs []string
		for _, e := range rawReport.Errors {
			if strings.ToLower(e.Level) == "error" {
				parseErrs = append(parseErrs, fmt.Sprintf("%s: %s", e.Path, e.Message))
			}
		}
		findings, pErr := ParseOutput(toolRes.Stdout, repoPath, cfg)
		if pErr != nil {
			return nil, pErr
		}
		if len(parseErrs) > 0 {
			return findings, fmt.Errorf("%w: %s", orchestrator.ErrPartial, strings.Join(parseErrs, "; "))
		}
		return findings, nil
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

		res.CheckID = normalizeRuleID(res.CheckID)
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

		owaspStr := ""
		if res.Extra.Metadata.OWASP != nil {
			owaspStr = fmt.Sprintf("%v", res.Extra.Metadata.OWASP)
		}

		category := orchestrator.CategorySAST
		if strings.ToLower(res.Extra.Metadata.Category) == "secret" {
			category = orchestrator.CategorySecret
		}

		snippet := strings.TrimSpace(res.Extra.Lines)
		if snippet == "requires login" {
			snippet = ""
		}
		if category == orchestrator.CategorySecret {
			snippet = "[REDACTED_SECRET]"
		}

		f := orchestrator.Finding{
			ID:          findingID,
			Source:      "semgrep",
			Engine:      orchestrator.EngineExternal,
			Category:    category,
			Rule:        res.CheckID,
			Severity:    sev,
			CWE:         cweStr,
			OWASP:       owaspStr,
			CVSS:        res.Extra.Metadata.CVSS,
			File:        relFile,
			LineStart:   res.Start.Line,
			LineEnd:     res.End.Line,
			Message:     res.Extra.Message,
			Snippet:     snippet,
			FirstSeen:   time.Now().UTC(),
			Fingerprint: orchestrator.GenerateFingerprint(category, res.CheckID, relFile, snippet),
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
						OWASP:       "A03:2021-Injection",
						CVSS:        7.8,
						File:        rel,
						LineStart:   lineNum,
						LineEnd:     lineNum,
						Message:     fmt.Sprintf("%s: %s", r.Message, strings.TrimSpace(line)),
						Snippet:     strings.TrimSpace(line),
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategorySAST, r.ID, rel, strings.TrimSpace(line)),
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
