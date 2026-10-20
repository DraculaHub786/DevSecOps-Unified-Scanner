package resilience

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// ResilienceAdapter conducts static posture checks for denial-of-service resilience,
// timeout hygiene, rate-limiting presence, and unbounded memory consumption risks.
type ResilienceAdapter struct{}

func New() *ResilienceAdapter {
	return &ResilienceAdapter{}
}

func (a *ResilienceAdapter) Name() string {
	return "resilience"
}

func (a *ResilienceAdapter) Category() string {
	return orchestrator.CategoryResilience
}

func (a *ResilienceAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	return len(discovery.Languages) > 0
}

type resilienceRule struct {
	ID          string
	Severity    string
	CWE         string
	Description string
	Pattern     *regexp.Regexp
	Exts        []string
}

func (a *ResilienceAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	if !cfg.Scanners.Resilience.Enabled {
		return nil, nil
	}

	rules := []resilienceRule{
		{
			ID:          "resilience-unbounded-body-read",
			Severity:    orchestrator.SeverityHigh,
			CWE:         "CWE-400", // Uncontrolled Resource Consumption
			Description: "Unbounded HTTP body read: reading r.Body or request stream without http.MaxBytesReader can lead to server memory exhaustion (DoS)",
			Pattern:     regexp.MustCompile(`(?i)(?:io\.ReadAll|ioutil\.ReadAll)\s*\(\s*(?:r\.Body|req\.Body)\s*\)`),
			Exts:        []string{".go"},
		},
		{
			ID:          "resilience-missing-server-timeout",
			Severity:    orchestrator.SeverityMedium,
			CWE:         "CWE-400",
			Description: "Use of default http.ListenAndServe / http.ListenAndServeTLS without ReadTimeout and WriteTimeout exposes the service to Slowloris attacks",
			Pattern:     regexp.MustCompile(`(?i)http\.ListenAndServe(?:TLS)?\s*\(`),
			Exts:        []string{".go"},
		},
		{
			ID:          "resilience-missing-request-size-limit",
			Severity:    orchestrator.SeverityMedium,
			CWE:         "CWE-770", // Allocation of Resources Without Limits or Throttling
			Description: "Express bodyParser / express.json() used without explicit 'limit' option; default allow large payloads",
			Pattern:     regexp.MustCompile(`(?i)(?:bodyParser\.json|express\.json|bodyParser\.urlencoded)\s*\(\s*\)`),
			Exts:        []string{".js", ".ts"},
		},
		{
			ID:          "resilience-unbounded-regex-redos",
			Severity:    orchestrator.SeverityMedium,
			CWE:         "CWE-1333", // Inefficient Regular Expression Complexity (ReDoS)
			Description: "Potentially vulnerable catastrophic backtracking regex pattern detected with nested quantifiers",
			Pattern:     regexp.MustCompile(`\([a-zA-Z0-9_\.\*\+\?]+\+[\*\+]+\)`),
			Exts:        []string{".js", ".ts", ".py", ".go"},
		},
	}

	var findings []orchestrator.Finding
	hasHTTPRoutes := false
	hasRateLimiter := false

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

			// Check rate limiter presence heuristic
			if strings.Contains(line, "express-rate-limit") ||
				strings.Contains(line, "tollbooth") ||
				strings.Contains(line, "rate.NewLimiter") ||
				strings.Contains(line, "flask_limiter") ||
				strings.Contains(line, "slowapi") {
				hasRateLimiter = true
			}

			// Check HTTP routes presence
			if strings.Contains(line, "http.HandleFunc") ||
				strings.Contains(line, "app.get(") ||
				strings.Contains(line, "app.post(") ||
				strings.Contains(line, "@app.route(") ||
				strings.Contains(line, "router.") {
				hasHTTPRoutes = true
			}

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
					findingID := orchestrator.GenerateID("resilience", r.ID, rel, lineNum)
					if cfg.ShouldIgnoreFinding(findingID) {
						continue
					}

					f := orchestrator.Finding{
						ID:          findingID,
						Source:      "resilience",
						Engine:      orchestrator.EngineEmbedded,
						Category:    orchestrator.CategoryResilience,
						Rule:        r.ID,
						Severity:    r.Severity,
						CWE:         r.CWE,
						CVSS:        6.5,
						File:        rel,
						LineStart:   lineNum,
						LineEnd:     lineNum,
						Message:     r.Description,
						FirstSeen:   time.Now().UTC(),
						Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryResilience, r.ID, rel, line),
					}
					f.RiskScore = orchestrator.CalculateRiskScore(&f)
					f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
					findings = append(findings, f)
				}
			}
		}

		return nil
	})

	// If the repo exposes HTTP routes but has zero rate-limiting middleware configured
	if hasHTTPRoutes && !hasRateLimiter {
		id := orchestrator.GenerateID("resilience", "missing-rate-limiter", "server", 1)
		if !cfg.ShouldIgnoreFinding(id) {
			f := orchestrator.Finding{
				ID:          id,
				Source:      "resilience",
				Engine:      orchestrator.EngineEmbedded,
				Category:    orchestrator.CategoryResilience,
				Rule:        "missing-rate-limiter",
				Severity:    orchestrator.SeverityMedium,
				CWE:         "CWE-770",
				CVSS:        5.3,
				File:        "server",
				LineStart:   1,
				LineEnd:     1,
				Message:     "HTTP service endpoints detected without visible rate-limiting middleware (e.g. tollbooth, express-rate-limit, slowapi)",
				FirstSeen:   time.Now().UTC(),
				Fingerprint: orchestrator.GenerateFingerprint(orchestrator.CategoryResilience, "missing-rate-limiter", "server", "ratelimit"),
			}
			f.RiskScore = orchestrator.CalculateRiskScore(&f)
			f.FixSuggestion = orchestrator.GenerateRemediation(repoPath, &f)
			findings = append(findings, f)
		}
	}

	return findings, err
}
