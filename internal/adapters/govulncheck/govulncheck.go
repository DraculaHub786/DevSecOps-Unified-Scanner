package govulncheck

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// GovulncheckAdapter wraps the official Go vulnerability checker with call-graph reachability analysis.
type GovulncheckAdapter struct{}

func New() *GovulncheckAdapter {
	return &GovulncheckAdapter{}
}

func (a *GovulncheckAdapter) Name() string {
	return "govulncheck"
}

func (a *GovulncheckAdapter) Category() string {
	return orchestrator.CategorySCA
}

func (a *GovulncheckAdapter) IsApplicable(discovery *orchestrator.DiscoveryResult) bool {
	if discovery == nil {
		return true
	}
	for _, lang := range discovery.Languages {
		if strings.ToLower(lang) == "go" {
			return true
		}
	}
	for _, m := range discovery.Manifests {
		if strings.HasSuffix(strings.ToLower(m), "go.mod") {
			return true
		}
	}
	return false
}

// Streaming NDJSON message types produced by `govulncheck -json`
type Message struct {
	Config   *ConfigMessage   `json:"config,omitempty"`
	Progress *ProgressMessage `json:"progress,omitempty"`
	OSV      *OSVMessage      `json:"osv,omitempty"`
	Finding  *FindingMessage  `json:"finding,omitempty"`
}

type ConfigMessage struct {
	ProtocolVersion string `json:"protocol_version"`
}

type ProgressMessage struct {
	Message string `json:"message"`
}

type OSVMessage struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Summary string   `json:"summary"`
	Details string   `json:"details"`
}

type FindingMessage struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version"`
	Trace        []TraceFrame `json:"trace"`
}

type TraceFrame struct {
	Module   string    `json:"module"`
	Version  string    `json:"version"`
	Package  string    `json:"package"`
	Function string    `json:"function"`
	Receiver string    `json:"receiver"`
	Position *Position `json:"position"`
}

type Position struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

// ParseGovulncheckOutput parses streaming NDJSON from govulncheck.
func ParseGovulncheckOutput(data []byte, repoPath string, cfg *config.Config) ([]orchestrator.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	osvMap := make(map[string]*OSVMessage)
	findingsByOSV := make(map[string][]FindingMessage)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		if msg.OSV != nil && msg.OSV.ID != "" {
			osvMap[msg.OSV.ID] = msg.OSV
		}
		if msg.Finding != nil && msg.Finding.OSV != "" {
			findingsByOSV[msg.Finding.OSV] = append(findingsByOSV[msg.Finding.OSV], *msg.Finding)
		}
	}

	var results []orchestrator.Finding
	for osvID, osv := range osvMap {
		findings := findingsByOSV[osvID]

		// Determine reachability from call stack traces
		isReachable := false
		var callStackEvidence string
		var topPkg string

		for _, f := range findings {
			var frames []string
			for _, tr := range f.Trace {
				if tr.Package != "" {
					topPkg = tr.Package
				}
				if tr.Function != "" {
					pos := ""
					if tr.Position != nil && tr.Position.Filename != "" {
						pos = fmt.Sprintf(" (%s:%d)", filepath.Base(tr.Position.Filename), tr.Position.Line)
					}
					frames = append(frames, fmt.Sprintf("%s.%s%s", tr.Package, tr.Function, pos))
				}
			}
			if len(frames) > 0 {
				isReachable = true
				if callStackEvidence == "" {
					callStackEvidence = strings.Join(frames, " -> ")
				}
			}
		}

		// Identify canonical CVE identifier if present
		cve := osvID
		for _, alias := range osv.Aliases {
			if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
				cve = alias
				break
			}
		}

		reachLabel := "proven"
		if !isReachable {
			reachLabel = "unreachable"
		}

		msgText := osv.Summary
		if msgText == "" {
			if topPkg != "" {
				msgText = fmt.Sprintf("Go vulnerability %s in %s [Reachability: %s (govulncheck)]", cve, topPkg, reachLabel)
			} else {
				msgText = fmt.Sprintf("Go vulnerability %s [Reachability: %s (govulncheck)]", cve, reachLabel)
			}
		} else {
			msgText = fmt.Sprintf("%s [Reachability: %s (govulncheck)]", msgText, reachLabel)
		}

		snippet := callStackEvidence
		if snippet == "" && topPkg != "" {
			snippet = topPkg
		}

		findingID := orchestrator.GenerateID("govulncheck", cve, "go.mod", 1)
		if cfg != nil && cfg.ShouldIgnoreFinding(findingID) {
			continue
		}

		finding := orchestrator.Finding{
			ID:                findingID,
			Source:            "govulncheck",
			Engine:            orchestrator.EngineExternal,
			Category:          orchestrator.CategorySCA,
			Rule:              cve,
			CVE:               cve,
			Severity:          orchestrator.SeverityHigh,
			CVSS:              7.5,
			File:              "go.mod",
			LineStart:         1,
			LineEnd:           1,
			Message:           msgText,
			Snippet:           snippet,
			OWASP:             "A06:2021-Vulnerable and Outdated Components",
			Reachable:         &isReachable,
			ReachabilityLevel: reachLabel,
			FirstSeen:         time.Now().UTC(),
			Fingerprint:       orchestrator.GenerateFingerprint(orchestrator.CategorySCA, cve, "go.mod", snippet),
		}
		finding.RiskScore = orchestrator.CalculateRiskScore(&finding)
		results = append(results, finding)
	}

	return results, nil
}

func (a *GovulncheckAdapter) Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error) {
	binPath, err := exec.LookPath("govulncheck")
	if err != nil || binPath == "" {
		return nil, fmt.Errorf("%w: govulncheck binary not found in PATH", orchestrator.ErrSkipped)
	}

	goModPath := filepath.Join(repoPath, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return nil, fmt.Errorf("%w: go.mod not found in %s", orchestrator.ErrSkipped, repoPath)
	}

	cmd := exec.CommandContext(ctx, binPath, "-json", "./...")
	cmd.Dir = repoPath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	// govulncheck exits with code 3 when vulnerabilities are detected, code 0 when clean.
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
			// Normal exit code when vulnerabilities are discovered
		} else if stdout.Len() > 0 {
			// Output was generated despite exit code
		} else {
			return nil, fmt.Errorf("govulncheck execution failed: %w (stderr: %s)", err, stderr.String())
		}
	}

	return ParseGovulncheckOutput(stdout.Bytes(), repoPath, cfg)
}
