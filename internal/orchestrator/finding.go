package orchestrator

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Categories
const (
	CategorySAST       = "sast"
	CategorySCA        = "sca"
	CategorySecret     = "secret"
	CategoryIaC        = "iac"
	CategoryDAST       = "dast"
	CategoryResilience = "resilience"
)

// Fix kinds
const (
	FixKindDependencyBump = "dependency-bump"
	FixKindCodePatch      = "code-patch"
	FixKindConfigPatch    = "config-patch"
	FixKindManualAction   = "manual-action"
)

// Finding represents a unified normalized security flaw across all scanners.
type Finding struct {
	ID            string    `json:"id"`
	Source        string    `json:"source"`
	Category      string    `json:"category"`
	Rule          string    `json:"rule"`
	Severity      string    `json:"severity"`
	CWE           string    `json:"cwe,omitempty"`
	CVE           string    `json:"cve,omitempty"`
	CVSS          float64   `json:"cvss,omitempty"`
	File          string    `json:"file"`
	LineStart     int       `json:"line_start"`
	LineEnd       int       `json:"line_end"`
	Message       string    `json:"message"`
	Reachable     *bool     `json:"reachable,omitempty"`
	Exposed       *bool     `json:"exposed,omitempty"`
	RiskScore     float64   `json:"risk_score"`
	FixSuggestion *Fix      `json:"fix_suggestion,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	Fingerprint   string    `json:"fingerprint"`
}

// Fix describes an automated or guided remediation proposal.
type Fix struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Diff        string `json:"diff,omitempty"`
	Confidence  string `json:"confidence"` // high | medium | low
}

// GenerateID produces a deterministic identifier from source, rule, file, and line.
func GenerateID(source, rule, file string, line int) string {
	raw := fmt.Sprintf("%s:%s:%s:%d", strings.ToLower(source), strings.ToLower(rule), file, line)
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("SENT-%x", hash[:6])
}

// GenerateFingerprint produces a stable fingerprint for tracking across scans even if lines shift slightly.
func GenerateFingerprint(category, rule, file, snippet string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", category, rule, file, strings.TrimSpace(snippet))
	hash := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", hash[:12])
}

// SeverityRank converts severity to numeric rank for sorting/filtering.
func SeverityRank(sev string) int {
	switch strings.ToLower(sev) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
