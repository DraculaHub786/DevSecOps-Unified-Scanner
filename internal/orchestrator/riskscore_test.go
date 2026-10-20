package orchestrator

import (
	"testing"
)

func TestCalculateRiskScore_Table(t *testing.T) {
	bTrue := true
	bFalse := false

	tests := []struct {
		name     string
		finding  Finding
		minScore float64
		maxScore float64
	}{
		{
			name: "Exposed critical secret",
			finding: Finding{
				Severity: SeverityCritical,
				Category: CategorySecret,
				File:     "api/server.go",
			},
			minScore: 65.0,
			maxScore: 75.0,
		},
		{
			name: "Dormant unreachable dependency",
			finding: Finding{
				Severity:  SeverityHigh,
				Category:  CategorySCA,
				CVSS:      7.5,
				Reachable: &bFalse,
				File:      "vendor/unused.go",
			},
			minScore: 30.0,
			maxScore: 36.0,
		},
		{
			name: "Reachable exposed critical vulnerability",
			finding: Finding{
				Severity:  SeverityCritical,
				Category:  CategorySAST,
				CVSS:      9.8,
				Reachable: &bTrue,
				Exposed:   &bTrue,
				File:      "controllers/user.go",
			},
			minScore: 90.0,
			maxScore: 100.0,
		},
		{
			name: "Low severity in test file",
			finding: Finding{
				Severity: SeverityLow,
				Category: CategoryResilience,
				File:     "auth_test.go",
			},
			minScore: 5.0,
			maxScore: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateRiskScore(&tt.finding)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("%s: expected score between %.1f and %.1f, got %.1f", tt.name, tt.minScore, tt.maxScore, score)
			}
		})
	}
}
