package main

import (
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestShouldFailGating(t *testing.T) {
	tests := []struct {
		name     string
		ciMode   bool
		failOn   string
		findings []orchestrator.Finding
		want     bool
	}{
		{
			name:   "non ci mode does not fail even with critical findings",
			ciMode: false,
			failOn: "high",
			findings: []orchestrator.Finding{
				{Severity: orchestrator.SeverityCritical},
			},
			want: false,
		},
		{
			name:   "ci mode fails when finding meets threshold",
			ciMode: true,
			failOn: "high",
			findings: []orchestrator.Finding{
				{Severity: orchestrator.SeverityHigh},
			},
			want: true,
		},
		{
			name:   "ci mode does not fail when findings are below threshold",
			ciMode: true,
			failOn: "critical",
			findings: []orchestrator.Finding{
				{Severity: orchestrator.SeverityHigh},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFailGating(tt.ciMode, tt.failOn, tt.findings)
			if got != tt.want {
				t.Fatalf("shouldFailGating(%v, %q, findings) = %v, want %v", tt.ciMode, tt.failOn, got, tt.want)
			}
		})
	}
}
