package main

import (
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestShouldFailForFindings(t *testing.T) {
	tests := []struct {
		name     string
		ciMode   bool
		failOn   string
		findings []orchestrator.Finding
		want     bool
	}{
		{
			name:   "does not fail when ci mode disabled",
			ciMode: false,
			failOn: "high",
			findings: []orchestrator.Finding{
				{Severity: "critical"},
			},
			want: false,
		},
		{
			name:   "fails when ci mode enabled and finding meets threshold",
			ciMode: true,
			failOn: "high",
			findings: []orchestrator.Finding{
				{Severity: "high"},
			},
			want: true,
		},
		{
			name:   "does not fail when ci mode enabled and findings below threshold",
			ciMode: true,
			failOn: "critical",
			findings: []orchestrator.Finding{
				{Severity: "high"},
				{Severity: "medium"},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldFailForFindings(tc.ciMode, tc.findings, tc.failOn)
			if got != tc.want {
				t.Fatalf("shouldFailForFindings() = %v, want %v", got, tc.want)
			}
		})
	}
}
