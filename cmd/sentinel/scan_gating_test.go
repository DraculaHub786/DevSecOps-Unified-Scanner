package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
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

func TestTrustedPolicyOverridesPRConfig(t *testing.T) {
	tmpRepo := t.TempDir()

	// PR maliciously adds .sentinel.yml ignoring all paths and relaxing fail_on to critical
	prPolicyContent := `thresholds:
  fail_on: critical
ignore:
  paths:
    - "**"
`
	if err := os.WriteFile(filepath.Join(tmpRepo, ".sentinel.yml"), []byte(prPolicyContent), 0644); err != nil {
		t.Fatalf("failed to write PR policy: %v", err)
	}

	// Trusted base branch policy stored outside the PR workspace (e.g. $RUNNER_TEMP/policy.yml)
	trustedPolicyDir := t.TempDir()
	trustedPolicyPath := filepath.Join(trustedPolicyDir, "base-policy.yml")
	basePolicyContent := `thresholds:
  fail_on: high
`
	if err := os.WriteFile(trustedPolicyPath, []byte(basePolicyContent), 0644); err != nil {
		t.Fatalf("failed to write base policy: %v", err)
	}

	// Loading untrusted repo config directly would have bypassed gating
	untrustedCfg, err := config.Load(tmpRepo)
	if err != nil {
		t.Fatalf("failed to load untrusted config: %v", err)
	}
	if untrustedCfg.Thresholds.FailOn != "critical" {
		t.Errorf("expected untrusted config to have fail_on: critical")
	}

	// Loading trusted base policy via LoadFile ignores repo .sentinel.yml
	trustedCfg, err := config.LoadFile(trustedPolicyPath)
	if err != nil {
		t.Fatalf("failed to load trusted config: %v", err)
	}
	if trustedCfg.Thresholds.FailOn != "high" {
		t.Errorf("expected trusted config to enforce fail_on: high, got %s", trustedCfg.Thresholds.FailOn)
	}
	if untrustedCfg.ShouldIgnorePath("server.js") != true {
		t.Errorf("expected untrusted config to ignore server.js due to '**'")
	}
	if trustedCfg.ShouldIgnorePath("server.js") != false {
		t.Errorf("expected trusted config NOT to ignore server.js, but it did")
	}

	// Simulate scan with HIGH finding: PR bypass fails, base policy blocks PR
	findings := []orchestrator.Finding{
		{Severity: orchestrator.SeverityHigh, File: "server.js"},
	}
	bypassed := shouldFailGating(true, untrustedCfg.Thresholds.FailOn, findings)
	if bypassed {
		t.Errorf("untrusted PR config was expected to bypass gating for high finding")
	}

	blocked := shouldFailGating(true, trustedCfg.Thresholds.FailOn, findings)
	if !blocked {
		t.Errorf("trusted base policy MUST block gating for high finding")
	}
}

func TestCheckUntrustedPolicyTable(t *testing.T) {
	// Create repo with in-repo .sentinel.yml
	repoWithPolicy := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoWithPolicy, ".sentinel.yml"), []byte("thresholds:\n  fail_on: high\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create repo without .sentinel.yml
	repoWithoutPolicy := t.TempDir()

	tests := []struct {
		name            string
		ciMode          bool
		configPath      string
		trustRepoPolicy bool
		repoDir         string
		expectError     bool
	}{
		{
			name:            "CI mode with in-repo policy and no overrides -> MUST FAIL",
			ciMode:          true,
			configPath:      "",
			trustRepoPolicy: false,
			repoDir:         repoWithPolicy,
			expectError:     true,
		},
		{
			name:            "CI mode with in-repo policy and explicit trusted --config -> SUCCEEDS",
			ciMode:          true,
			configPath:      "/tmp/trusted.yml",
			trustRepoPolicy: false,
			repoDir:         repoWithPolicy,
			expectError:     false,
		},
		{
			name:            "CI mode with in-repo policy and explicit --trust-repo-policy -> SUCCEEDS",
			ciMode:          true,
			configPath:      "",
			trustRepoPolicy: true,
			repoDir:         repoWithPolicy,
			expectError:     false,
		},
		{
			name:            "Non-CI local mode with in-repo policy -> SUCCEEDS",
			ciMode:          false,
			configPath:      "",
			trustRepoPolicy: false,
			repoDir:         repoWithPolicy,
			expectError:     false,
		},
		{
			name:            "CI mode when repo has no .sentinel.yml -> SUCCEEDS",
			ciMode:          true,
			configPath:      "",
			trustRepoPolicy: false,
			repoDir:         repoWithoutPolicy,
			expectError:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkUntrustedPolicy(tc.ciMode, tc.configPath, tc.trustRepoPolicy, tc.repoDir)
			if tc.expectError && err == nil {
				t.Fatalf("expected error rejecting untrusted repo policy, got nil")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
