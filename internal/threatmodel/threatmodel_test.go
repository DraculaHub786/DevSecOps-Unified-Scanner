package threatmodel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestGenerateThreatModel(t *testing.T) {
	// Create a temporary project directory
	tmpDir, err := os.MkdirTemp("", "sentinel-threatmodel-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write mock app.js with an Express route and postgres connection
	appJS := `
const express = require('express');
const app = express();
app.get('/api/users', (req, res) => res.json([]));
const pg = require('pg');
const client = new pg.Client('postgres://user:pass@localhost/db');
client.connect();
`
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js"), []byte(appJS), 0644); err != nil {
		t.Fatalf("Failed to write app.js: %v", err)
	}

	// Write mock Dockerfile
	dockerfile := `
FROM node:18
EXPOSE 8080
CMD ["node", "app.js"]
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		t.Fatalf("Failed to write Dockerfile: %v", err)
	}

	mockFindings := []orchestrator.Finding{
		{
			ID:        "f-auth-1",
			Rule:      "hardcoded-jwt-token",
			Category:  orchestrator.CategorySecret,
			Severity:  "critical",
			File:      "app.js",
			LineStart: 6,
		},
		{
			ID:        "f-sql-1",
			Rule:      "raw-sql-injection",
			Category:  orchestrator.CategorySAST,
			Severity:  "high",
			CWE:       "CWE-89",
			File:      "app.js",
			LineStart: 7,
		},
		{
			ID:        "f-dos-1",
			Rule:      "missing-rate-limit",
			Category:  orchestrator.CategoryResilience,
			Severity:  "medium",
			File:      "server.go",
			LineStart: 12,
		},
	}

	report, err := GenerateThreatModel(tmpDir, mockFindings)
	if err != nil {
		t.Fatalf("GenerateThreatModel failed: %v", err)
	}

	if len(report.EntryPoints) == 0 {
		t.Errorf("Expected entry points to be detected, got 0")
	}

	var foundRoute, foundPort bool
	for _, ep := range report.EntryPoints {
		if ep.Target == "/api/users" {
			foundRoute = true
		}
		if ep.Target == "8080" {
			foundPort = true
		}
	}
	if !foundRoute {
		t.Errorf("Expected /api/users route to be found")
	}
	if !foundPort {
		t.Errorf("Expected EXPOSE 8080 to be found")
	}

	if len(report.DataStores) == 0 {
		t.Errorf("Expected postgres data store to be detected, got 0")
	} else if report.DataStores[0].Type != "Postgres" {
		t.Errorf("Expected DataStore Type 'Postgres', got '%s'", report.DataStores[0].Type)
	}

	if len(report.STRIDE) != len(mockFindings) {
		t.Fatalf("Expected %d STRIDE items, got %d", len(mockFindings), len(report.STRIDE))
	}

	if report.STRIDE[0].Category != "Spoofing" {
		t.Errorf("Expected f-auth-1 to be Spoofing, got %s", report.STRIDE[0].Category)
	}
	if report.STRIDE[1].Category != "Tampering" {
		t.Errorf("Expected f-sql-1 to be Tampering, got %s", report.STRIDE[1].Category)
	}
	if report.STRIDE[2].Category != "Denial of Service" {
		t.Errorf("Expected f-dos-1 to be Denial of Service, got %s", report.STRIDE[2].Category)
	}

	// Verify Exposed field updated for app.js
	if mockFindings[0].Exposed == nil || !*mockFindings[0].Exposed {
		t.Errorf("Expected mockFindings[0] on app.js to be marked Exposed=true")
	}

	md := report.RenderMarkdown()
	if !strings.Contains(md, "Threat Model & Trust Boundary Analysis") {
		t.Errorf("RenderMarkdown missing title")
	}
	if !strings.Contains(md, "/api/users") {
		t.Errorf("RenderMarkdown missing /api/users")
	}
}
