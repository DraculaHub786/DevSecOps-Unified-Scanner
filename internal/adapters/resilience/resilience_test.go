package resilience

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

func TestResilienceAdapterDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Create a Go file with unbounded read and missing server timeouts
	goCode := `package main
import (
	"io"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	w.Write(data)
}
func main() {
	http.HandleFunc("/api", handle)
	http.ListenAndServe(":8080", nil)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "server.go"), []byte(goCode), 0644); err != nil {
		t.Fatalf("Failed to write server.go: %v", err)
	}

	// 2. Create a JS file with unconstrained body parser and ReDoS regex
	jsCode := `const express = require('express');
const app = express();
app.use(express.json());
const badRegex = /([a-z]+)+$/;
app.get('/test', (req, res) => res.send("ok"));
`
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js"), []byte(jsCode), 0644); err != nil {
		t.Fatalf("Failed to write app.js: %v", err)
	}

	adapter := New()
	cfg := config.DefaultConfig()
	discovery := &orchestrator.DiscoveryResult{
		RepoPath:  tmpDir,
		Languages: []string{"go", "javascript"},
	}

	findings, err := adapter.Run(context.Background(), tmpDir, cfg, discovery)
	if err != nil {
		t.Fatalf("Resilience adapter failed: %v", err)
	}

	ruleFound := make(map[string]bool)
	for _, f := range findings {
		ruleFound[f.Rule] = true
		if f.Category != orchestrator.CategoryResilience {
			t.Errorf("Expected category %s, got %s", orchestrator.CategoryResilience, f.Category)
		}
		if f.Engine != orchestrator.EngineNative {
			t.Errorf("Expected engine native for resilience, got %s", f.Engine)
		}
	}

	expectedRules := []string{
		"resilience-unbounded-body-read",
		"resilience-missing-server-timeout",
		"resilience-missing-request-size-limit",
		"resilience-unbounded-regex-redos",
		"missing-rate-limiter",
	}

	for _, rule := range expectedRules {
		if !ruleFound[rule] {
			t.Errorf("Expected resilience finding %q, but not found among: %v", rule, ruleFound)
		}
	}
}

func TestResilienceAdapterDisabled(t *testing.T) {
	adapter := New()
	cfg := config.DefaultConfig()
	cfg.Scanners.Resilience.Enabled = false

	findings, err := adapter.Run(context.Background(), t.TempDir(), cfg, nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings when disabled, got %d", len(findings))
	}
}
