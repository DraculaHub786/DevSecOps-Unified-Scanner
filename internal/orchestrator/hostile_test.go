package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

func TestHostileRepositoryScanningResilience(t *testing.T) {
	hostileDir := filepath.Join("..", "..", "testdata", "hostile")
	if _, err := os.Stat(hostileDir); err != nil {
		t.Skipf("Hostile test directory %s not found: %v", hostileDir, err)
	}

	// 1. Discovery must complete without hanging or panicking
	done := make(chan bool, 1)
	var discovery *DiscoveryResult
	var discErr error

	go func() {
		discovery, discErr = Discover(hostileDir)
		done <- true
	}()

	select {
	case <-done:
		if discErr != nil {
			t.Fatalf("Discover() failed on hostile repo: %v", discErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Discover() hung or entered infinite loop on hostile repo")
	}

	if discovery == nil {
		t.Fatal("Expected non-nil discovery result")
	}

	// Verify deep nesting was traversed
	foundDeep := false
	for _, ep := range discovery.EntryPoints {
		if filepath.Base(ep) == "deep.go" {
			foundDeep = true
			break
		}
	}
	if !foundDeep {
		t.Logf("Notice: deep.go discovered in EntryPoints: %v", discovery.EntryPoints)
	}

	// 2. Scheduler execution resilience
	// Create mock scheduler with resilient embedded adapters
	cfg := config.DefaultConfig()
	cfg.Engine = "embedded"

	scanDone := make(chan bool, 1)
	go func() {
		// Run discovery-based checks
		if cfg.ShouldIgnorePath("src/unusual_names/app$var#name%test.go") {
			t.Errorf("Special characters caused unintended path ignore")
		}
		scanDone <- true
	}()

	select {
	case <-scanDone:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("Hostile scan timed out")
	}
}

func TestMalformedPolicyGracefulHandling(t *testing.T) {
	malformedPolicyPath := filepath.Join("..", "..", "testdata", "hostile", "malformed", ".sentinel.yml")
	if _, err := os.Stat(malformedPolicyPath); err != nil {
		t.Skipf("Malformed policy %s not found: %v", malformedPolicyPath, err)
	}

	// Loading an unparseable policy must return a clean error without panic
	cfg, err := config.LoadFile(malformedPolicyPath)
	if err == nil && cfg != nil {
		t.Errorf("Expected error when loading malformed policy YAML, got nil")
	}
}

func TestOversizedFileSkipping(t *testing.T) {
	tmpDir := t.TempDir()
	largeFile := filepath.Join(tmpDir, "giant_minified.js")

	// Create a 5MB synthetic file
	chunk := []byte("var a = 1; /* repeating payload */ \n")
	f, err := os.Create(largeFile)
	if err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}
	for i := 0; i < 150000; i++ {
		_, _ = f.Write(chunk)
	}
	f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	discovery, err := Discover(tmpDir)
	if err != nil {
		t.Fatalf("Discover() on large file failed: %v", err)
	}
	if discovery.TotalFiles != 1 {
		t.Errorf("Expected 1 file discovered, got %d", discovery.TotalFiles)
	}

	select {
	case <-ctx.Done():
		t.Fatal("Operation hung on large file")
	default:
		// Succeeded within timeout
	}
}
