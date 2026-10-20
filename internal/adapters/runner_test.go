package adapters

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunToolSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := RunTool(ctx, "go", "version")
	if err != nil {
		t.Fatalf("RunTool failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "go version") {
		t.Errorf("Expected stdout to contain 'go version', got %q", string(res.Stdout))
	}
}

func TestRunToolExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Calling non-existent go subcommand should exit with code 2
	res, err := RunTool(ctx, "go", "nonexistent-subcommand-12345")
	if err != nil {
		t.Fatalf("Unexpected execution error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Errorf("Expected non-zero exit code, got 0")
	}
	if len(res.Stderr) == 0 {
		t.Errorf("Expected non-empty stderr for invalid subcommand")
	}
}

func TestRunToolMissingBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := RunTool(ctx, "binary-that-definitely-does-not-exist-98765")
	if err == nil {
		t.Fatalf("Expected error for non-existent binary, got nil")
	}
}
