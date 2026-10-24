package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionParityAcrossArtifacts(t *testing.T) {
	// Root directory is two levels up from cmd/sentinel
	rootDir, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("failed to resolve root directory: %v", err)
	}

	versionBytes, err := os.ReadFile(filepath.Join(rootDir, "VERSION"))
	if err != nil {
		t.Fatalf("failed to read root VERSION file: %v", err)
	}
	expectedVersion := strings.TrimSpace(string(versionBytes))
	if expectedVersion == "" {
		t.Fatal("root VERSION file is empty")
	}

	// 1. Verify main.go version variable matches
	if version != expectedVersion {
		t.Errorf("main.go version mismatch: got %q, expected %q", version, expectedVersion)
	}

	// 2. Verify Formula/sentinel.rb
	formulaBytes, err := os.ReadFile(filepath.Join(rootDir, "Formula", "sentinel.rb"))
	if err != nil {
		t.Fatalf("failed to read Formula/sentinel.rb: %v", err)
	}
	formulaStr := string(formulaBytes)
	if !strings.Contains(formulaStr, "v"+expectedVersion) {
		t.Errorf("Formula/sentinel.rb does not contain tag 'v%s'", expectedVersion)
	}
	if !strings.Contains(formulaStr, "-X main.version="+expectedVersion) {
		t.Errorf("Formula/sentinel.rb does not contain ldflags '-X main.version=%s'", expectedVersion)
	}

	// 3. Verify Dockerfile
	dockerBytes, err := os.ReadFile(filepath.Join(rootDir, "Dockerfile"))
	if err != nil {
		t.Fatalf("failed to read Dockerfile: %v", err)
	}
	dockerStr := string(dockerBytes)
	if !strings.Contains(dockerStr, "ARG VERSION="+expectedVersion) {
		t.Errorf("Dockerfile does not contain 'ARG VERSION=%s'", expectedVersion)
	}

	// 4. Verify deploy/docker/Dockerfile.cli
	dockerCliBytes, err := os.ReadFile(filepath.Join(rootDir, "deploy", "docker", "Dockerfile.cli"))
	if err != nil {
		t.Fatalf("failed to read deploy/docker/Dockerfile.cli: %v", err)
	}
	dockerCliStr := string(dockerCliBytes)
	if !strings.Contains(dockerCliStr, "ARG VERSION="+expectedVersion) {
		t.Errorf("deploy/docker/Dockerfile.cli does not contain 'ARG VERSION=%s'", expectedVersion)
	}

	// 5. Verify deploy/github-actions/sentinel-scan/action.yml
	actionBytes, err := os.ReadFile(filepath.Join(rootDir, "deploy", "github-actions", "sentinel-scan", "action.yml"))
	if err != nil {
		t.Fatalf("failed to read action.yml: %v", err)
	}
	actionStr := string(actionBytes)
	if !strings.Contains(actionStr, ":v"+expectedVersion) {
		t.Errorf("action.yml does not contain image tag ':v%s'", expectedVersion)
	}

	// 6. Verify extension-vscode/package.json
	pkgBytes, err := os.ReadFile(filepath.Join(rootDir, "extension-vscode", "package.json"))
	if err != nil {
		t.Fatalf("failed to read extension-vscode/package.json: %v", err)
	}
	pkgStr := string(pkgBytes)
	if !strings.Contains(pkgStr, `"version": "`+expectedVersion+`"`) {
		t.Errorf("extension-vscode/package.json does not contain '\"version\": \"%s\"'", expectedVersion)
	}
}
