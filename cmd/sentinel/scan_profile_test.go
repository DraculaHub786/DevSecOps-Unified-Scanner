package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanCommandProfilesRegistered(t *testing.T) {
	cmd := newScanCmd()

	allFlag := cmd.Flags().Lookup("all")
	if allFlag == nil {
		t.Fatal("expected --all flag to be registered on scan command")
	}

	quickFlag := cmd.Flags().Lookup("quick")
	if quickFlag == nil {
		t.Fatal("expected --quick flag to be registered on scan command")
	}
}

func TestDiscoverContainerImages(t *testing.T) {
	tmpDir := t.TempDir()

	dockerfileContent := `FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder /app/app /app/app
CMD ["/app/app"]
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte(dockerfileContent), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	composeContent := `version: '3.8'
services:
  web:
    image: nginx:1.25-alpine
    ports:
      - "80:80"
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: secret
`
	if err := os.WriteFile(filepath.Join(tmpDir, "docker-compose.yml"), []byte(composeContent), 0644); err != nil {
		t.Fatalf("failed to write docker-compose.yml: %v", err)
	}

	images := discoverContainerImages(tmpDir)

	expectedImages := map[string]bool{
		"golang:1.22-alpine": true,
		"alpine:3.19":        true,
		"nginx:1.25-alpine":  true,
		"postgres:16-alpine": true,
	}

	for _, img := range images {
		delete(expectedImages, img)
	}

	if len(expectedImages) > 0 {
		t.Errorf("discoverContainerImages missed expected images: %v (found: %v)", expectedImages, images)
	}
}
