# Contributing to Sentinel DevSecOps Unified Scanner

Thank you for your interest in contributing to Sentinel!

## Development Setup

1. **Prerequisites**:
   - Go 1.24+ (or Go 1.27)
   - Node.js 20+ (for VS Code extension)
   - Git

2. **Clone and Build**:
   ```bash
   git clone https://github.com/DraculaHub786/DevSecOps-Unified-Scanner.git
   cd DevSecOps-Unified-Scanner
   go build -o bin/sentinel ./cmd/sentinel
   go build -o bin/sentinel-agent ./cmd/sentinel-agent
   ```

3. **Running Tests**:
   ```bash
   go test -v ./...
   ```

## Commit Guidelines

We follow Conventional Commits:
- `feat:` New features or capabilities
- `fix:` Bug fixes
- `docs:` Documentation updates
- `test:` Adding or updating tests
- `chore:` Dependency bumps, CI maintenance

## Pull Request Checklist

- [ ] Code passes `go vet ./...` and `go test ./...`
- [ ] No raw secrets or unredacted keys added
- [ ] Any new scanner adapter implements `adapters.Adapter` and handles `Engine` provenance correctly
- [ ] Added unit or integration tests for new features
