package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
)

// DiscoveryResult details the detected technical stack, manifests, and files in a target directory.
type DiscoveryResult struct {
	RepoPath     string   `json:"repo_path"`
	Languages    []string `json:"languages"`
	Manifests    []string `json:"manifests"`
	Lockfiles    []string `json:"lockfiles"`
	IaCFiles     []string `json:"iac_files"`
	HasGit       bool     `json:"has_git"`
	TotalFiles   int      `json:"total_files"`
}

// Discover analyzes the workspace path and detects applicable stacks, languages, and manifests.
func Discover(repoPath string) (*DiscoveryResult, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		absPath = repoPath
	}

	result := &DiscoveryResult{
		RepoPath:  absPath,
		Languages: make([]string, 0),
		Manifests: make([]string, 0),
		Lockfiles: make([]string, 0),
		IaCFiles:  make([]string, 0),
	}

	// Check for .git directory
	gitPath := filepath.Join(absPath, ".git")
	if fi, err := os.Stat(gitPath); err == nil && fi.IsDir() {
		result.HasGit = true
	}

	langSet := make(map[string]bool)
	manifestSet := make(map[string]bool)
	lockfileSet := make(map[string]bool)
	iacSet := make(map[string]bool)

	ignoredDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
		".sentinel":    true,
		"dist":         true,
		"build":        true,
		"target":       true,
		"__pycache__":  true,
		".venv":        true,
	}

	totalFiles := 0

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if info.IsDir() {
			base := info.Name()
			if ignoredDirs[base] && path != absPath {
				return filepath.SkipDir
			}
			return nil
		}

		totalFiles++
		rel, err := filepath.Rel(absPath, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		baseName := strings.ToLower(info.Name())

		// Manifest & Lockfile detection
		switch baseName {
		case "package.json":
			manifestSet[rel] = true
			langSet["javascript"] = true
			langSet["typescript"] = true
		case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			lockfileSet[rel] = true
			langSet["javascript"] = true
		case "go.mod":
			manifestSet[rel] = true
			langSet["go"] = true
		case "go.sum":
			lockfileSet[rel] = true
			langSet["go"] = true
		case "requirements.txt", "pyproject.toml", "pipfile", "setup.py":
			manifestSet[rel] = true
			langSet["python"] = true
		case "pipfile.lock", "poetry.lock":
			lockfileSet[rel] = true
			langSet["python"] = true
		case "pom.xml", "build.gradle":
			manifestSet[rel] = true
			langSet["java"] = true
		case "cargo.toml":
			manifestSet[rel] = true
			langSet["rust"] = true
		case "cargo.lock":
			lockfileSet[rel] = true
			langSet["rust"] = true
		case "dockerfile":
			iacSet[rel] = true
		}

		// Prefix / suffix detections
		if strings.HasPrefix(baseName, "dockerfile.") {
			iacSet[rel] = true
		}
		if strings.HasSuffix(baseName, ".tf") || strings.HasSuffix(baseName, ".tfvars") {
			iacSet[rel] = true
			langSet["terraform"] = true
		}
		if strings.HasSuffix(baseName, ".k8s.yaml") || strings.HasSuffix(baseName, ".k8s.yml") {
			iacSet[rel] = true
		}

		// Source file extensions
		ext := strings.ToLower(filepath.Ext(baseName))
		switch ext {
		case ".go":
			langSet["go"] = true
		case ".js", ".jsx", ".mjs", ".cjs":
			langSet["javascript"] = true
		case ".ts", ".tsx":
			langSet["typescript"] = true
		case ".py":
			langSet["python"] = true
		case ".java":
			langSet["java"] = true
		case ".rs":
			langSet["rust"] = true
		case ".c", ".h", ".cpp", ".hpp":
			langSet["c/c++"] = true
		case ".rb":
			langSet["ruby"] = true
		case ".php":
			langSet["php"] = true
		}

		return nil
	})

	for l := range langSet {
		result.Languages = append(result.Languages, l)
	}
	for m := range manifestSet {
		result.Manifests = append(result.Manifests, m)
	}
	for lk := range lockfileSet {
		result.Lockfiles = append(result.Lockfiles, lk)
	}
	for iac := range iacSet {
		result.IaCFiles = append(result.IaCFiles, iac)
	}
	result.TotalFiles = totalFiles

	return result, err
}
