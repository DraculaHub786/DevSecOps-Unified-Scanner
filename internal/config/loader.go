package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads and parses .sentinel.yml from repoPath, or falls back to DefaultConfig.
func Load(repoPath string) (*Config, error) {
	cfg := DefaultConfig()

	candidatePaths := []string{
		filepath.Join(repoPath, ".sentinel.yml"),
		filepath.Join(repoPath, ".sentinel.yaml"),
		filepath.Join(repoPath, "sentinel.yml"),
	}

	var foundPath string
	for _, p := range candidatePaths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			foundPath = p
			break
		}
	}

	if foundPath == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(foundPath)
	if err != nil {
		return cfg, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ShouldIgnorePath checks if a given relative file path matches any ignore glob.
func (c *Config) ShouldIgnorePath(relPath string) bool {
	normalized := filepath.ToSlash(relPath)
	for _, pattern := range c.Ignore.Paths {
		cleanPattern := filepath.ToSlash(pattern)
		// Simple wildcard and prefix checks
		if strings.HasSuffix(cleanPattern, "/**") {
			prefix := strings.TrimSuffix(cleanPattern, "/**")
			if strings.HasPrefix(normalized, prefix+"/") || normalized == prefix {
				return true
			}
		}
		if match, _ := filepath.Match(cleanPattern, normalized); match {
			return true
		}
		if match, _ := filepath.Match(cleanPattern, filepath.Base(normalized)); match {
			return true
		}
		if strings.Contains(normalized, strings.Trim(cleanPattern, "*")) && cleanPattern != "" {
			if strings.HasPrefix(cleanPattern, "**/*") {
				suffix := strings.TrimPrefix(cleanPattern, "**/*")
				if strings.HasSuffix(normalized, suffix) {
					return true
				}
			}
		}
	}
	return false
}

// ShouldIgnoreFinding checks whether a finding ID is in the suppressed findings list.
func (c *Config) ShouldIgnoreFinding(findingID string) bool {
	for _, f := range c.Ignore.Findings {
		if strings.EqualFold(strings.TrimSpace(f), strings.TrimSpace(findingID)) {
			return true
		}
	}
	return false
}
