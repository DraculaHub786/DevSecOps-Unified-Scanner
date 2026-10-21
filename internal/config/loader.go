package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads and parses .sentinel.yml from repoPath, or falls back to DefaultConfig.
// Enforces KnownFields(true) and requires a justification reason on every finding suppression.
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

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true) // fail loudly on misspelled config keys

	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("invalid .sentinel.yml configuration: %w", err)
	}

	// Validation: suppressions must have a justification reason
	for idx, supp := range cfg.Ignore.Findings {
		if strings.TrimSpace(supp.ID) == "" {
			return nil, fmt.Errorf("invalid ignore.findings[%d]: id cannot be empty", idx)
		}
		if strings.TrimSpace(supp.Reason) == "" {
			return nil, fmt.Errorf("suppression %q requires a justification reason in .sentinel.yml", supp.ID)
		}
	}

	// Validation: threshold levels
	if cfg.Thresholds.FailOn != "" {
		validLevels := map[string]bool{
			"critical": true,
			"high":     true,
			"medium":   true,
			"low":      true,
			"info":     true,
		}
		if !validLevels[strings.ToLower(cfg.Thresholds.FailOn)] {
			return nil, fmt.Errorf("invalid thresholds.fail_on %q: must be one of critical, high, medium, low, info", cfg.Thresholds.FailOn)
		}
	}
	if cfg.Thresholds.RiskScoreMax < 0 || cfg.Thresholds.RiskScoreMax > 100 {
		return nil, fmt.Errorf("invalid thresholds.risk_score_max %.1f: must be between 0.0 and 100.0", cfg.Thresholds.RiskScoreMax)
	}

	return cfg, nil
}

// ShouldIgnorePath checks if a given relative file path matches any ignore glob.
func (c *Config) ShouldIgnorePath(relPath string) bool {
	normalized := filepath.ToSlash(relPath)
	for _, pattern := range c.Ignore.Paths {
		cleanPattern := filepath.ToSlash(pattern)
		// Check for double star recursive directory match
		if strings.HasSuffix(cleanPattern, "/**") {
			prefix := strings.TrimSuffix(cleanPattern, "/**")
			prefix = strings.TrimPrefix(prefix, "**/")
			if strings.Contains(normalized, prefix+"/") || strings.HasPrefix(normalized, prefix) {
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

// ShouldIgnoreFinding checks whether a finding ID is in the suppressed findings list and not expired.
func (c *Config) ShouldIgnoreFinding(findingID string) bool {
	today := time.Now().UTC()
	for _, supp := range c.Ignore.Findings {
		if strings.EqualFold(strings.TrimSpace(supp.ID), strings.TrimSpace(findingID)) {
			// Check expiration if specified
			if supp.Expires != "" {
				exp, err := time.Parse("2006-01-02", supp.Expires)
				if err == nil && today.After(exp) {
					// Suppression has expired; do not ignore
					return false
				}
			}
			return true
		}
	}
	return false
}
