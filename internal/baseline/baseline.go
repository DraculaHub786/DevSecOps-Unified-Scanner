package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// BaselineVersionCurrent represents current fingerprinting scheme version (v2.0).
const BaselineVersionCurrent = "2.0"

// BaselineFile represents saved state of accepted findings.
type BaselineFile struct {
	Version      string    `json:"version"`
	CreatedAt    time.Time `json:"created_at"`
	Fingerprints []string  `json:"fingerprints"`
}

// GetBaselinePath returns path to .sentinel/baseline.json.
func GetBaselinePath(repoPath string) string {
	return filepath.Join(repoPath, ".sentinel", "baseline.json")
}

// Save writes current scan findings fingerprints to baseline.json.
func Save(repoPath string, findings []orchestrator.Finding) (string, error) {
	outPath := GetBaselinePath(repoPath)
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return "", err
	}

	fingerprints := make([]string, 0, len(findings))
	seen := make(map[string]bool)
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = f.ID
		}
		if !seen[fp] {
			seen[fp] = true
			fingerprints = append(fingerprints, fp)
		}
	}

	b := BaselineFile{
		Version:      BaselineVersionCurrent,
		CreatedAt:    time.Now().UTC(),
		Fingerprints: fingerprints,
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return "", err
	}

	return outPath, os.WriteFile(outPath, data, 0644)
}

// Load loads baseline fingerprints from .sentinel/baseline.json.
func Load(repoPath string) (map[string]bool, error) {
	path := GetBaselinePath(repoPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline file not found at %s: %w", path, err)
	}

	var b BaselineFile
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	if b.Version != BaselineVersionCurrent {
		fmt.Fprintf(os.Stderr, "⚠️ Notice: Baseline format updated to v2.0 (source snippet fingerprints). Run 'sentinel baseline' to refresh baseline.\n")
	}

	set := make(map[string]bool, len(b.Fingerprints))
	for _, fp := range b.Fingerprints {
		set[fp] = true
	}
	return set, nil
}

// FilterNewFindings filters out any finding that already exists in the baseline set.
func FilterNewFindings(findings []orchestrator.Finding, baselineSet map[string]bool) []orchestrator.Finding {
	if len(baselineSet) == 0 {
		return findings
	}
	var newOnly []orchestrator.Finding
	for _, f := range findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = f.ID
		}
		if !baselineSet[fp] {
			newOnly = append(newOnly, f)
		}
	}
	return newOnly
}
