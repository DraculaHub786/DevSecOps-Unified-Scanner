package rules

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleBreakdown contains counts of detection rules by category and total.
type RuleBreakdown struct {
	Total         int
	SAST          int
	Resilience    int
	GitHubActions int
	SupplyChain   int
	ByCategory    map[string]int
}

type parsedRuleEntry struct {
	ID       string `yaml:"id"`
	Metadata struct {
		Category string `yaml:"category"`
	} `yaml:"metadata"`
}

type parsedRuleFile struct {
	Rules []parsedRuleEntry `yaml:"rules"`
}

// CountRules dynamically inspects all embedded rule YAML files and counts
// the actual rule definitions per category.
func CountRules() (RuleBreakdown, error) {
	stats := RuleBreakdown{
		ByCategory: make(map[string]int),
	}

	entries, err := Content.ReadDir(".")
	if err != nil {
		return stats, fmt.Errorf("reading embedded rules directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		data, err := Content.ReadFile(entry.Name())
		if err != nil {
			return stats, fmt.Errorf("reading embedded rule file %s: %w", entry.Name(), err)
		}

		var file parsedRuleFile
		if err := yaml.Unmarshal(data, &file); err != nil {
			return stats, fmt.Errorf("unmarshaling rule file %s: %w", entry.Name(), err)
		}

		count := len(file.Rules)
		switch entry.Name() {
		case "sast-rules.yml":
			stats.SAST += count
		case "resilience-rules.yml":
			stats.Resilience += count
		case "github-actions-rules.yml":
			stats.GitHubActions += count
		case "supply-chain-rules.yml":
			stats.SupplyChain += count
		default:
			// Fallback by metadata category
			for _, r := range file.Rules {
				cat := strings.ToLower(strings.TrimSpace(r.Metadata.Category))
				stats.ByCategory[cat]++
			}
		}

		for _, r := range file.Rules {
			cat := strings.ToLower(strings.TrimSpace(r.Metadata.Category))
			if cat != "" {
				stats.ByCategory[cat]++
			}
		}
	}

	stats.Total = stats.SAST + stats.Resilience + stats.GitHubActions + stats.SupplyChain
	return stats, nil
}

// Summary returns a human-readable one-line summary formatted for version output.
func (b RuleBreakdown) Summary() string {
	return fmt.Sprintf("Rules: embedded v1 (%d rules: %d SAST, %d resilience, %d GitHub Actions, %d supply chain)",
		b.Total, b.SAST, b.Resilience, b.GitHubActions, b.SupplyChain)
}
