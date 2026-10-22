package rules

import (
	"testing"

	"gopkg.in/yaml.v3"
)

type semgrepRuleFile struct {
	Rules []struct {
		ID        string   `yaml:"id"`
		Message   string   `yaml:"message"`
		Severity  string   `yaml:"severity"`
		Languages []string `yaml:"languages"`
	} `yaml:"rules"`
}

func TestEmbeddedRulesValid(t *testing.T) {
	sastData, err := Content.ReadFile("sast-rules.yml")
	if err != nil {
		t.Fatalf("Failed to read embedded sast-rules.yml: %v", err)
	}

	var parsed semgrepRuleFile
	if err := yaml.Unmarshal(sastData, &parsed); err != nil {
		t.Fatalf("Embedded sast-rules.yml has invalid YAML syntax: %v", err)
	}

	t.Logf("Embedded SAST rules count: %d", len(parsed.Rules))
	if len(parsed.Rules) < 30 {
		t.Errorf("Expected at least 30 embedded SAST rules, got %d", len(parsed.Rules))
	}

	resilienceData, err := Content.ReadFile("resilience-rules.yml")
	if err != nil {
		t.Fatalf("Failed to read embedded resilience-rules.yml: %v", err)
	}

	var resParsed semgrepRuleFile
	if err := yaml.Unmarshal(resilienceData, &resParsed); err != nil {
		t.Fatalf("Embedded resilience-rules.yml has invalid YAML syntax: %v", err)
	}
}
