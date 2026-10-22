package rules

import (
	"strings"
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

func validateRuleFile(t *testing.T, filename string, parsed semgrepRuleFile) {
	t.Helper()
	if len(parsed.Rules) == 0 {
		t.Fatalf("%s has no rules defined", filename)
	}

	seenIDs := make(map[string]bool)
	validSeverities := map[string]bool{
		"ERROR":   true,
		"WARNING": true,
		"INFO":    true,
	}

	for i, r := range parsed.Rules {
		id := strings.TrimSpace(r.ID)
		if id == "" {
			t.Errorf("%s rule[%d] has empty id", filename, i)
		} else {
			if seenIDs[id] {
				t.Errorf("%s duplicate rule id: %s", filename, id)
			}
			seenIDs[id] = true
		}

		if strings.TrimSpace(r.Message) == "" {
			t.Errorf("%s rule %s has empty message", filename, id)
		}

		if len(r.Languages) == 0 {
			t.Errorf("%s rule %s has empty languages list", filename, id)
		} else {
			for _, lang := range r.Languages {
				if strings.TrimSpace(lang) == "" {
					t.Errorf("%s rule %s contains empty language entry", filename, id)
				}
			}
		}

		sev := strings.ToUpper(strings.TrimSpace(r.Severity))
		if !validSeverities[sev] {
			t.Errorf("%s rule %s has invalid severity %q (allowed: ERROR, WARNING, INFO)", filename, id, r.Severity)
		}
	}
}

func TestEmbeddedRulesValid(t *testing.T) {
	entries, err := Content.ReadDir(".")
	if err != nil {
		t.Fatalf("Failed to read embedded rules directory: %v", err)
	}

	ymlFilesFound := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		ymlFilesFound++

		data, err := Content.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("Failed to read %s: %v", entry.Name(), err)
		}

		var parsed semgrepRuleFile
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Failed to unmarshal %s: %v", entry.Name(), err)
		}

		validateRuleFile(t, entry.Name(), parsed)

		if entry.Name() == "sast-rules.yml" {
			t.Logf("Embedded SAST rules count: %d", len(parsed.Rules))
			if len(parsed.Rules) < 30 {
				t.Errorf("Expected at least 30 embedded SAST rules, got %d", len(parsed.Rules))
			}
		}
	}

	if ymlFilesFound == 0 {
		t.Fatalf("No embedded .yml rule files found")
	}
}
