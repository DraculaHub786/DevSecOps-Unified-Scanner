package rules

import (
	"os"
	"path/filepath"
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
		Metadata  struct {
			CWE        string `yaml:"cwe"`
			OWASP      string `yaml:"owasp"`
			Category   string `yaml:"category"`
			Confidence string `yaml:"confidence"`
		} `yaml:"metadata"`
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
	validCategories := map[string]bool{
		"sast":       true,
		"secret":     true,
		"resilience": true,
		"iac":        true,
	}
	validConfidences := map[string]bool{
		"high":   true,
		"medium": true,
		"low":    true,
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

		// Metadata validation (T-048)
		if strings.TrimSpace(r.Metadata.CWE) == "" {
			t.Errorf("%s rule %s has missing or empty metadata.cwe", filename, id)
		}
		if strings.TrimSpace(r.Metadata.OWASP) == "" {
			t.Errorf("%s rule %s has missing or empty metadata.owasp", filename, id)
		}
		cat := strings.ToLower(strings.TrimSpace(r.Metadata.Category))
		if !validCategories[cat] {
			t.Errorf("%s rule %s has invalid metadata.category %q (allowed: sast, secret, resilience, iac)", filename, id, r.Metadata.Category)
		}
		conf := strings.ToLower(strings.TrimSpace(r.Metadata.Confidence))
		if !validConfidences[conf] {
			t.Errorf("%s rule %s has invalid metadata.confidence %q (allowed: high, medium, low)", filename, id, r.Metadata.Confidence)
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

func TestRuleIDsCoveredInTests(t *testing.T) {
	// Read all rule IDs from rules/*.yml
	entries, err := Content.ReadDir(".")
	if err != nil {
		t.Fatalf("Failed to read rules directory: %v", err)
	}

	var allRuleIDs []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		data, err := Content.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("Failed to read %s: %v", entry.Name(), err)
		}
		var parsed semgrepRuleFile
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("Failed to unmarshal %s: %v", entry.Name(), err)
		}
		for _, r := range parsed.Rules {
			allRuleIDs = append(allRuleIDs, strings.TrimSpace(r.ID))
		}
	}

	// Read test files from rules/tests
	testEntries, err := os.ReadDir("tests")
	if err != nil {
		t.Fatalf("Failed to read rules/tests directory: %v", err)
	}

	testContent := ""
	for _, te := range testEntries {
		if te.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join("tests", te.Name()))
		if err == nil {
			testContent += "\n" + string(data)
		}
	}

	// Verify every rule ID has a test case (T-054)
	for _, id := range allRuleIDs {
		if !strings.Contains(testContent, id) {
			t.Errorf("Rule %q has no corresponding test case in rules/tests/", id)
		}
	}
}
