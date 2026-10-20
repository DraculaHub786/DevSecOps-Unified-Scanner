package doctor

import (
	"testing"
)

func TestCheckEngines(t *testing.T) {
	statuses := CheckEngines()
	if len(statuses) != 5 {
		t.Fatalf("Expected 5 tools checked, got %d", len(statuses))
	}

	expectedNames := []string{
		"Semgrep (SAST)",
		"Gitleaks (Secrets)",
		"OSV-Scanner (SCA)",
		"Trivy (IaC/Containers)",
		"Nuclei (DAST)",
	}

	for i, st := range statuses {
		if st.Name != expectedNames[i] {
			t.Errorf("Tool %d name: got %q, want %q", i, st.Name, expectedNames[i])
		}
		if st.Mode != "external" && st.Mode != "embedded lite" {
			t.Errorf("Tool %d mode: unexpected mode %q", i, st.Mode)
		}
		if st.Recommended == "" {
			t.Errorf("Tool %d: recommended installation string should not be empty", i)
		}
	}
}
