package doctor

import (
	"os"
	"path/filepath"
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

func TestParseVersionOutput(t *testing.T) {
	// Stdout standard case
	v := parseVersionOutput([]byte("v8.30.1\n"), nil)
	if v != "v8.30.1" {
		t.Errorf("expected v8.30.1, got %q", v)
	}

	// Stderr fallback case (e.g. CLI tool writing version to stderr)
	v = parseVersionOutput(nil, []byte("nuclei version 3.3.8\n"))
	if v != "nuclei version 3.3.8" {
		t.Errorf("expected nuclei version 3.3.8, got %q", v)
	}

	// Multiline banner with version inside
	banner := `
  __   __
 /  \_/  \
 \__/ \__/
 semgrep version: 1.182.0 (c67d1)
 scanning rules...
`
	v = parseVersionOutput([]byte(banner), nil)
	if v != "semgrep version: 1.182.0 (c67d1)" {
		t.Errorf("expected extracted version line, got %q", v)
	}
}

func TestIsVersionMismatch(t *testing.T) {
	tests := []struct {
		installed string
		pinned    string
		want      bool
	}{
		{"8.30.1", "8.30.1", false},
		{"v8.30.1", "8.30.1", false},
		{"gitleaks version 8.30.1", "8.30.1", false},
		{"8.18.4", "8.30.1", true},
		{"v1.8.2", "2.7.0", true},
		{"", "8.30.1", false},
	}

	for _, tt := range tests {
		got := IsVersionMismatch(tt.installed, tt.pinned)
		if got != tt.want {
			t.Errorf("IsVersionMismatch(%q, %q) = %v, want %v", tt.installed, tt.pinned, got, tt.want)
		}
	}
}

func TestLoadPinnedVersions(t *testing.T) {
	tmpDir := t.TempDir()
	pluginsDir := filepath.Join(tmpDir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		t.Fatalf("failed to create plugins dir: %v", err)
	}

	envContent := `
# Pinned versions
GITLEAKS_VERSION=8.30.1
OSV_VERSION=2.7.0
TRIVY_VERSION=0.76.0
SEMGREP_VERSION=1.182.0
NUCLEI_VERSION=3.3.8
`
	if err := os.WriteFile(filepath.Join(pluginsDir, "versions.env"), []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write versions.env: %v", err)
	}

	versions := LoadPinnedVersions(tmpDir)
	if versions["gitleaks"] != "8.30.1" {
		t.Errorf("expected gitleaks version 8.30.1, got %q", versions["gitleaks"])
	}
	if versions["osv-scanner"] != "2.7.0" {
		t.Errorf("expected osv-scanner version 2.7.0, got %q", versions["osv-scanner"])
	}
	if versions["trivy"] != "0.76.0" {
		t.Errorf("expected trivy version 0.76.0, got %q", versions["trivy"])
	}
	if versions["semgrep"] != "1.182.0" {
		t.Errorf("expected semgrep version 1.182.0, got %q", versions["semgrep"])
	}
	if versions["nuclei"] != "3.3.8" {
		t.Errorf("expected nuclei version 3.3.8, got %q", versions["nuclei"])
	}
}
