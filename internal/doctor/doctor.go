package doctor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters"
)

// ToolStatus captures presence, version, and operational mode for a scanner engine.
type ToolStatus struct {
	Name        string `json:"name"`
	Binary      string `json:"binary"`
	Found       bool   `json:"found"`
	Path        string `json:"path"`
	Version     string `json:"version"`
	Mode        string `json:"mode"` // "external" or "embedded lite"
	Recommended string `json:"recommended"`
}

// CheckEngines inspects all five wrapped external scanning engines.
func CheckEngines() []ToolStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tools := []struct {
		name        string
		bin         string
		verArgs     []string
		recommended string
	}{
		{"Semgrep (SAST)", "semgrep", []string{"--version"}, "Install with: pipx install semgrep"},
		{"Gitleaks (Secrets)", "gitleaks", []string{"version"}, "Install with: bash plugins/install.sh"},
		{"OSV-Scanner (SCA)", "osv-scanner", []string{"--version"}, "Install with: bash plugins/install.sh"},
		{"Trivy (IaC/Containers)", "trivy", []string{"--version"}, "Install with: bash plugins/install.sh"},
		{"Nuclei (DAST)", "nuclei", []string{"-version"}, "Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	}

	results := make([]ToolStatus, 0, len(tools))
	for _, t := range tools {
		st := ToolStatus{
			Name:        t.name,
			Binary:      t.bin,
			Recommended: t.recommended,
		}

		path, err := exec.LookPath(t.bin)
		if err == nil && path != "" {
			st.Found = true
			st.Path = path
			st.Mode = "external"

			res, err := adapters.RunTool(ctx, path, t.verArgs...)
			if err == nil && len(res.Stdout) > 0 {
				firstLine := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")[0]
				st.Version = firstLine
			} else {
				st.Version = "installed (version check returned empty)"
			}
		} else {
			st.Found = false
			st.Mode = "embedded lite"
			st.Version = "n/a (fallback regex engine active)"
		}

		results = append(results, st)
	}

	return results
}

// PrintDoctor outputs diagnostic findings to the console.
func PrintDoctor(tools []ToolStatus) {
	fmt.Println("\n🩺 Sentinel Engine Diagnostics & Health Check:")
	fmt.Println("=========================================================================")

	allExternal := true
	for _, t := range tools {
		if t.Found {
			fmt.Printf("  • %-26s %-10s [Version: %s]\n    Path: %s\n", t.Name, "✅ external", t.Version, t.Path)
		} else {
			allExternal = false
			fmt.Printf("  • %-26s %-10s [%s]\n    Hint: %s\n", t.Name, "⚠️ embedded", t.Mode, t.Recommended)
		}
	}
	fmt.Println("  • Resilience / Posture Engine:  ✅ native     [Always active - Go static analyzer]")
	fmt.Println("=========================================================================")

	if allExternal {
		fmt.Println("🎉 System is operating in FULL external mode: All 5 production engines verified.")
	} else {
		fmt.Println("ℹ️  System is operating in LITE mode: Missing tools fall back to embedded heuristics.")
		fmt.Println("   Run 'bash plugins/install.sh' (or 'plugins/install.ps1') to vendor pinned binaries.")
	}
	fmt.Println()
}
