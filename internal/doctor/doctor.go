package doctor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/adapters"
)

// Pinned tool defaults (aligned with plugins/versions.env)
var DefaultPinnedVersions = map[string]string{
	"gitleaks":    "8.30.1",
	"osv-scanner": "2.7.0",
	"trivy":       "0.76.0",
	"semgrep":     "1.182.0",
	"nuclei":      "3.3.8",
}

// ToolStatus captures presence, version, and operational mode for a scanner engine.
type ToolStatus struct {
	Name            string `json:"name"`
	Binary          string `json:"binary"`
	Found           bool   `json:"found"`
	Path            string `json:"path"`
	Version         string `json:"version"`
	PinnedVersion   string `json:"pinned_version,omitempty"`
	VersionMismatch bool   `json:"version_mismatch,omitempty"`
	Mode            string `json:"mode"` // "external" or "embedded lite"
	Recommended     string `json:"recommended"`
}

// LoadPinnedVersions attempts to load versions from plugins/versions.env or defaults.
func LoadPinnedVersions(baseDir string) map[string]string {
	res := make(map[string]string)
	for k, v := range DefaultPinnedVersions {
		res[k] = v
	}

	candidates := []string{
		filepath.Join(baseDir, "plugins", "versions.env"),
		filepath.Join(".", "plugins", "versions.env"),
	}

	for _, cand := range candidates {
		data, err := os.ReadFile(cand)
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "GITLEAKS_VERSION":
					res["gitleaks"] = val
				case "OSV_VERSION":
					res["osv-scanner"] = val
				case "TRIVY_VERSION":
					res["trivy"] = val
				case "SEMGREP_VERSION":
					res["semgrep"] = val
				case "NUCLEI_VERSION":
					res["nuclei"] = val
				}
			}
			break
		}
	}
	return res
}

func parseVersionOutput(stdout, stderr []byte) string {
	raw := string(stdout)
	if strings.TrimSpace(raw) == "" {
		raw = string(stderr)
	}

	scanner := bufio.NewScanner(strings.NewReader(raw))
	re := regexp.MustCompile(`(?i)(?:version\s*:?|v)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if match := re.FindString(line); match != "" {
			return strings.TrimSpace(line)
		}
	}

	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
		return strings.TrimSpace(lines[0])
	}
	return ""
}

// IsVersionMismatch compares detected version string against pinned version.
func IsVersionMismatch(installed, pinned string) bool {
	if installed == "" || pinned == "" {
		return false
	}
	return !strings.Contains(installed, pinned)
}

// CheckEngines inspects all five wrapped external scanning engines.
func CheckEngines() []ToolStatus {
	pinnedVersions := LoadPinnedVersions(".")

	tools := []struct {
		name        string
		bin         string
		verArgs     []string
		recommended string
	}{
		{"Semgrep (SAST)", "semgrep", []string{"--version", "--disable-version-check"}, "Install with: pipx install semgrep"},
		{"Gitleaks (Secrets)", "gitleaks", []string{"version"}, "Install with: bash plugins/install.sh"},
		{"OSV-Scanner (SCA)", "osv-scanner", []string{"--version"}, "Install with: bash plugins/install.sh"},
		{"Trivy (IaC/Containers)", "trivy", []string{"--version"}, "Install with: bash plugins/install.sh"},
		{"Nuclei (DAST)", "nuclei", []string{"-version"}, "Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
	}

	results := make([]ToolStatus, 0, len(tools))
	for _, t := range tools {
		st := ToolStatus{
			Name:          t.name,
			Binary:        t.bin,
			PinnedVersion: pinnedVersions[t.bin],
			Recommended:   t.recommended,
		}

		path, err := exec.LookPath(t.bin)
		if err == nil && path != "" {
			st.Found = true
			st.Path = path
			st.Mode = "external"

			toolCtx, toolCancel := context.WithTimeout(context.Background(), 20*time.Second)
			res, runErr := adapters.RunTool(toolCtx, path, t.verArgs...)
			toolCancel()

			if runErr == nil {
				parsed := parseVersionOutput(res.Stdout, res.Stderr)
				if parsed != "" {
					st.Version = parsed
				} else {
					st.Version = "installed (version check returned empty)"
				}
			} else {
				st.Version = fmt.Sprintf("installed (error checking version: %v)", runErr)
			}

			if st.PinnedVersion != "" && IsVersionMismatch(st.Version, st.PinnedVersion) {
				st.VersionMismatch = true
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
			if t.VersionMismatch {
				fmt.Printf("    ⚠️ Version mismatch: installed %s != pinned %s (run 'bash plugins/install.sh' to align)\n", t.Version, t.PinnedVersion)
			}
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

// PrintPrivacy outputs all external network endpoints the tool can contact and why (Phase 7 / P-23).
func PrintPrivacy() {
	fmt.Println("\n🔒 Sentinel Privacy & Network Disclosure Audit:")
	fmt.Println("=========================================================================")
	fmt.Println("Sentinel is built strictly local-first. Zero telemetry is collected by default.")
	fmt.Println("Zero source code, credentials, or file paths ever leave your local machine.")
	fmt.Println("=========================================================================")
	fmt.Println("Network endpoints contacted during scan operations (when online):")
	fmt.Println("  1. api.osv.dev:443")
	fmt.Println("     • Purpose: Query Open Source Vulnerabilities database for package CVEs.")
	fmt.Println("     • Data sent: Package name and version strings only.")
	fmt.Println("     • Data NOT sent: No source code, secrets, or file paths.")
	fmt.Println("  2. ghcr.io:443 / aquasecurity.github.io:443")
	fmt.Println("     • Purpose: Download/update public Trivy vulnerability database cache.")
	fmt.Println("     • Data sent: HTTPS GET for public database tarball.")
	fmt.Println("  3. Target URL (provided via --target)")
	fmt.Println("     • Purpose: Passive DAST scanning with Nuclei.")
	fmt.Println("     • Authorization: Requires explicit --i-have-authorization flag.")
	fmt.Println("     • Guardrails: Blocks private RFC1918 IPs, loopback, and cloud metadata.")
	fmt.Println("-------------------------------------------------------------------------")
	fmt.Println("Strict Offline Guarantee:")
	fmt.Println("  Running with '--offline' ensures ZERO outbound network egress.")
	fmt.Println("  All dependency and rule checks degrade gracefully to local embedded data.")
	fmt.Println("=========================================================================")
}

