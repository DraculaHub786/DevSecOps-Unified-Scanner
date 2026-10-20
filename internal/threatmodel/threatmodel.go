package threatmodel

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// ThreatModelReport aggregates structural entry points, trust boundaries, and STRIDE mappings.
type ThreatModelReport struct {
	EntryPoints []EntryPoint `json:"entry_points"`
	DataStores  []DataStore  `json:"data_stores"`
	AuthGuards  []AuthGuard  `json:"auth_guards"`
	STRIDE      []STRIDEItem `json:"stride"`
}

type EntryPoint struct {
	Type     string `json:"type"` // "HTTP Route", "Exposed Port", "RPC"
	Location string `json:"location"`
	Target   string `json:"target"`
}

type DataStore struct {
	Type     string `json:"type"` // "Postgres", "Redis", "MongoDB", "MySQL", "SQLite"
	Location string `json:"location"`
}

type AuthGuard struct {
	Name     string `json:"name"`
	Location string `json:"location"`
}

type STRIDEItem struct {
	Category string                 `json:"category"` // Spoofing, Tampering, Repudiation, InfoDisclosure, DoS, ElevationOfPrivilege
	Finding  orchestrator.Finding   `json:"finding"`
	OWASP    string                 `json:"owasp"`
}

// GenerateThreatModel analyzes repository structure to discover entry points, data stores, and maps findings to STRIDE.
func GenerateThreatModel(repoPath string, findings []orchestrator.Finding) (*ThreatModelReport, error) {
	report := &ThreatModelReport{
		EntryPoints: make([]EntryPoint, 0),
		DataStores:  make([]DataStore, 0),
		AuthGuards:  make([]AuthGuard, 0),
		STRIDE:      make([]STRIDEItem, 0),
	}

	routeRegexes := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:app\.(?:get|post|put|delete|patch|use)|router\.(?:get|post|put|delete))\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:http\.HandleFunc|r\.(?:GET|POST|PUT|DELETE))\s*\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)@app\.route\s*\(\s*["']([^"']+)["']`),
	}

	exposeRegex := regexp.MustCompile(`(?i)^\s*EXPOSE\s+([0-9]+)`)
	dataStoreKeywords := []string{"postgres", "mysql", "mongodb", "redis", "sqlite", "dynamodb"}

	_ = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(repoPath, path)
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, ".") || strings.Contains(rel, "node_modules") || strings.Contains(rel, "vendor") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// 1. Detect routes
			for _, re := range routeRegexes {
				if match := re.FindStringSubmatch(line); len(match) > 1 {
					report.EntryPoints = append(report.EntryPoints, EntryPoint{
						Type:     "HTTP Endpoint",
						Location: fmt.Sprintf("%s:%d", rel, lineNum),
						Target:   match[1],
					})
				}
			}

			// 2. Detect exposed ports in Dockerfile
			if strings.Contains(strings.ToLower(rel), "dockerfile") {
				if match := exposeRegex.FindStringSubmatch(line); len(match) > 1 {
					report.EntryPoints = append(report.EntryPoints, EntryPoint{
						Type:     "Container Port",
						Location: fmt.Sprintf("%s:%d", rel, lineNum),
						Target:   match[1],
					})
				}
			}

			// 3. Detect data stores
			lowerLine := strings.ToLower(line)
			for _, kw := range dataStoreKeywords {
				if strings.Contains(lowerLine, kw) && (strings.Contains(lowerLine, "connect") || strings.Contains(lowerLine, "open") || strings.Contains(lowerLine, "client")) {
					titleKw := strings.ToUpper(kw[:1]) + strings.ToLower(kw[1:])
					report.DataStores = append(report.DataStores, DataStore{
						Type:     titleKw,
						Location: fmt.Sprintf("%s:%d", rel, lineNum),
					})
					break
				}
			}

			// 4. Detect auth middleware
			if strings.Contains(lowerLine, "auth") || strings.Contains(lowerLine, "jwt") || strings.Contains(lowerLine, "passport") {
				if strings.Contains(lowerLine, "middleware") || strings.Contains(lowerLine, "use(") {
					report.AuthGuards = append(report.AuthGuards, AuthGuard{
						Name:     strings.TrimSpace(line),
						Location: fmt.Sprintf("%s:%d", rel, lineNum),
					})
				}
			}
		}

		return nil
	})

	// Map findings to STRIDE categories and update Exposure
	for i := range findings {
		f := &findings[i]
		strideCat, owaspCat := classifySTRIDE(f)

		// Check if file is on an entry point
		isExposed := false
		for _, ep := range report.EntryPoints {
			epFile := strings.Split(ep.Location, ":")[0]
			if strings.EqualFold(epFile, f.File) {
				isExposed = true
				break
			}
		}
		f.Exposed = &isExposed

		report.STRIDE = append(report.STRIDE, STRIDEItem{
			Category: strideCat,
			Finding:  *f,
			OWASP:    owaspCat,
		})
	}

	return report, nil
}

func classifySTRIDE(f *orchestrator.Finding) (string, string) {
	rule := strings.ToLower(f.Rule)
	cat := strings.ToLower(f.Category)
	cwe := strings.ToLower(f.CWE)

	if cat == orchestrator.CategorySecret || strings.Contains(rule, "token") || strings.Contains(rule, "auth") {
		return "Spoofing", "A07:2021-Identification and Authentication Failures"
	}
	if strings.Contains(rule, "sql") || strings.Contains(rule, "command") || strings.Contains(cwe, "cwe-89") || strings.Contains(cwe, "cwe-78") {
		return "Tampering", "A03:2021-Injection"
	}
	if strings.Contains(rule, "log") || strings.Contains(cwe, "cwe-117") {
		return "Repudiation", "A09:2021-Security Logging and Monitoring Failures"
	}
	if strings.Contains(rule, "leak") || strings.Contains(rule, "exposure") || strings.Contains(cwe, "cwe-200") {
		return "Information Disclosure", "A01:2021-Broken Access Control"
	}
	if cat == orchestrator.CategoryResilience || strings.Contains(rule, "timeout") || strings.Contains(rule, "body") || strings.Contains(cwe, "cwe-400") {
		return "Denial of Service", "A04:2021-Insecure Design"
	}
	if strings.Contains(rule, "root") || strings.Contains(rule, "privilege") || strings.Contains(cwe, "cwe-250") {
		return "Elevation of Privilege", "A01:2021-Broken Access Control"
	}

	return "Tampering", "A06:2021-Vulnerable and Outdated Components"
}

// RenderMarkdown outputs the Threat Model Report in Markdown format.
func (r *ThreatModelReport) RenderMarkdown() string {
	var sb strings.Builder
	sb.WriteString("# 🗺️ Threat Model & Trust Boundary Analysis\n\n")

	sb.WriteString("### 🚪 Identified Entry Points\n\n")
	if len(r.EntryPoints) == 0 {
		sb.WriteString("*No public entry points automatically detected.*\n\n")
	} else {
		sb.WriteString("| Type | Target / Route | Location |\n| :--- | :--- | :--- |\n")
		for _, ep := range r.EntryPoints {
			sb.WriteString(fmt.Sprintf("| %s | `%-20s` | `%s` |\n", ep.Type, ep.Target, ep.Location))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### 🗄️ Connected Data Stores\n\n")
	if len(r.DataStores) == 0 {
		sb.WriteString("*No persistence data store references detected.*\n\n")
	} else {
		sb.WriteString("| Store Type | Reference Location |\n| :--- | :--- |\n")
		for _, ds := range r.DataStores {
			sb.WriteString(fmt.Sprintf("| %s | `%s` |\n", ds.Type, ds.Location))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### 🛡️ STRIDE Threat Matrix\n\n")
	sb.WriteString("| STRIDE Category | OWASP Category | Finding ID | Severity | File Location |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")
	for _, item := range r.STRIDE {
		sb.WriteString(fmt.Sprintf("| **%s** | %s | `%s` | %s | `%s:%d` |\n",
			item.Category, item.OWASP, item.Finding.ID, item.Finding.Severity, item.Finding.File, item.Finding.LineStart))
	}

	return sb.String()
}
