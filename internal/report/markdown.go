package report

import (
	"fmt"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// GenerateMarkdown formats scan findings into a GitHub PR comment / Markdown report.
func GenerateMarkdown(result *orchestrator.ScanResult, failOn string) string {
	var sb strings.Builder

	passed := true
	failRank := orchestrator.SeverityRank(failOn)
	for _, f := range result.Findings {
		if orchestrator.SeverityRank(f.Severity) >= failRank {
			passed = false
			break
		}
	}

	sb.WriteString("# 🛡️ Sentinel DevSecOps Scan Summary\n\n")

	if passed {
		fmt.Fprintf(&sb, "> **Status: PASSED ✅** — No security findings exceeded the gating threshold (`%s`)\n\n", failOn)
	} else {
		fmt.Fprintf(&sb, "> **Status: FAILED ❌** — Critical/High findings violate the gating threshold (`%s`)\n\n", failOn)
	}

	sb.WriteString("### 📊 Scan Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **Duration** | `%d ms` |\n", result.DurationMs))
	sb.WriteString(fmt.Sprintf("| **Total Findings** | `%d` |\n", result.Summary.Total))
	sb.WriteString(fmt.Sprintf("| **Critical** | `%d` 🚨 |\n", result.Summary.Critical))
	sb.WriteString(fmt.Sprintf("| **High** | `%d` ⚠️ |\n", result.Summary.High))
	sb.WriteString(fmt.Sprintf("| **Medium** | `%d` 🟡 |\n", result.Summary.Medium))
	sb.WriteString(fmt.Sprintf("| **Low** | `%d` 🔵 |\n", result.Summary.Low))
	sb.WriteString(fmt.Sprintf("| **Info** | `%d` ℹ️ |\n\n", result.Summary.Info))

	if len(result.Coverage) > 0 {
		sb.WriteString("### 🛡️ Category Coverage\n\n")
		sb.WriteString("| Category | Status | Engine | Detail |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- |\n")
		for _, c := range result.Coverage {
			icon := "✅"
			switch c.Status {
			case "skipped":
				icon = "⚠️"
			case "failed":
				icon = "❌"
			case "not-applicable":
				icon = "➖"
			}
			detail := c.Detail
			if detail == "" {
				detail = "-"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | %s %s | `%s` | %s |\n", c.Category, icon, strings.ToUpper(c.Status), c.Engine, detail))
		}
		sb.WriteString("\n")
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("### ⚠️ Warnings\n\n")
		for _, w := range result.Warnings {
			sb.WriteString(fmt.Sprintf("- ⚠️ %s\n", w))
		}
		sb.WriteString("\n")
	}

	if len(result.Findings) == 0 {
		sb.WriteString("🎉 **Zero vulnerabilities or secrets detected! Your repository security posture is clean.**\n")
		return sb.String()
	}

	sb.WriteString("### 🔍 Security Findings\n\n")
	sb.WriteString("| ID | Category | Severity | Rule / Advisory | Location | Risk Score | OWASP | Fix Available |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

	for _, f := range result.Findings {
		fixBadge := "None"
		if f.FixSuggestion != nil {
			fixBadge = fmt.Sprintf("`%s`", f.FixSuggestion.Kind)
		}

		ref := f.Rule
		if f.CVE != "" {
			ref = f.CVE
		}

		sevIcon := "🔵"
		switch strings.ToLower(f.Severity) {
		case orchestrator.SeverityCritical:
			sevIcon = "🚨 Critical"
		case orchestrator.SeverityHigh:
			sevIcon = "⚠️ High"
		case orchestrator.SeverityMedium:
			sevIcon = "🟡 Medium"
		case orchestrator.SeverityLow:
			sevIcon = "🔵 Low"
		default:
			sevIcon = "ℹ️ Info"
		}

		owaspVal := f.OWASP
		if owaspVal == "" {
			owaspVal = "-"
		}
		sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s | `%s` | `%s:%d` | `%.1f` | `%s` | %s |\n",
			f.ID, f.Category, sevIcon, ref, f.File, f.LineStart, f.RiskScore, owaspVal, fixBadge))
	}

	sb.WriteString("\n### 🛠️ Remediation Guidance\n\n")
	for _, f := range result.Findings {
		if f.FixSuggestion == nil {
			continue
		}

		sb.WriteString(fmt.Sprintf("<details>\n<summary><b>%s (%s)</b>: %s</summary>\n\n", f.ID, f.Severity, f.Message))
		sb.WriteString(fmt.Sprintf("**Recommendation:** %s\n\n", f.FixSuggestion.Description))
		if f.FixSuggestion.Diff != "" {
			sb.WriteString("```diff\n")
			sb.WriteString(f.FixSuggestion.Diff)
			sb.WriteString("\n```\n\n")
			sb.WriteString(fmt.Sprintf("*Apply fix automatically with:* `sentinel fix %s --apply`\n\n", f.ID))
		}
		sb.WriteString("</details>\n\n")
	}

	return sb.String()
}
