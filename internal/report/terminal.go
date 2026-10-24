package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// ANSI color escape sequences
var (
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorDim       = "\033[2m"
	colorRed       = "\033[31m"
	colorBrightRed = "\033[91m"
	colorYellow    = "\033[33m"
	colorGreen     = "\033[32m"
	colorCyan      = "\033[36m"
	colorGray      = "\033[90m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		DisableColors()
	}
}

// DisableColors strips all ANSI color codes from terminal output.
func DisableColors() {
	colorReset = ""
	colorBold = ""
	colorDim = ""
	colorRed = ""
	colorBrightRed = ""
	colorYellow = ""
	colorGreen = ""
	colorCyan = ""
	colorGray = ""
}

// RenderTerminal prints rich formatted scan findings to standard output.
func RenderTerminal(w io.Writer, result *orchestrator.ScanResult, failOn string) {
	fmt.Fprintf(w, "\n%s%s=========================================================================%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s   🛡️  SENTINEL DEVSECOPS UNIFIED SCANNER  🛡️%s\n", colorBold, colorGreen, colorReset)
	fmt.Fprintf(w, "%s%s=========================================================================%s\n\n", colorBold, colorCyan, colorReset)

	// Provenance line (P-16)
	var provItems []string
	catNameMap := map[string]string{
		"sast":       "SAST",
		"sca":        "SCA",
		"secrets":    "Secrets",
		"iac":        "IaC",
		"dast":       "DAST",
		"resilience": "Resilience",
	}
	engineToolMap := map[string]string{
		"sast":       "semgrep",
		"sca":        "osv-scanner",
		"secrets":    "gitleaks",
		"iac":        "trivy",
		"dast":       "nuclei",
		"resilience": "native",
	}
	for _, c := range result.Coverage {
		if c.Status == "not-applicable" || c.Status == "skipped" {
			continue
		}
		label := catNameMap[c.Category]
		if label == "" {
			label = strings.ToUpper(c.Category)
		}
		tool := engineToolMap[c.Category]
		if tool == "" {
			tool = c.Category
		}
		if c.Engine == orchestrator.EngineNative {
			provItems = append(provItems, fmt.Sprintf("%s: native", label))
		} else if c.Status == "degraded" {
			provItems = append(provItems, fmt.Sprintf("%s: %s (degraded)", label, tool))
		} else if c.Engine == orchestrator.EngineExternal {
			provItems = append(provItems, fmt.Sprintf("%s: %s (external)", label, tool))
		} else {
			provItems = append(provItems, fmt.Sprintf("%s: %s (embedded)", label, tool))
		}
	}

	modeStr := fmt.Sprintf("%sMode:%s %sFULL%s", colorDim, colorReset, colorGreen, colorReset)
	if result.Mode == "lite" {
		modeStr = fmt.Sprintf("%sMode:%s %sLITE%s (fallback engines in use)", colorDim, colorReset, colorYellow, colorReset)
	}

	repoPath := "."
	if result.Discovery != nil && result.Discovery.RepoPath != "" {
		repoPath = result.Discovery.RepoPath
	}

	fmt.Fprintf(w, "%sTarget:%s %s  %sDuration:%s %dms  %s\n",
		colorDim, colorReset, repoPath,
		colorDim, colorReset, result.DurationMs,
		modeStr,
	)
	if len(provItems) > 0 {
		fmt.Fprintf(w, "%sProvenance:%s %s\n", colorDim, colorReset, strings.Join(provItems, " · "))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Summary: %s%d Critical%s | %s%d High%s | %s%d Medium%s | %s%d Low%s | %d Info\n\n",
		colorBrightRed, result.Summary.Critical, colorReset,
		colorRed, result.Summary.High, colorReset,
		colorYellow, result.Summary.Medium, colorReset,
		colorCyan, result.Summary.Low, colorReset,
		result.Summary.Info,
	)

	if len(result.Warnings) > 0 {
		fmt.Fprintf(w, "%s⚠️ Warnings:%s\n", colorYellow, colorReset)
		for _, warn := range result.Warnings {
			fmt.Fprintf(w, "  • %s%s%s\n", colorYellow, warn, colorReset)
		}
		fmt.Fprintln(w)
	}

	if len(result.Coverage) > 0 {
		fmt.Fprintf(w, "%sCategory Coverage:%s\n", colorBold, colorReset)
		for _, c := range result.Coverage {
			statusColor := colorGreen
			switch c.Status {
			case "skipped":
				statusColor = colorYellow
			case "degraded":
				statusColor = colorYellow
			case "failed":
				statusColor = colorRed
			case "not-applicable":
				statusColor = colorDim
			}
			detail := ""
			if c.Detail != "" {
				detail = fmt.Sprintf(" (%s)", c.Detail)
			}
			fmt.Fprintf(w, "  • %-12s [%s%s%s via %s]%s\n", c.Category, statusColor, strings.ToUpper(c.Status), colorReset, c.Engine, detail)
		}
		fmt.Fprintln(w)
	}

	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "%s%s✨ No security flaws or secrets identified. Repository is clean!%s\n\n", colorBold, colorGreen, colorReset)
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%sSEV\tID\tCAT\tENGINE\tLOCATION\tRISK\tRULE / SUMMARY%s\n", colorBold, colorReset)
	fmt.Fprintf(tw, "%s---\t--\t---\t------\t--------\t----\t--------------%s\n", colorDim, colorReset)

	for _, f := range result.Findings {
		sevColor := colorGray
		switch strings.ToLower(f.Severity) {
		case orchestrator.SeverityCritical:
			sevColor = colorBrightRed
		case orchestrator.SeverityHigh:
			sevColor = colorRed
		case orchestrator.SeverityMedium:
			sevColor = colorYellow
		case orchestrator.SeverityLow:
			sevColor = colorCyan
		}
		locStr := fmt.Sprintf("%s:%d", f.File, f.LineStart)
		locRunes := []rune(locStr)
		if len(locRunes) > 28 {
			locStr = "..." + string(locRunes[len(locRunes)-25:])
		}

		msg := f.Message
		msgRunes := []rune(msg)
		if len(msgRunes) > 55 {
			msg = string(msgRunes[:52]) + "..."
		}

		engLabel := "ext"
		if f.Engine == orchestrator.EngineEmbedded {
			engLabel = "lite"
		} else if f.Engine == orchestrator.EngineNative {
			engLabel = "native"
		}

		fmt.Fprintf(tw, "%s%s%s\t%s\t%s\t%s\t%s\t%.1f\t%s\n",
			sevColor, sevLabel(f.Severity), colorReset,
			f.ID,
			f.Category,
			engLabel,
			locStr,
			f.RiskScore,
			msg,
		)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%sTip: Use %ssentinel explain <id>%s to view rule remediation details.%s\n", colorDim, colorBold, colorDim, colorReset)
	fmt.Fprintf(w, "%sTip: Use %ssentinel fix <id> --apply%s to preview and apply automated patch.%s\n\n", colorDim, colorBold, colorDim, colorReset)

	failRank := orchestrator.SeverityRank(failOn)
	failed := false
	for _, f := range result.Findings {
		if orchestrator.SeverityRank(f.Severity) >= failRank {
			failed = true
			break
		}
	}

	if failed {
		fmt.Fprintf(w, "%s%s❌ Gating failure: findings exceed fail-on threshold (%s)%s\n", colorBold, colorRed, failOn, colorReset)
	} else {
		fmt.Fprintf(w, "%s%s✅ Gating check passed (below %s threshold)%s\n", colorBold, colorGreen, failOn, colorReset)
	}
}

func sevLabel(s string) string {
	switch strings.ToLower(s) {
	case orchestrator.SeverityCritical:
		return "CRIT"
	case orchestrator.SeverityHigh:
		return "HIGH"
	case orchestrator.SeverityMedium:
		return "MED"
	case orchestrator.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

