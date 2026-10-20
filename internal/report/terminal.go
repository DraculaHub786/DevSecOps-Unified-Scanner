package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// ANSI color escape sequences
const (
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

// RenderTerminal prints rich formatted scan findings to standard output.
func RenderTerminal(w io.Writer, result *orchestrator.ScanResult, failOn string) {
	fmt.Fprintf(w, "\n%s%s=========================================================================%s\n", colorBold, colorCyan, colorReset)
	fmt.Fprintf(w, "%s%s   🛡️  SENTINEL DEVSECOPS UNIFIED SCANNER  🛡️%s\n", colorBold, colorGreen, colorReset)
	fmt.Fprintf(w, "%s%s=========================================================================%s\n\n", colorBold, colorCyan, colorReset)

	// Mode description
	var extList, embList []string
	for adName, eng := range result.Engines {
		if eng == orchestrator.EngineExternal {
			extList = append(extList, adName)
		} else {
			embList = append(embList, adName)
		}
	}

	modeStr := fmt.Sprintf("%sMode:%s %s%s%s", colorDim, colorReset, colorGreen, strings.ToUpper(result.Mode), colorReset)
	if result.Mode == "lite" {
		modeStr = fmt.Sprintf("%sMode:%s %sLITE%s (embedded lite engines: %s)", colorDim, colorReset, colorYellow, colorReset, strings.Join(embList, ", "))
	} else if len(extList) > 0 {
		modeStr = fmt.Sprintf("%sMode:%s %sFULL%s (%d external engines: %s)", colorDim, colorReset, colorGreen, colorReset, len(extList), strings.Join(extList, ", "))
	}

	fmt.Fprintf(w, "%sTarget:%s %s  %sDuration:%s %dms  %s\n",
		colorDim, colorReset, result.Discovery.RepoPath,
		colorDim, colorReset, result.DurationMs,
		modeStr,
	)

	fmt.Fprintf(w, "Summary: %s%d Critical%s | %s%d High%s | %s%d Medium%s | %s%d Low%s | %d Info\n\n",
		colorBrightRed, result.Summary.Critical, colorReset,
		colorRed, result.Summary.High, colorReset,
		colorYellow, result.Summary.Medium, colorReset,
		colorCyan, result.Summary.Low, colorReset,
		result.Summary.Info,
	)

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

		location := fmt.Sprintf("%s:%d", f.File, f.LineStart)
		if len(location) > 28 {
			location = "..." + location[len(location)-25:]
		}

		msg := f.Message
		if len(msg) > 55 {
			msg = msg[:52] + "..."
		}

		engLabel := "ext"
		if f.Engine == orchestrator.EngineEmbedded {
			engLabel = "lite"
		}

		fmt.Fprintf(tw, "%s%s%s\t%s\t%s\t%s\t%s\t%.1f\t%s\n",
			sevColor, strings.ToUpper(f.Severity[:4]), colorReset,
			f.ID,
			f.Category,
			engLabel,
			location,
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
