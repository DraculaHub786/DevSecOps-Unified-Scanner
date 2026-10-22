package report

import (
	"fmt"
	"html"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// GenerateHTML produces a single self-contained HTML report with zero external CDN dependencies.
func GenerateHTML(result *orchestrator.ScanResult, failOn string) string {
	var sb strings.Builder

	passed := true
	failRank := orchestrator.SeverityRank(failOn)
	for _, f := range result.Findings {
		if orchestrator.SeverityRank(f.Severity) >= failRank {
			passed = false
			break
		}
	}

	statusColor := "#10b981"
	statusText := "PASSED"
	if !passed {
		statusColor = "#ef4444"
		statusText = "FAILED"
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel DevSecOps Scan Report</title>
<style>
  :root {
    --bg: #0f172a;
    --card-bg: #1e293b;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --border: #334155;
    --crit: #ef4444;
    --high: #f97316;
    --med: #eab308;
    --low: #38bdf8;
    --info: #a855f7;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 32px 20px;
    line-height: 1.5;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px; }
  h1 { margin: 0; font-size: 24px; display: flex; align-items: center; gap: 8px; }
  .badge { padding: 4px 10px; border-radius: 9999px; font-weight: 600; font-size: 13px; text-transform: uppercase; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
  .card-num { font-size: 28px; font-weight: 700; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }
  th { background: #162032; font-weight: 600; color: var(--text-muted); }
  tr:hover { background: #243249; }
  .sev-pill { font-weight: 600; text-transform: uppercase; font-size: 11px; padding: 2px 8px; border-radius: 4px; display: inline-block; }
  .sev-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid #ef4444; }
  .sev-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid #f97316; }
  .sev-medium { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }
  .sev-low { background: rgba(56, 189, 248, 0.2); color: #7dd3fc; border: 1px solid #38bdf8; }
  .code { font-family: monospace; font-size: 13px; background: #0b1120; padding: 2px 6px; border-radius: 4px; }
  .meta { color: var(--text-muted); font-size: 13px; margin-top: 4px; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ Sentinel DevSecOps Report</h1>
      <div class="meta">Target: <code>` + html.EscapeString(result.Discovery.RepoPath) + `</code> | Duration: ` + fmt.Sprintf("%d ms", result.DurationMs) + ` | Mode: ` + strings.ToUpper(result.Mode) + `</div>
    </div>
    <div>
      <span class="badge" style="background: ` + statusColor + `; color: white;">` + statusText + ` (Fail-on: ` + html.EscapeString(failOn) + `)</span>
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <div style="color: var(--text-muted); font-size: 13px;">Total Flaws</div>
      <div class="card-num">` + fmt.Sprintf("%d", result.Summary.Total) + `</div>
    </div>
    <div class="card">
      <div style="color: var(--crit); font-size: 13px;">Critical</div>
      <div class="card-num" style="color: var(--crit);">` + fmt.Sprintf("%d", result.Summary.Critical) + `</div>
    </div>
    <div class="card">
      <div style="color: var(--high); font-size: 13px;">High</div>
      <div class="card-num" style="color: var(--high);">` + fmt.Sprintf("%d", result.Summary.High) + `</div>
    </div>
    <div class="card">
      <div style="color: var(--med); font-size: 13px;">Medium</div>
      <div class="card-num" style="color: var(--med);">` + fmt.Sprintf("%d", result.Summary.Medium) + `</div>
    </div>
    <div class="card">
      <div style="color: var(--low); font-size: 13px;">Low</div>
      <div class="card-num" style="color: var(--low);">` + fmt.Sprintf("%d", result.Summary.Low) + `</div>
    </div>
  </div>
`)

	if len(result.Warnings) > 0 {
		sb.WriteString(`  <div style="background: rgba(234, 179, 8, 0.1); border: 1px solid #eab308; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px;">
    <h3 style="margin-top: 0; margin-bottom: 8px; color: #fde047; font-size: 15px;">⚠️ Scan Warnings</h3>
    <ul style="margin: 0; padding-left: 20px; color: #fef08a; font-size: 13px;">
`)
		for _, w := range result.Warnings {
			sb.WriteString(`      <li>` + html.EscapeString(w) + `</li>` + "\n")
		}
		sb.WriteString(`    </ul>
  </div>
`)
	}

	if len(result.Coverage) > 0 {
		sb.WriteString(`  <h2>🛡️ Category Coverage</h2>
  <table style="margin-bottom: 28px;">
    <thead>
      <tr>
        <th>Category</th>
        <th>Status</th>
        <th>Engine</th>
        <th>Detail</th>
      </tr>
    </thead>
    <tbody>
`)
		for _, c := range result.Coverage {
			statusBg := "rgba(16, 185, 129, 0.2)"
			statusCol := "#6ee7b7"
			if c.Status == "skipped" {
				statusBg = "rgba(234, 179, 8, 0.2)"
				statusCol = "#fde047"
			} else if c.Status == "failed" {
				statusBg = "rgba(239, 68, 68, 0.2)"
				statusCol = "#fca5a5"
			} else if c.Status == "not-applicable" {
				statusBg = "rgba(148, 163, 184, 0.2)"
				statusCol = "#94a3b8"
			}
			detail := c.Detail
			if detail == "" {
				detail = "-"
			}
			sb.WriteString(fmt.Sprintf(`      <tr>
        <td><b>%s</b></td>
        <td><span class="badge" style="background: %s; color: %s;">%s</span></td>
        <td><code>%s</code></td>
        <td style="color: var(--text-muted);">%s</td>
      </tr>
`, html.EscapeString(c.Category), statusBg, statusCol, html.EscapeString(strings.ToUpper(c.Status)), html.EscapeString(c.Engine), html.EscapeString(detail)))
		}
		sb.WriteString("    </tbody>\n  </table>\n")
	}

	sb.WriteString(`  <h2>Security Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>ID</th>
        <th>Category</th>
        <th>OWASP</th>
        <th>Engine</th>
        <th>File & Location</th>
        <th>Risk Score</th>
        <th>Rule / Message</th>
      </tr>
    </thead>
    <tbody>
`)

	if len(result.Findings) == 0 {
		sb.WriteString(`<tr><td colspan="8" style="text-align: center; padding: 32px; color: #10b981;">🎉 Clean repository! Zero security flaws identified.</td></tr>`)
	} else {
		for _, f := range result.Findings {
			sevClass := "sev-" + strings.ToLower(f.Severity)
			owaspTag := "-"
			if f.OWASP != "" {
				owaspTag = fmt.Sprintf(`<span class="badge" style="background: #334155; color: #93c5fd; font-size: 11px;">%s</span>`, html.EscapeString(f.OWASP))
			}
			fixHTML := ""
			if f.FixSuggestion != nil {
				fixHTML = fmt.Sprintf(`<div style="margin-top: 6px; font-size: 12px; color: #a5b4fc;"><b>💡 Fix (%s):</b> %s</div>`,
					html.EscapeString(f.FixSuggestion.Kind), html.EscapeString(f.FixSuggestion.Description))
			}

			sb.WriteString(fmt.Sprintf(`
      <tr>
        <td><span class="sev-pill %s">%s</span></td>
        <td><code>%s</code></td>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td>
        <td><code>%s:%d</code></td>
        <td><b>%.1f</b></td>
        <td>
          <b>%s</b>
          <div class="meta">%s</div>
          %s
        </td>
      </tr>`,
				sevClass, html.EscapeString(f.Severity),
				html.EscapeString(f.ID),
				html.EscapeString(f.Category),
				owaspTag,
				html.EscapeString(f.Engine),
				html.EscapeString(f.File), f.LineStart,
				f.RiskScore,
				html.EscapeString(f.Rule),
				html.EscapeString(f.Message),
				fixHTML,
			))
		}
	}

	sb.WriteString(`
    </tbody>
  </table>
  <footer style="margin-top: 32px; text-align: center; color: var(--text-muted); font-size: 13px;">
    Generated by Sentinel DevSecOps Unified Scanner • Local-First Security Engine
  </footer>
</div>
</body>
</html>`)

	return sb.String()
}
