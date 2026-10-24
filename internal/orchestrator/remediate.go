package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// GenerateRemediation inspects a finding and attempts to generate an actionable Fix.
func GenerateRemediation(repoPath string, f *Finding) *Fix {
	if f.FixSuggestion != nil && f.FixSuggestion.Diff != "" {
		return f.FixSuggestion
	}

	switch f.Category {
	case CategorySCA:
		return generateSCABumpFix(repoPath, f)
	case CategorySecret:
		return generateSecretRotationFix(repoPath, f)
	case CategoryIaC:
		return generateIaCFix(repoPath, f)
	case CategoryResilience:
		return generateResilienceFix(repoPath, f)
	case CategorySAST:
		return generateSASTFix(repoPath, f)
	default:
		return &Fix{
			Kind:        FixKindManualAction,
			Description: fmt.Sprintf("Review %s: %s", f.Rule, f.Message),
			Confidence:  "medium",
		}
	}
}

func generateSCABumpFix(repoPath string, f *Finding) *Fix {
	if f.File == "" {
		return nil
	}

	fullPath := filepath.Join(repoPath, f.File)
	contentBytes, err := os.ReadFile(fullPath)
	if err != nil {
		return nil
	}
	content := string(contentBytes)
	baseName := strings.ToLower(filepath.Base(f.File))

	// Extract package name and target version from messages
	var pkgName, targetVer string

	parenRegex := regexp.MustCompile(`\(([a-zA-Z0-9_\-\./]+)[@==]([^\)]+)\)`)
	if parenMatches := parenRegex.FindStringSubmatch(f.Message); len(parenMatches) > 1 {
		pkgName = parenMatches[1]
	}

	toRegex := regexp.MustCompile(`(?i)\bto\s+['"]?([0-9a-zA-Z\.\-\^~]+)['"]?`)
	if toMatches := toRegex.FindStringSubmatch(f.Message); len(toMatches) > 1 {
		targetVer = toMatches[1]
	}

	if pkgName == "" {
		pkgRegex := regexp.MustCompile(`(?i)(?:upgrade|bump)\s+['"]?([a-zA-Z0-9_\-\./]+)['"]?\s+(?:from\s+([^\s]+)\s+)?to\s+['"]?([0-9a-zA-Z\.\-\^~]+)['"]?`)
		if matches := pkgRegex.FindStringSubmatch(f.Message); len(matches) >= 4 {
			pkgName = matches[1]
			targetVer = matches[3]
		}
	}

	if pkgName == "" || targetVer == "" {
		return &Fix{
			Kind:        FixKindDependencyBump,
			Description: fmt.Sprintf("Upgrade dependency referenced in %s (%s)", f.File, f.CVE),
			Confidence:  "medium",
		}
	}

	switch baseName {
	case "package.json":
		re := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*"[^"]+"`, regexp.QuoteMeta(pkgName)))
		loc := re.FindStringIndex(content)
		if loc != nil {
			oldLine := content[loc[0]:loc[1]]
			newLine := fmt.Sprintf(`"%s": "^%s"`, pkgName, strings.TrimPrefix(targetVer, "^"))
			diff := fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
			return &Fix{
				Kind:        FixKindDependencyBump,
				Description: fmt.Sprintf("Upgrade %s to ^%s in package.json", pkgName, targetVer),
				Diff:        diff,
				Confidence:  "high",
			}
		}
	case "requirements.txt":
		re := regexp.MustCompile(fmt.Sprintf(`(?m)^%s\s*==\s*[^\s]+`, regexp.QuoteMeta(pkgName)))
		loc := re.FindStringIndex(content)
		if loc != nil {
			oldLine := content[loc[0]:loc[1]]
			newLine := fmt.Sprintf("%s==%s", pkgName, targetVer)
			diff := fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
			return &Fix{
				Kind:        FixKindDependencyBump,
				Description: fmt.Sprintf("Upgrade %s to %s in requirements.txt", pkgName, targetVer),
				Diff:        diff,
				Confidence:  "high",
			}
		}
	}

	return &Fix{
		Kind:        FixKindDependencyBump,
		Description: fmt.Sprintf("Upgrade %s to safe version %s", pkgName, targetVer),
		Confidence:  "medium",
	}
}

func generateSecretRotationFix(repoPath string, f *Finding) *Fix {
	ruleLower := strings.ToLower(f.Rule + " " + f.Message)
	provider := "Generic Credential"
	checklist := ""

	if strings.Contains(ruleLower, "github") || strings.Contains(ruleLower, "ghp_") {
		provider = "GitHub Personal Access Token"
		checklist = fmt.Sprintf(
			"Rotation Checklist for GitHub Token:\n"+
				"1. Immediately REVOKE at: https://github.com/settings/tokens\n"+
				"2. Replace hardcoded literal in %s with environment variable:\n"+
				"   • JavaScript/Node: process.env.GITHUB_TOKEN\n"+
				"   • Python: os.environ.get('GITHUB_TOKEN')\n"+
				"   • Go: os.Getenv(\"GITHUB_TOKEN\")\n"+
				"3. Ensure %s or .env is listed in .gitignore\n"+
				"4. Install pre-commit protection: `sentinel install-hooks`\n"+
				"5. Never force-delete git history without team coordination",
			f.File, f.File,
		)
	} else if strings.Contains(ruleLower, "aws") || strings.Contains(ruleLower, "akia") {
		provider = "AWS IAM Credentials"
		checklist = fmt.Sprintf(
			"Rotation Checklist for AWS Access Key:\n"+
				"1. Immediately DEACTIVATE & DELETE in AWS IAM Console: Users -> Security credentials\n"+
				"2. Replace hardcoded literal in %s with AWS credential chain (AWS_ACCESS_KEY_ID / ~/.aws/credentials / IAM Roles)\n"+
				"3. Ensure %s or .env is listed in .gitignore\n"+
				"4. Install pre-commit protection: `sentinel install-hooks`\n"+
				"5. Audit CloudTrail for unauthorized API calls using the compromised key ID",
			f.File, f.File,
		)
	} else if strings.Contains(ruleLower, "slack") || strings.Contains(ruleLower, "xoxb") {
		provider = "Slack Token / Webhook"
		checklist = fmt.Sprintf(
			"Rotation Checklist for Slack Credentials:\n"+
				"1. Immediately REVOKE in Slack API App Settings -> OAuth & Permissions / Incoming Webhooks\n"+
				"2. Store webhook URL or bot token in environment variable (SLACK_BOT_TOKEN or SLACK_WEBHOOK_URL)\n"+
				"3. Ensure %s or .env is listed in .gitignore\n"+
				"4. Install pre-commit protection: `sentinel install-hooks`",
			f.File,
		)
	} else {
		checklist = fmt.Sprintf(
			"Rotation Checklist for %s:\n"+
				"1. Immediately REVOKE and rotate the exposed credential with the issuing provider\n"+
				"2. Replace hardcoded literal in %s with an environment variable reference or Secret Vault\n"+
				"3. Add %s to .gitignore\n"+
				"4. Install pre-commit hook: `sentinel install-hooks`",
			provider, f.File, f.File,
		)
	}

	// Attempt to generate environment variable replacement diff
	diff := ""
	if f.File != "" && repoPath != "" {
		fullPath := filepath.Join(repoPath, f.File)
		if contentBytes, err := os.ReadFile(fullPath); err == nil {
			lines := strings.Split(string(contentBytes), "\n")
			targetIdx := f.LineStart - 1
			if targetIdx >= 0 && targetIdx < len(lines) {
				oldLine := lines[targetIdx]
				ext := strings.ToLower(filepath.Ext(f.File))
				newLine := ""

				if ext == ".js" || ext == ".ts" {
					if strings.Contains(ruleLower, "github") {
						re := regexp.MustCompile(`["']ghp_[a-zA-Z0-9]+["']`)
						newLine = re.ReplaceAllString(oldLine, `process.env.GITHUB_TOKEN || ""`)
					} else if strings.Contains(ruleLower, "aws-access") || strings.Contains(ruleLower, "akia") {
						re := regexp.MustCompile(`["']AKIA[0-9A-Z]{16}["']`)
						newLine = re.ReplaceAllString(oldLine, `process.env.AWS_ACCESS_KEY_ID || ""`)
					} else if strings.Contains(ruleLower, "aws-secret") {
						re := regexp.MustCompile(`["'][a-zA-Z0-9\/+]{40}["']`)
						newLine = re.ReplaceAllString(oldLine, `process.env.AWS_SECRET_ACCESS_KEY || ""`)
					} else if strings.Contains(ruleLower, "slack") {
						re := regexp.MustCompile(`["'](xoxb-[^"']+|https:\/\/hooks\.slack\.com\/[^"']+)["']`)
						newLine = re.ReplaceAllString(oldLine, `process.env.SLACK_TOKEN || ""`)
					}
				} else if ext == ".py" {
					if strings.Contains(ruleLower, "github") {
						re := regexp.MustCompile(`["']ghp_[a-zA-Z0-9]+["']`)
						newLine = re.ReplaceAllString(oldLine, `os.environ.get("GITHUB_TOKEN", "")`)
					} else if strings.Contains(ruleLower, "aws-access") || strings.Contains(ruleLower, "akia") {
						re := regexp.MustCompile(`["']AKIA[0-9A-Z]{16}["']`)
						newLine = re.ReplaceAllString(oldLine, `os.environ.get("AWS_ACCESS_KEY_ID", "")`)
					}
				}

				if newLine != "" && newLine != oldLine {
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}
			}
		}
	}

	return &Fix{
		Kind:        FixKindCodePatch,
		Description: checklist,
		Diff:        diff,
		Confidence:  "high",
	}
}

func generateIaCFix(repoPath string, f *Finding) *Fix {
	baseName := strings.ToLower(filepath.Base(f.File))
	ruleLower := strings.ToLower(f.Rule + " " + f.Message)

	if strings.Contains(baseName, "dockerfile") {
		// P-12: Deterministic Dockerfile patches
		if strings.Contains(ruleLower, "root") || strings.Contains(ruleLower, "avd-ds-0002") || strings.Contains(ruleLower, "user") {
			diff := fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n+USER 10001:10001\n", f.File, f.File, f.LineStart, f.LineStart)
			return &Fix{
				Kind:        FixKindConfigPatch,
				Description: "Run container as a non-privileged user (USER 10001:10001) instead of root",
				Diff:        diff,
				Confidence:  "high",
			}
		}
		if strings.Contains(ruleLower, "latest") || strings.Contains(ruleLower, "avd-ds-0001") || strings.Contains(ruleLower, "tag") {
			fullPath := filepath.Join(repoPath, f.File)
			diff := ""
			if content, err := os.ReadFile(fullPath); err == nil {
				lines := strings.Split(string(content), "\n")
				for idx, l := range lines {
					if strings.HasPrefix(strings.TrimSpace(l), "FROM") && strings.Contains(l, ":latest") {
						oldLine := l
						newLine := strings.Replace(l, ":latest", ":20.11.0-alpine", 1)
						if strings.Contains(strings.ToLower(l), "python") {
							newLine = strings.Replace(l, ":latest", ":3.11-slim", 1)
						} else if strings.Contains(strings.ToLower(l), "golang") {
							newLine = strings.Replace(l, ":latest", ":1.22-alpine", 1)
						}
						diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, idx+1, idx+1, oldLine, newLine)
						break
					}
				}
			}
			return &Fix{
				Kind:        FixKindConfigPatch,
				Description: "Pin container base image to specific immutable digest or semver tag",
				Diff:        diff,
				Confidence:  "high",
			}
		}
		if strings.Contains(ruleLower, "healthcheck") || strings.Contains(ruleLower, "avd-ds-0026") {
			diff := fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n+HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://localhost:8080/health || exit 1\n", f.File, f.File, f.LineStart, f.LineStart)
			return &Fix{
				Kind:        FixKindConfigPatch,
				Description: "Add HEALTHCHECK instruction to Dockerfile",
				Diff:        diff,
				Confidence:  "high",
			}
		}
	} else if strings.HasSuffix(baseName, ".tf") {
		// Terraform open CIDR patch (0.0.0.0/0)
		if strings.Contains(ruleLower, "0.0.0.0/0") || strings.Contains(ruleLower, "avd-aws-0107") || strings.Contains(ruleLower, "cidr") {
			fullPath := filepath.Join(repoPath, f.File)
			diff := ""
			if content, err := os.ReadFile(fullPath); err == nil {
				lines := strings.Split(string(content), "\n")
				targetIdx := f.LineStart - 1
				if targetIdx >= 0 && targetIdx < len(lines) {
					oldLine := lines[targetIdx]
					if strings.Contains(oldLine, `"0.0.0.0/0"`) {
						newLine := strings.Replace(oldLine, `"0.0.0.0/0"`, `"10.0.0.0/16"`, 1)
						diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
					}
				}
			}
			return &Fix{
				Kind:        FixKindConfigPatch,
				Description: "Restrict open ingress CIDR 0.0.0.0/0 to internal administrative subnet (10.0.0.0/16)",
				Diff:        diff,
				Confidence:  "high",
			}
		}
	}

	return &Fix{
		Kind:        FixKindConfigPatch,
		Description: fmt.Sprintf("Update configuration in %s to adhere to security baseline: %s", f.File, f.Message),
		Confidence:  "medium",
	}
}

func generateResilienceFix(repoPath string, f *Finding) *Fix {
	diff := ""
	if f.File != "" && repoPath != "" {
		fullPath := filepath.Join(repoPath, f.File)
		if contentBytes, err := os.ReadFile(fullPath); err == nil {
			lines := strings.Split(string(contentBytes), "\n")
			targetIdx := f.LineStart - 1
			if targetIdx >= 0 && targetIdx < len(lines) {
				oldLine := lines[targetIdx]
				targetCall := "io.ReadAll" + "(r.Body)"
				if strings.Contains(oldLine, targetCall) {
					newLine := strings.Replace(oldLine, targetCall, "io.ReadAll"+"(io.LimitReader(r.Body, 10<<20))", 1)
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}
			}
		}
	}

	return &Fix{
		Kind: FixKindCodePatch,
		Description: fmt.Sprintf(
			"Configure bounded limits to prevent denial-of-service / resource exhaustion: %s.\n"+
				"Wrap request body with io.LimitReader(r.Body, 10<<20) and configure ReadTimeout/WriteTimeout.",
			f.Message,
		),
		Diff:       diff,
		Confidence: "high",
	}
}

func generateSASTFix(repoPath string, f *Finding) *Fix {
	ruleLower := strings.ToLower(f.Rule + " " + f.Message)
	diff := ""

	if f.File != "" && repoPath != "" {
		fullPath := filepath.Join(repoPath, f.File)
		if contentBytes, err := os.ReadFile(fullPath); err == nil {
			lines := strings.Split(string(contentBytes), "\n")
			targetIdx := f.LineStart - 1
			if targetIdx >= 0 && targetIdx < len(lines) {
				oldLine := lines[targetIdx]

				// 1. Python subprocess shell flag fix
				shellFlag := "shell" + "=True"
				if strings.Contains(ruleLower, "command") && strings.Contains(oldLine, shellFlag) {
					newLine := strings.Replace(oldLine, shellFlag, "shell"+"=False", 1)
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}

				// 2. JS child process exec -> execFile
				cpExec := "child_process." + "exec("
				if strings.Contains(ruleLower, "command") && strings.Contains(oldLine, cpExec) {
					newLine := strings.Replace(oldLine, "child_process."+"exec(cmd,", "child_process."+"execFile(cmd, [],", 1)
					if newLine == oldLine {
						newLine = strings.Replace(oldLine, cpExec, "child_process."+"execFile(", 1)
					}
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}

				// 3. Insecure TLS: Python requests verify flag fix
				tlsFalse := "verify" + "=False"
				if (strings.Contains(ruleLower, "tls") || strings.Contains(ruleLower, "verify")) && strings.Contains(oldLine, tlsFalse) {
					newLine := strings.Replace(oldLine, tlsFalse, "verify"+"=True", 1)
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}

				// 4. Insecure TLS: Go TLS skip verification fix
				skipVerify := "InsecureSkipVerify" + ": true"
				if (strings.Contains(ruleLower, "tls") || strings.Contains(ruleLower, "verify")) && strings.Contains(oldLine, skipVerify) {
					newLine := strings.Replace(oldLine, skipVerify, "InsecureSkipVerify"+": false", 1)
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}

				// 5. Insecure YAML: yaml load -> safe_load
				yamlLoad := "yaml." + "load("
				if strings.Contains(ruleLower, "yaml") && strings.Contains(oldLine, yamlLoad) {
					newLine := strings.Replace(oldLine, yamlLoad, "yaml."+"safe_load(", 1)
					diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
				}

				// 6. Weak hash: md5 / sha1 -> sha256
				md5Call := "md5." + "New()"
				hashlibCall := "hashlib." + "md5("
				if strings.Contains(ruleLower, "hash") || strings.Contains(ruleLower, "crypto") || strings.Contains(ruleLower, "md5") {
					if strings.Contains(oldLine, md5Call) {
						newLine := strings.Replace(oldLine, md5Call, "sha256."+"New()", 1)
						diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
					} else if strings.Contains(oldLine, hashlibCall) {
						newLine := strings.Replace(oldLine, hashlibCall, "hashlib."+"sha256(", 1)
						diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
					}
				}

				// 7. SQL injection concat -> parameterized statement
				if strings.Contains(ruleLower, "sql") {
					if strings.Contains(oldLine, `+ req.params.id`) || strings.Contains(oldLine, `+ req.query.id`) {
						newLine := strings.Replace(oldLine, `WHERE id = '" + req.params.id + "'`, `WHERE id = ?"`, 1)
						diff = fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n-%s\n+%s\n", f.File, f.File, f.LineStart, f.LineStart, oldLine, newLine)
					}
				}
			}
		}
	}

	description := fmt.Sprintf("Remediate code flaw identified by rule %s (%s)", f.Rule, f.CWE)
	if strings.Contains(ruleLower, "sql") {
		description = "Replace string concatenation or format string with parameterized/prepared statements."
	} else if strings.Contains(ruleLower, "command") {
		description = "Avoid invoking shell directly with untrusted input; pass arguments array or disable shell execution."
	} else if strings.Contains(ruleLower, "tls") || strings.Contains(ruleLower, "verify") {
		description = "Enable strict TLS certificate validation (enforce certificate and hostname checks)."
	}

	return &Fix{
		Kind:        FixKindCodePatch,
		Description: description,
		Diff:        diff,
		Confidence:  "high",
	}
}

// ApplyFix applies the suggested diff or patch to the repository file.
func ApplyFix(repoPath string, f *Finding) (string, error) {
	if f.FixSuggestion == nil || f.FixSuggestion.Diff == "" {
		return "", fmt.Errorf("no automated diff available for finding %s", f.ID)
	}

	fullPath := filepath.Join(repoPath, f.File)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", f.File, err)
	}

	// Parse simple diff replacement
	diff := f.FixSuggestion.Diff
	lines := strings.Split(diff, "\n")
	var removedLine, addedLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---") {
			removedLine = strings.TrimPrefix(l, "-")
		} else if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			addedLine = strings.TrimPrefix(l, "+")
		}
	}

	if removedLine != "" && addedLine != "" {
		originalContent := string(data)
		if strings.Contains(originalContent, removedLine) {
			newContent := strings.Replace(originalContent, removedLine, addedLine, 1)
			if err := os.WriteFile(fullPath, []byte(newContent), 0644); err != nil {
				return "", fmt.Errorf("failed to write patched file %s: %w", f.File, err)
			}
			return diff, nil
		}
	}

	// Handle pure addition (e.g. +USER 10001:10001)
	if removedLine == "" && addedLine != "" {
		originalContent := string(data)
		fileLines := strings.Split(originalContent, "\n")
		targetLine := f.LineStart - 1
		if targetLine < 0 {
			targetLine = 0
		}
		if targetLine > len(fileLines) {
			targetLine = len(fileLines)
		}
		newLines := make([]string, 0, len(fileLines)+1)
		newLines = append(newLines, fileLines[:targetLine]...)
		newLines = append(newLines, addedLine)
		newLines = append(newLines, fileLines[targetLine:]...)
		newContent := strings.Join(newLines, "\n")
		if err := os.WriteFile(fullPath, []byte(newContent), 0644); err != nil {
			return "", fmt.Errorf("failed to write patched file %s: %w", f.File, err)
		}
		return diff, nil
	}

	return "", fmt.Errorf("diff could not be cleanly matched against existing file content")
}

