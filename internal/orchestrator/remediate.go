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
	if f.FixSuggestion != nil {
		return f.FixSuggestion
	}

	switch f.Category {
	case CategorySCA:
		return generateSCABumpFix(repoPath, f)
	case CategorySecret:
		return generateSecretRotationFix(f)
	case CategoryIaC:
		return generateIaCFix(repoPath, f)
	case CategoryResilience:
		return generateResilienceFix(f)
	case CategorySAST:
		return generateSASTFix(f)
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

	// Extract package name and target version from messages like:
	// "Command Injection via template in lodash (lodash@4.17.15) - Upgrade package to 4.17.21"
	// or "Upgrade lodash from 4.17.15 to 4.17.21"
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

func generateSecretRotationFix(f *Finding) *Fix {
	return &Fix{
		Kind: FixKindManualAction,
		Description: fmt.Sprintf(
			"1. Immediately REVOKE and rotate the exposed credential.\n"+
				"2. Add %s to .gitignore if it contains sensitive tokens.\n"+
				"3. Use environment variables (e.g. process.env or os.Getenv) or a Secret Vault.\n"+
				"4. If committed to git history, rewrite history using `git filter-repo` or BFG Repo-Cleaner.",
			f.File,
		),
		Confidence: "high",
	}
}

func generateIaCFix(repoPath string, f *Finding) *Fix {
	baseName := strings.ToLower(filepath.Base(f.File))
	if strings.Contains(baseName, "dockerfile") {
		if strings.Contains(strings.ToLower(f.Message), "root") || strings.Contains(strings.ToLower(f.Rule), "root") {
			diff := fmt.Sprintf("--- %s\n+++ %s\n@@ -%d +%d @@\n+USER 10001:10001\n", f.File, f.File, f.LineStart, f.LineStart)
			return &Fix{
				Kind:        FixKindConfigPatch,
				Description: "Run container as a non-privileged user instead of root",
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

func generateResilienceFix(f *Finding) *Fix {
	return &Fix{
		Kind: FixKindCodePatch,
		Description: fmt.Sprintf(
			"Configure bounded limits to prevent denial-of-service / resource exhaustion: %s.\n"+
				"Ensure appropriate ReadTimeout, WriteTimeout, and rate-limiting middleware are in place.",
			f.Message,
		),
		Confidence: "high",
	}
}

func generateSASTFix(f *Finding) *Fix {
	// If rule or message mentions SQL injection, command injection, path traversal
	if strings.Contains(strings.ToLower(f.Rule), "sql") || strings.Contains(strings.ToLower(f.Message), "sql") {
		return &Fix{
			Kind:        FixKindCodePatch,
			Description: "Replace string concatenation or format string with parameterized/prepared statements.",
			Confidence:  "high",
		}
	}
	if strings.Contains(strings.ToLower(f.Rule), "path-traversal") || strings.Contains(strings.ToLower(f.Message), "path") {
		return &Fix{
			Kind:        FixKindCodePatch,
			Description: "Sanitize user-provided file paths with filepath.Clean and verify prefix within base directory.",
			Confidence:  "high",
		}
	}

	return &Fix{
		Kind:        FixKindCodePatch,
		Description: fmt.Sprintf("Remediate code flaw identified by rule %s (%s)", f.Rule, f.CWE),
		Confidence:  "medium",
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

	return "", fmt.Errorf("diff could not be cleanly matched against existing file content")
}
