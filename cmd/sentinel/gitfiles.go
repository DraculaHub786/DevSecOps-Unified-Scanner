package main

import (
	"os/exec"
	"strings"
)

// gitStagedFiles returns files staged for the next commit (added/copied/modified).
// Deletions are excluded: there is nothing left to scan.
func gitStagedFiles(repoPath string) []string {
	return gitLines(repoPath, "diff", "--cached", "--name-only", "--diff-filter=ACM")
}

// gitPushedFiles returns files changed in the commits that would be pushed.
// Falls back to the staged set when no upstream is configured (first push).
func gitPushedFiles(repoPath string) []string {
	files := gitLines(repoPath, "diff", "--name-only", "--diff-filter=ACM", "@{upstream}...HEAD")
	if len(files) > 0 {
		return files
	}
	files = gitLines(repoPath, "log", "--name-only", "--pretty=format:", "--diff-filter=ACM", "HEAD")
	if len(files) > 0 {
		return files
	}
	return gitStagedFiles(repoPath)
}

// gitLines runs a git subcommand inside repoPath and returns non-empty trimmed lines.
func gitLines(repoPath string, args ...string) []string {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// filterScannable keeps only paths whose extension we can meaningfully analyse, so a
// commit touching only images or lockfiles does not pay for a scan.
func filterScannable(paths []string) []string {
	scannableExt := []string{
		".go", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".java",
		".rb", ".php", ".cs", ".tf", ".yaml", ".yml", ".json", ".txt",
		".env", ".sh", ".ps1",
	}
	var kept []string
	for _, p := range paths {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "dockerfile") {
			kept = append(kept, p)
			continue
		}
		for _, ext := range scannableExt {
			if strings.HasSuffix(lower, ext) {
				kept = append(kept, p)
				break
			}
		}
	}
	return kept
}
