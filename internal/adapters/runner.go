package adapters

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

// ToolResult encapsulates stdout, stderr, and exit code from an external tool invocation.
type ToolResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// RunTool runs bin with an argument array (never string-concatenated shell commands),
// keeps stdout and stderr separate, and captures the exact exit code.
// err is non-nil only when the binary could not be started or the context was cancelled.
func RunTool(ctx context.Context, bin string, args ...string) (*ToolResult, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = &out, &errb

	runErr := cmd.Run()
	res := &ToolResult{
		Stdout: out.Bytes(),
		Stderr: errb.Bytes(),
	}

	if ctx.Err() != nil {
		return res, ctx.Err()
	}

	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		res.ExitCode = ee.ExitCode()
		return res, nil
	}

	return res, runErr
}

// LogEngineStderr writes engine stderr to .sentinel/logs/<engine>.log, bounded to 512KB.
// Returns the log file path relative to repoPath, or an empty string if stderr is empty.
func LogEngineStderr(repoPath, engine string, stderr []byte) string {
	if len(bytes.TrimSpace(stderr)) == 0 {
		return ""
	}
	logsDir := filepath.Join(repoPath, ".sentinel", "logs")
	_ = os.MkdirAll(logsDir, 0755)
	logFile := filepath.Join(logsDir, engine+".log")

	// Bound to max 512KB (keep most recent tail)
	const maxBytes = 512 * 1024
	toWrite := stderr
	if len(toWrite) > maxBytes {
		toWrite = toWrite[len(toWrite)-maxBytes:]
	}

	_ = os.WriteFile(logFile, toWrite, 0644)
	rel, err := filepath.Rel(repoPath, logFile)
	if err != nil {
		return filepath.ToSlash(logFile)
	}
	return filepath.ToSlash(rel)
}

// FindToolBinary searches for an external tool binary in system PATH, the local plugins/ directory,
// the binary's directory plugins, and standard user tool directories (Go bin, Python scripts).
func FindToolBinary(bin string) (string, error) {
	// 1. Standard LookPath in system PATH
	if path, err := exec.LookPath(bin); err == nil && path != "" {
		return path, nil
	}

	// Extensions to check
	exts := []string{""}
	if filepath.Ext(bin) == "" {
		exts = []string{".exe", ".cmd", ".bat", ""}
	}

	// 2. Candidate search locations
	var dirs []string
	// Relative plugins directories
	dirs = append(dirs, "plugins", filepath.Join("..", "plugins"), filepath.Join("..", "..", "plugins"))

	// Directory of the current running executable
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "plugins"))
		dirs = append(dirs, filepath.Dir(exe))
	}

	// Working directory plugins
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "plugins"))
	}

	// User home directories (Go bin, Python Scripts)
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Local", "Programs", "Python", "Python311", "Scripts"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Local", "Programs", "Python", "Python312", "Scripts"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Roaming", "Python", "Python311", "Scripts"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Roaming", "Python", "Python312", "Scripts"))
		dirs = append(dirs, filepath.Join(home, ".local", "bin"))
	}

	for _, d := range dirs {
		for _, ext := range exts {
			candidate := filepath.Join(d, bin+ext)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				if abs, err := filepath.Abs(candidate); err == nil {
					return abs, nil
				}
				return candidate, nil
			}
		}
	}

	return "", exec.ErrNotFound
}
