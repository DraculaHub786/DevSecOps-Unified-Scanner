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
