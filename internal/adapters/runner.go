package adapters

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
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
