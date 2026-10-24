package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSubprocessSafetyInvariant enforces that production Go code never invokes shell strings (sh -c / bash -c / cmd.exe /c).
// All subprocess calls MUST pass argument arrays directly to exec.CommandContext.
func TestSubprocessSafetyInvariant(t *testing.T) {
	rootDirs := []string{
		filepath.Join("..", "adapters"),
		filepath.Join("..", "orchestrator"),
		filepath.Join("..", "doctor"),
		filepath.Join("..", "report"),
		filepath.Join("..", "threatmodel"),
		filepath.Join("..", "..", "cmd"),
	}

	for _, dir := range rootDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			content := string(data)

			// Prohibit unsafe shell invocation patterns
			if strings.Contains(content, `exec.Command("sh"`) ||
				strings.Contains(content, `exec.CommandContext(ctx, "sh"`) ||
				strings.Contains(content, `exec.Command("bash"`) ||
				strings.Contains(content, `exec.Command("cmd"`) ||
				strings.Contains(content, `exec.Command("powershell"`) {
				t.Errorf("Security invariant violation in %s: prohibited shell wrapper detected; pass binary and argument array directly", path)
			}

			return nil
		})
	}
}
