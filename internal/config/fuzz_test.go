package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadFile hardens the YAML policy loader against hostile input (P-22).
// The seed corpus mirrors testdata/hostile and the KnownFields strictness that
// guards CI against a malicious .sentinel.yml.
func FuzzLoadFile(f *testing.F) {
	seeds := []string{
		"version: 1\nthresholds:\n  fail_on: high\n",
		"version: 1\nthresholds:\n  fail_on: critical\nignore:\n  findings:\n    - id: SENT-1\n      reason: audited\n",
		"",
		"version: 1\nunknown_key: oops\n",
		"version: 1\nthresholds:\n  fail_on: ../../etc/passwd\n",
		"version: -1\nignore:\n  paths: ['**', '*']\n",
		"version: 1\nignore:\n  findings:\n    - id: ''\n      reason: ''\n",
		"\x00\x01\x02\x03",
		"version: 1\n\tthresholds: [unclosed\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".sentinel.yml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Skip()
		}

		cfg, err := LoadFile(path)
		if err != nil {
			// A rejected policy is a valid outcome; the loader must never panic.
			return
		}
		if cfg == nil {
			t.Fatal("LoadFile returned nil config with nil error")
		}

		// Whatever loaded must survive the downstream helpers without panicking.
		_ = Audit(cfg)
		_ = cfg.ShouldIgnorePath("src/main.go")
		_ = cfg.ShouldIgnorePath("")
		_ = cfg.ShouldIgnoreFinding("SENT-000000000000")
	})
}

// FuzzShouldIgnorePath exercises the glob matcher directly, since CI policy trust
// depends on ignore paths never silently matching everything.
func FuzzShouldIgnorePath(f *testing.F) {
	f.Add("vendor/**", "vendor/lib/x.go")
	f.Add("**/*_test.go", "pkg/foo_test.go")
	f.Add("*", "anything")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, pattern, path string) {
		cfg := DefaultConfig()
		cfg.Ignore.Paths = []string{pattern}
		_ = cfg.ShouldIgnorePath(path)
	})
}
