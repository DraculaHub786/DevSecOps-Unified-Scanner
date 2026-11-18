package rules

import (
	"os/exec"
	"strings"
	"testing"
)

// TestRulePackLoads is a regression guard for the worst failure mode this project hit
// twice: one malformed rule pattern makes the entire YAML file unparseable, Semgrep then
// loads zero rules, and a scan reports "0 findings" — which reads as "your code is clean"
// when in fact nothing was scanned.
//
// It shells out to `semgrep --validate` because the Go code embeds the file rather than
// parsing it, so a syntax error is invisible to every other test.
func TestRulePackLoads(t *testing.T) {
	semgrepBin, err := exec.LookPath("semgrep")
	if err != nil {
		t.Skip("semgrep not installed; skipping rule pack validation")
	}

	out, _ := exec.Command(semgrepBin, "--validate", "--config", "sast-rules.yml").CombinedOutput()
	output := string(out)

	// The success line reads "found 0 configuration error(s)", so a naive substring
	// check for "configuration error" wrongly fails on a perfectly valid pack.
	// Match the success line explicitly instead.
	if !strings.Contains(output, "Configuration is valid") {
		t.Fatalf("rule pack failed to validate, which makes every scan report a false 'clean':\n%s", output)
	}
	// A pack that loads but yields zero rules is equally dangerous.
	if strings.Contains(output, "and 0 rule(s)") {
		t.Fatalf("rule pack validated but contains zero rules:\n%s", output)
	}
}
