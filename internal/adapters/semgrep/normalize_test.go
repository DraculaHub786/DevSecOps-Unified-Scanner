package semgrep

import (
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

// B-01: Semgrep prefixes rule IDs with the config directory it loaded them from. The
// same rule therefore arrived as both "org-x" (embedded bundle) and "rules.org-x" (an
// extra_rules path pointing at the same file), producing two findings for one defect.
func TestNormalizeRuleIDStripsDirectoryQualifier(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"org-python-command-injection-shell", "org-python-command-injection-shell"},
		{"rules.org-python-command-injection-shell", "org-python-command-injection-shell"},
		{"rules.org-go-insecure-skip-verify", "org-go-insecure-skip-verify"},
		{"sentinel-rules-12345.org-js-sql-injection-concat", "org-js-sql-injection-concat"},
		{"/tmp/rules/extra.org-python-command-injection-shell", "org-python-command-injection-shell"},
		{"rules.org-jwt-none-algorithm-python", "org-jwt-none-algorithm-python"},
	}

	for _, tc := range cases {
		if got := normalizeRuleID(tc.in); got != tc.want {
			t.Errorf("normalizeRuleID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The normaliser must be idempotent: running it twice cannot change the result, or
// fingerprints would drift between report generations.
func TestNormalizeRuleIDIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"rules.org-python-command-injection-shell",
		"sentinel-rules-999.org-go-insecure-skip-verify",
		"org-js-sql-injection-concat",
	} {
		once := normalizeRuleID(in)
		twice := normalizeRuleID(once)
		if once != twice {
			t.Errorf("normalizeRuleID not idempotent for %q: %q -> %q", in, once, twice)
		}
	}
}

// Unmapped registry-pack rules must pass through with only the volatile temp prefix
// removed, so their IDs stay stable without being forced into Sentinel's namespace.
func TestNormalizeRuleIDPreservesUnknownRules(t *testing.T) {
	const registryRule = "javascript.express.security.audit.express-check-csurf"
	if got := normalizeRuleID(registryRule); got != registryRule {
		t.Errorf("normalizeRuleID(%q) = %q, want it unchanged", registryRule, got)
	}
}

// FuzzParseOutput hardens the Semgrep JSON reader against malformed or hostile engine
// output (P-22). A scanner must never panic on the output of the tool it wraps, because
// an upgraded or compromised engine can emit anything.
func FuzzParseOutput(f *testing.F) {
	seeds := []string{
		`{"results":[],"errors":[]}`,
		`{"results":[{"check_id":"org-x","path":"a.go","start":{"line":1},"end":{"line":1},"extra":{"message":"m","severity":"ERROR","metadata":{"cwe":"CWE-89","category":"sast"}}}],"errors":[]}`,
		`{"results":[{"check_id":"rules.org-x","path":"a.go","start":{"line":0},"end":{"line":-1},"extra":{"message":"","severity":"","metadata":{}}}],"errors":[]}`,
		`{"results":null,"errors":null}`,
		`{}`,
		`{"results":[{"check_id":"","path":"","start":{"line":999999999},"end":{"line":0},"extra":{"metadata":{"cwe":["CWE-1","CWE-2"]}}}]}`,
		`{"results":[{"check_id":"org-x","path":"../../etc/passwd","start":{"line":1},"extra":{"metadata":{"cwe":{"nested":"object"}}}}]}`,
		`not json at all`,
		`{"errors":[{"level":"error","message":"Rule parse error"}]}`,
		"\x00\xff\xfe",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	cfg := config.DefaultConfig()

	f.Fuzz(func(t *testing.T, payload string) {
		findings, err := ParseOutput([]byte(payload), ".", cfg)
		if err != nil {
			return // rejection is a valid outcome
		}
		for _, finding := range findings {
			_ = finding.Severity
			_ = finding.RiskScore
			if finding.LineStart < 0 {
				t.Fatalf("negative LineStart %d from payload %q", finding.LineStart, payload)
			}
		}
	})
}

// FuzzNormalizeRuleID guards the rule-ID canonicaliser, which B-01 showed is load
// bearing for deduplication correctness.
func FuzzNormalizeRuleID(f *testing.F) {
	f.Add("rules.org-x")
	f.Add("sentinel-rules-1.org-x")
	f.Add("")
	f.Add(".")
	f.Add("....")
	f.Add("org-python-command-injection-shell")

	f.Fuzz(func(t *testing.T, id string) {
		once := normalizeRuleID(id)
		twice := normalizeRuleID(once)
		if once != twice {
			t.Fatalf("normalizeRuleID not idempotent: %q -> %q -> %q", id, once, twice)
		}
	})
}

// The bundled rule ID index must actually be populated, otherwise normalisation silently
// degrades to the temp-prefix-only path and B-01 returns.
func TestBundledRuleIDsLoaded(t *testing.T) {
	normalizeRuleID("warmup") // triggers the sync.Once
	if len(bundledRuleIDs) == 0 {
		t.Fatal("bundled rule ID index is empty; embedded rule packs were not parsed")
	}
	if _, ok := bundledRuleIDs["org-python-command-injection-shell"]; !ok {
		t.Error("expected org-python-command-injection-shell in the bundled rule index")
	}
}
