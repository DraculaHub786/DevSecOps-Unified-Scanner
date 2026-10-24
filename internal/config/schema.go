package config

// Config represents the top-level configuration loaded from .sentinel.yml.
type Config struct {
	ConfigDir  string          `yaml:"-"`
	Version    int             `yaml:"version"`
	Engine     string          `yaml:"engine"` // auto | external | embedded
	Offline    bool            `yaml:"offline,omitempty"`
	Scanners   ScannersConfig  `yaml:"scanners"`
	Ignore     IgnoreConfig    `yaml:"ignore"`
	Thresholds ThresholdConfig `yaml:"thresholds"`
	Output     OutputConfig    `yaml:"output"`
	Cloud      CloudConfig     `yaml:"cloud"`
}

// ScannersConfig controls individual scanning engine options.
type ScannersConfig struct {
	SAST       SASTConfig       `yaml:"sast"`
	Secrets    SecretsConfig    `yaml:"secrets"`
	SCA        SCAConfig        `yaml:"sca"`
	IaC        IaCConfig        `yaml:"iac"`
	DAST       DASTConfig       `yaml:"dast"`
	Resilience ResilienceConfig `yaml:"resilience"`
}

// SASTConfig options for Semgrep / static analysis.
type SASTConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Ruleset    string   `yaml:"ruleset"`
	ExtraRules []string `yaml:"extra_rules"`
	Packs      []string `yaml:"packs"`
}

// SecretsConfig options for Gitleaks.
type SecretsConfig struct {
	Enabled     bool `yaml:"enabled"`
	ScanHistory bool `yaml:"scan_history"`
}

// SCAConfig options for OSV-Scanner / dependency analysis.
type SCAConfig struct {
	Enabled       bool     `yaml:"enabled"`
	FailOnLicense []string `yaml:"fail_on_license"`
}

// IaCConfig options for Trivy / infrastructure as code.
type IaCConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DASTConfig options for Nuclei / dynamic analysis.
type DASTConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Target       string   `yaml:"target"`
	Allowlist    []string `yaml:"allowlist"`
	AllowPrivate bool     `yaml:"allow_private"`
}

// ResilienceConfig options for posture checks.
type ResilienceConfig struct {
	Enabled bool `yaml:"enabled"`
}

// FindingSuppression defines an explicit suppression with mandatory justification reason.
type FindingSuppression struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`            // required justification comment
	Expires string `yaml:"expires,omitempty"` // optional expiration date YYYY-MM-DD
}

// IgnoreConfig defines exclusions for paths and finding suppressions.
type IgnoreConfig struct {
	Paths    []string             `yaml:"paths"`
	Findings []FindingSuppression `yaml:"findings"`
}

// ThresholdConfig defines build failure gating criteria.
type ThresholdConfig struct {
	FailOn       string  `yaml:"fail_on"`                  // critical | high | medium | low
	RiskScoreMax float64 `yaml:"risk_score_max,omitempty"` // fail if any finding risk score exceeds this value
}

// OutputConfig defines report formats and storage path.
type OutputConfig struct {
	Formats []string `yaml:"formats"`
	Path    string   `yaml:"path"`
}

// CloudConfig defines optional SaaS synchronization parameters.
type CloudConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

// DefaultConfig returns safe, production-grade defaults.
func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Engine:  "auto",
		Scanners: ScannersConfig{
			SAST: SASTConfig{
				Enabled: true,
				Ruleset: "auto",
				ExtraRules: []string{
					"rules/sast-rules.yml",
				},
			},
			Secrets: SecretsConfig{
				Enabled:     true,
				ScanHistory: false,
			},
			SCA: SCAConfig{
				Enabled:       true,
				FailOnLicense: []string{},
			},
			IaC: IaCConfig{
				Enabled: true,
			},
			DAST: DASTConfig{
				Enabled:      false,
				Target:       "",
				Allowlist:    []string{},
				AllowPrivate: false,
			},
			Resilience: ResilienceConfig{
				Enabled: true,
			},
		},
		Ignore: IgnoreConfig{
			Paths: []string{
				"vendor/**",
				"node_modules/**",
				"dist/**",
				"build/**",
				".git/**",
				"**/.sentinel/**",
				"testdata/**",
				"rules/tests/**",
				"**/*_test.go",
			},
			Findings: []FindingSuppression{},
		},
		Thresholds: ThresholdConfig{
			FailOn: "high",
		},
		Output: OutputConfig{
			Formats: []string{"terminal", "sarif", "markdown"},
			Path:    ".sentinel/reports/",
		},
		Cloud: CloudConfig{
			Enabled:  false,
			Endpoint: "",
		},
	}
}
