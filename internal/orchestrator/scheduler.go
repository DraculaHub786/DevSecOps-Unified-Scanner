package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

// ErrPartial indicates that a scanner completed with non-fatal syntax or parsing errors on some files.
var ErrPartial = errors.New("partial scan results")

// ErrSkipped indicates that a scanner could not run because required prerequisites were absent (e.g. no lockfile).
var ErrSkipped = errors.New("scanner skipped")

// ErrDegraded indicates that a scanner gracefully degraded to an offline or embedded advisory database due to network unreachability.
var ErrDegraded = errors.New("scanner degraded")

// ScannerRunner is the interface the scheduler needs to execute adapters.
type ScannerRunner interface {
	Name() string
	Category() string
	IsApplicable(discovery *DiscoveryResult) bool
	Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *DiscoveryResult) ([]Finding, error)
}

// CoverageLine records the execution status of a single security category.
type CoverageLine struct {
	Category string `json:"category"`
	Engine   string `json:"engine"` // "external" | "embedded" | "none"
	Status   string `json:"status"` // "ran" | "skipped" | "failed" | "not-applicable"
	Detail   string `json:"detail,omitempty"`
}

// ScanOptions configures an orchestration run.
type ScanOptions struct {
	RepoPath       string
	OnlyCategories []string
	SkipCategories []string
	TargetURL      string
	Incremental    bool
	ChangedFiles   []string
	Timeout        time.Duration
	CI             bool
	AllowLite      bool
	// GuardMode marks a pre-commit/pre-push gate. Guard runs on developer machines that
	// may have no external engines at all, so an embedded result is legitimate there
	// rather than the hard failure that --ci treats it as.
	GuardMode bool
	// OnProgress is an optional callback notifying live progress observers (e.g. dynamic TUI HUD).
	OnProgress func(stage string, detail string)
}

// ScanResult aggregates the final correlated output of a scan.
type ScanResult struct {
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
	DurationMs int64             `json:"duration_ms"`
	Mode       string            `json:"mode"`    // "full" (all external tools ran) | "lite" (one or more embedded fallback engines used)
	Engines    map[string]string `json:"engines"` // scanner name -> "external" | "embedded"
	Discovery  *DiscoveryResult  `json:"discovery"`
	Findings   []Finding         `json:"findings"`
	Warnings   []string          `json:"warnings"`
	Summary    SeveritySummary   `json:"summary"`
	Coverage   []CoverageLine    `json:"coverage,omitempty"`
}

// SeveritySummary counts findings per severity bracket.
type SeveritySummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Scheduler coordinates parallel execution of scanner adapters.
type Scheduler struct {
	adapters []ScannerRunner
}

// NewScheduler creates a new execution coordinator.
func NewScheduler(adapters ...ScannerRunner) *Scheduler {
	return &Scheduler{
		adapters: adapters,
	}
}

// Execute orchestrates the full scan pipeline: Discover -> Plan -> Execute -> Deduplicate -> Score -> Remediate.
func (s *Scheduler) Execute(ctx context.Context, cfg *config.Config, opts ScanOptions) (*ScanResult, error) {
	started := time.Now().UTC()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Discover
	if opts.OnProgress != nil {
		opts.OnProgress("discovery", "Traversing AST dependency graph...")
	}
	discovery, err := Discover(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("discovery phase failed: %w", err)
	}
	if opts.TargetURL != "" {
		discovery.TargetURL = opts.TargetURL
	} else if cfg != nil && cfg.Scanners.DAST.Target != "" {
		discovery.TargetURL = cfg.Scanners.DAST.Target
	}

	// 2. Plan: filter applicable adapters
	categoryFilter := make(map[string]bool)
	for _, c := range opts.OnlyCategories {
		categoryFilter[normalizeCategory(c)] = true
	}
	skipFilter := make(map[string]bool)
	for _, s := range opts.SkipCategories {
		skipFilter[normalizeCategory(s)] = true
	}

	var applicable []ScannerRunner
	for _, a := range s.adapters {
		cat := a.Category()
		if len(categoryFilter) > 0 && !categoryFilter[cat] {
			continue
		}
		if skipFilter[cat] {
			continue
		}
		if a.IsApplicable(discovery) {
			applicable = append(applicable, a)
		}
	}

	// 3. Execute in parallel with panic recovery and timeout protection
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		allFindings []Finding
		warnings    []string
		adapterErrs []string
		enginesUsed = make(map[string]string)
		coverageMap = make(map[string]CoverageLine)
		// degradedEngines records adapters that ran with an embedded advisory list
		// because the network was unavailable, as opposed to a missing external binary.
		// Degradation is reported per category but must not flip the whole run to "lite"
		// or fail the CI lite gate (B-03 / B-05).
		degradedEngines = make(map[string]bool)
	)

	for _, adapter := range applicable {
		wg.Add(1)
		go func(ad ScannerRunner) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					msg := fmt.Sprintf("Adapter %s panicked: %v", ad.Name(), r)
					warnings = append(warnings, msg)
					adapterErrs = append(adapterErrs, msg)
					coverageMap[ad.Category()] = CoverageLine{
						Category: ad.Category(),
						Engine:   "failed",
						Status:   "failed",
						Detail:   msg,
					}
					mu.Unlock()
				}
			}()

			adCtx, adCancel := context.WithTimeout(scanCtx, 60*time.Second)
			defer adCancel()

			if opts.OnProgress != nil {
				opts.OnProgress("engine_start", ad.Name())
			}

			res, err := ad.Run(adCtx, opts.RepoPath, cfg, discovery)
			if opts.OnProgress != nil {
				opts.OnProgress("engine_done", fmt.Sprintf("%s (%d findings)", ad.Name(), len(res)))
			}
			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				if errors.Is(err, ErrSkipped) {
					msg := fmt.Sprintf("Adapter %s skipped: %v", ad.Name(), err)
					warnings = append(warnings, msg)
					coverageMap[ad.Category()] = CoverageLine{
						Category: ad.Category(),
						Engine:   "none",
						Status:   "skipped",
						Detail:   err.Error(),
					}
					return
				}
				if errors.Is(err, ErrPartial) {
					msg := fmt.Sprintf("Adapter %s returned partial results: %v", ad.Name(), err)
					warnings = append(warnings, msg)
					if opts.CI {
						adapterErrs = append(adapterErrs, msg)
					}
					coverageMap[ad.Category()] = CoverageLine{
						Category: ad.Category(),
						Engine:   EngineExternal,
						Status:   "ran",
						Detail:   "partial results returned",
					}
					allFindings = append(allFindings, res...)
					return
				}
				if errors.Is(err, ErrDegraded) {
					msg := fmt.Sprintf("Adapter %s degraded: %v", ad.Name(), err)
					warnings = append(warnings, msg)
					detail := "network unreachable (used embedded advisory list)"
					if cfg != nil && cfg.Offline {
						detail = "offline mode (used embedded advisory list)"
					}
					coverageMap[ad.Category()] = CoverageLine{
						Category: ad.Category(),
						Engine:   EngineEmbedded,
						Status:   "degraded",
						Detail:   detail,
					}
					enginesUsed[ad.Name()] = EngineEmbedded
					degradedEngines[ad.Name()] = true
					allFindings = append(allFindings, res...)
					return
				}
				msg := fmt.Sprintf("Adapter %s failed: %v", ad.Name(), err)
				warnings = append(warnings, msg)
				adapterErrs = append(adapterErrs, msg)
				coverageMap[ad.Category()] = CoverageLine{
					Category: ad.Category(),
					Engine:   "failed",
					Status:   "failed",
					Detail:   err.Error(),
				}
				return
			}

			// Record engine provenance
			engine := EngineExternal
			if ad.Name() == "resilience" {
				engine = EngineNative
			} else if cfg.Engine == "embedded" {
				engine = EngineEmbedded
			} else if len(res) > 0 {
				for _, f := range res {
					if f.Engine == EngineEmbedded {
						engine = EngineEmbedded
						break
					} else if f.Engine == EngineNative {
						engine = EngineNative
						break
					}
				}
			} else {
				// No findings returned: determine mode by binary availability
				binMap := map[string]string{
					"semgrep":  "semgrep",
					"gitleaks": "gitleaks",
					"osv":      "osv-scanner",
					"trivy":    "trivy",
					"nuclei":   "nuclei",
				}
				if bin, ok := binMap[ad.Name()]; ok {
					if _, err := findToolBinary(bin); err != nil {
						engine = EngineEmbedded
					}
				}
			}
			enginesUsed[ad.Name()] = engine
			detail := ""
			// P-06: lite-mode SAST is a narrow regex subset, not a Semgrep-equivalent
			// engine. Say so in the coverage line rather than reporting a bare "ran".
			if engine == EngineEmbedded && ad.Category() == CategorySAST {
				detail = "embedded regex subset (no taint tracking); install semgrep for full SAST"
			}
			coverageMap[ad.Category()] = CoverageLine{
				Category: ad.Category(),
				Engine:   engine,
				Status:   "ran",
				Detail:   detail,
			}

			allFindings = append(allFindings, res...)
		}(adapter)
	}

	wg.Wait()

	// In CI mode, any adapter crash or failure MUST fail the gate with exit code 2.
	// Guard mode degrades gracefully instead: a missing optional engine must not block
	// every commit on a developer machine.
	if opts.CI && !opts.GuardMode && len(adapterErrs) > 0 {
		return nil, fmt.Errorf("CI mode gate failure: scanner crash/error detected: %s", strings.Join(adapterErrs, "; "))
	}

	// Append warning for OSV lite mode (WO-07)
	if enginesUsed["osv"] == EngineEmbedded {
		warnings = append(warnings, "osv: embedded advisory list has 7 entries; install osv-scanner for full coverage")
	}

	// Determine overall mode. A deliberately requested offline run, or an unreachable
	// network, degrades a single category to an embedded advisory list but is reported
	// as "degraded" — it must not be presented as a lite fallback, because every
	// external engine is still installed and in use (B-05).
	overallMode := "full"
	for engName, eng := range enginesUsed {
		// Native first-party engines (like resilience) do not trigger fallback lite mode
		if eng == EngineEmbedded && engName != "resilience" && !degradedEngines[engName] {
			overallMode = "lite"
			break
		}
	}

	// In CI mode, a lite fallback means a required engine is missing and results cannot
	// be trusted. That is a scanner/config error (exit 2) unless --allow-lite was passed.
	// Guard mode is exempt: a pre-commit hook runs on machines that may never have run
	// the engine installer, and an embedded secrets/SAST result is a legitimate gate.
	if opts.CI && !opts.GuardMode && overallMode == "lite" && !opts.AllowLite {
		return nil, fmt.Errorf("CI mode error: scanner ran in 'lite' mode with embedded engines. Install required scanner binaries or specify --allow-lite")
	}

	// A degraded category in CI is an environmental fault unless the caller asked for it
	// explicitly with --offline. Silently passing would hide real vulnerabilities behind
	// a truncated advisory list.
	if opts.CI && !opts.GuardMode && len(degradedEngines) > 0 && (cfg == nil || !cfg.Offline) {
		names := make([]string, 0, len(degradedEngines))
		for name := range degradedEngines {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("CI mode error: %s degraded (network unreachable). Use --offline to scan with embedded advisories deliberately, or restore network access", strings.Join(names, ", "))
	}

	// 4. Correlate and Deduplicate
	if opts.OnProgress != nil {
		opts.OnProgress("correlate", "Deduplicating findings & scoring contextual risk...")
	}
	deduped := CorrelateAndDeduplicate(allFindings)

	// 5. Score & Generate Remediation
	summary := SeveritySummary{}
	entryPointMap := make(map[string]bool)
	if discovery != nil {
		for _, ep := range discovery.EntryPoints {
			entryPointMap[ep] = true
		}
	}

	for i := range deduped {
		f := &deduped[i]
		if f.Exposed == nil {
			isExposed := entryPointMap[f.File]
			f.Exposed = &isExposed
		}
		f.RiskScore = CalculateRiskScore(f)
		if f.FixSuggestion == nil {
			f.FixSuggestion = GenerateRemediation(opts.RepoPath, f)
		}

		summary.Total++
		switch f.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		case SeverityInfo:
			summary.Info++
		}
	}

	// 6. Stable ordering: severity rank descending, file ascending, line ascending
	sort.SliceStable(deduped, func(i, j int) bool {
		rI := SeverityRank(deduped[i].Severity)
		rJ := SeverityRank(deduped[j].Severity)
		if rI != rJ {
			return rI > rJ
		}
		if deduped[i].File != deduped[j].File {
			return deduped[i].File < deduped[j].File
		}
		return deduped[i].LineStart < deduped[j].LineStart
	})

	finished := time.Now().UTC()

	// Build full coverage list across all six standard categories (T-045)
	allCats := []string{CategorySAST, CategorySCA, CategorySecret, CategoryIaC, CategoryDAST, CategoryResilience}
	var coverageList []CoverageLine
	for _, cat := range allCats {
		if line, exists := coverageMap[cat]; exists {
			coverageList = append(coverageList, line)
		} else {
			status := "not-applicable"
			detail := "no matching source files or target declared"
			if skipFilter[cat] || (len(categoryFilter) > 0 && !categoryFilter[cat]) {
				status = "skipped"
				detail = "category filtered out by scan options"
			}
			coverageList = append(coverageList, CoverageLine{
				Category: cat,
				Engine:   "none",
				Status:   status,
				Detail:   detail,
			})
		}
	}

	return &ScanResult{
		StartedAt:  started,
		FinishedAt: finished,
		DurationMs: finished.Sub(started).Milliseconds(),
		Mode:       overallMode,
		Engines:    enginesUsed,
		Discovery:  discovery,
		Findings:   deduped,
		Warnings:   warnings,
		Summary:    summary,
		Coverage:   coverageList,
	}, nil
}

func normalizeCategory(c string) string {
	clean := strings.ToLower(strings.TrimSpace(c))
	switch clean {
	case "secrets":
		return CategorySecret
	case "deps":
		return CategorySCA
	default:
		return clean
	}
}

func findToolBinary(bin string) (string, error) {
	if p, err := exec.LookPath(bin); err == nil && p != "" {
		return p, nil
	}
	exts := []string{""}
	if filepath.Ext(bin) == "" {
		exts = []string{".exe", ".cmd", ".bat", ""}
	}
	dirs := []string{"plugins", filepath.Join("..", "plugins"), filepath.Join("..", "..", "plugins")}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "plugins"), filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "plugins"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Local", "Programs", "Python", "Python311", "Scripts"))
		dirs = append(dirs, filepath.Join(home, "AppData", "Local", "Programs", "Python", "Python312", "Scripts"))
	}
	for _, d := range dirs {
		for _, ext := range exts {
			cand := filepath.Join(d, bin+ext)
			if info, err := os.Stat(cand); err == nil && !info.IsDir() {
				return cand, nil
			}
		}
	}
	return "", exec.ErrNotFound
}
