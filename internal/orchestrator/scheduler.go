package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
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

			res, err := ad.Run(adCtx, opts.RepoPath, cfg, discovery)
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
			if cfg.Engine == "embedded" {
				engine = EngineEmbedded
			} else if len(res) > 0 {
				for _, f := range res {
					if f.Engine == EngineEmbedded {
						engine = EngineEmbedded
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
					if _, err := exec.LookPath(bin); err != nil {
						engine = EngineEmbedded
					}
				}
			}
			enginesUsed[ad.Name()] = engine
			coverageMap[ad.Category()] = CoverageLine{
				Category: ad.Category(),
				Engine:   engine,
				Status:   "ran",
			}

			allFindings = append(allFindings, res...)
		}(adapter)
	}

	wg.Wait()

	// In CI mode, any adapter crash or failure MUST fail the gate with exit code 2
	if opts.CI && len(adapterErrs) > 0 {
		return nil, fmt.Errorf("CI mode gate failure: scanner crash/error detected: %s", strings.Join(adapterErrs, "; "))
	}

	// Append warning for OSV lite mode (WO-07)
	if enginesUsed["osv"] == EngineEmbedded {
		warnings = append(warnings, "osv: embedded advisory list has 7 entries; install osv-scanner for full coverage")
	}

	// Determine overall mode
	overallMode := "full"
	for _, eng := range enginesUsed {
		if eng == EngineEmbedded {
			overallMode = "lite"
			break
		}
	}

	// If in CI mode and running in lite mode without --allow-lite, return error
	if opts.CI && overallMode == "lite" && !opts.AllowLite {
		return nil, fmt.Errorf("CI mode error: scanner ran in 'lite' mode with embedded engines. Install required scanner binaries or specify --allow-lite")
	}

	// 4. Correlate and Deduplicate
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
