package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

// ScannerRunner is the interface the scheduler needs to execute adapters.
type ScannerRunner interface {
	Name() string
	Category() string
	IsApplicable(discovery *DiscoveryResult) bool
	Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *DiscoveryResult) ([]Finding, error)
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
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	DurationMs    int64             `json:"duration_ms"`
	Mode          string            `json:"mode"`    // "full" (all external tools ran) | "lite" (one or more embedded fallback engines used)
	Engines       map[string]string `json:"engines"` // scanner name -> "external" | "embedded"
	Discovery     *DiscoveryResult  `json:"discovery"`
	Findings      []Finding         `json:"findings"`
	Warnings      []string          `json:"warnings"`
	Summary       SeveritySummary   `json:"summary"`
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

	// 2. Plan: filter applicable adapters
	categoryFilter := make(map[string]bool)
	for _, c := range opts.OnlyCategories {
		categoryFilter[c] = true
	}
	skipFilter := make(map[string]bool)
	for _, s := range opts.SkipCategories {
		skipFilter[s] = true
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
		enginesUsed = make(map[string]string)
	)

	for _, adapter := range applicable {
		wg.Add(1)
		go func(ad ScannerRunner) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					warnings = append(warnings, fmt.Sprintf("Adapter %s panicked: %v", ad.Name(), r))
					mu.Unlock()
				}
			}()

			adCtx, adCancel := context.WithTimeout(scanCtx, 60*time.Second)
			defer adCancel()

			res, err := ad.Run(adCtx, opts.RepoPath, cfg, discovery)
			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Adapter %s failed: %v", ad.Name(), err))
				return
			}

			// Record engine provenance
			engine := EngineExternal
			for _, f := range res {
				if f.Engine == EngineEmbedded {
					engine = EngineEmbedded
					break
				}
			}
			enginesUsed[ad.Name()] = engine

			allFindings = append(allFindings, res...)
		}(adapter)
	}

	wg.Wait()

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
	for i := range deduped {
		f := &deduped[i]
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
	}, nil
}
