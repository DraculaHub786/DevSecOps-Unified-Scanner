package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sentinel-dev/sentinel/internal/config"
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
	TargetURL      string
	Incremental    bool
	ChangedFiles   []string
	Timeout        time.Duration
}

// ScanResult aggregates the final correlated output of a scan.
type ScanResult struct {
	StartedAt     time.Time        `json:"started_at"`
	FinishedAt    time.Time        `json:"finished_at"`
	DurationMs    int64            `json:"duration_ms"`
	Discovery     *DiscoveryResult `json:"discovery"`
	Findings      []Finding        `json:"findings"`
	Warnings      []string         `json:"warnings"`
	Summary       SeveritySummary  `json:"summary"`
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
	var applicable []ScannerRunner
	categoryFilter := make(map[string]bool)
	for _, c := range opts.OnlyCategories {
		categoryFilter[c] = true
	}

	for _, a := range s.adapters {
		if len(categoryFilter) > 0 && !categoryFilter[a.Category()] {
			continue
		}
		if a.IsApplicable(discovery) {
			applicable = append(applicable, a)
		}
	}

	// 3. Execute in parallel
	var (
		wg          sync.WaitGroup
		mu          sync.Mutex
		allFindings []Finding
		warnings    []string
	)

	for _, adapter := range applicable {
		wg.Add(1)
		go func(ad ScannerRunner) {
			defer wg.Done()

			// Adapter-level timeout
			adCtx, adCancel := context.WithTimeout(scanCtx, 60*time.Second)
			defer adCancel()

			res, err := ad.Run(adCtx, opts.RepoPath, cfg, discovery)
			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Adapter %s failed: %v", ad.Name(), err))
				return
			}
			allFindings = append(allFindings, res...)
		}(adapter)
	}

	wg.Wait()

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

	finished := time.Now().UTC()

	return &ScanResult{
		StartedAt:  started,
		FinishedAt: finished,
		DurationMs: finished.Sub(started).Milliseconds(),
		Discovery:  discovery,
		Findings:   deduped,
		Warnings:   warnings,
		Summary:    summary,
	}, nil
}
