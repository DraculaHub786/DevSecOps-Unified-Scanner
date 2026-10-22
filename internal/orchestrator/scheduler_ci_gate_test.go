package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

type gateAdapter struct {
	name string
	err  error
}

func (g *gateAdapter) Name() string                       { return g.name }
func (g *gateAdapter) Category() string                   { return CategorySAST }
func (g *gateAdapter) IsApplicable(*DiscoveryResult) bool { return true }
func (g *gateAdapter) Run(context.Context, string, *config.Config, *DiscoveryResult) ([]Finding, error) {
	return nil, g.err
}

func runGate(t *testing.T, ci bool, ads ...ScannerRunner) error {
	t.Helper()
	_, err := NewScheduler(ads...).Execute(context.Background(), config.DefaultConfig(),
		ScanOptions{RepoPath: t.TempDir(), CI: ci, AllowLite: true})
	return err
}

func TestCIFailsWhenAScannerCrashes(t *testing.T) {
	err := runGate(t, true, &gateAdapter{name: "semgrep", err: fmt.Errorf("exit 2")})
	if err == nil {
		t.Fatal("a crashed scanner must fail the CI gate")
	}
}

func TestCIIgnoresDeliberateSkips(t *testing.T) {
	err := runGate(t, true, &gateAdapter{name: "osv", err: fmt.Errorf("%w: offline", ErrSkipped)})
	if err != nil && !errors.Is(err, ErrSkipped) {
		t.Fatalf("a skip must not fail CI: %v", err)
	}
}

func TestLocalRunToleratesACrashedScanner(t *testing.T) {
	if err := runGate(t, false, &gateAdapter{name: "semgrep", err: fmt.Errorf("exit 2")}); err != nil {
		t.Fatalf("outside CI a crash is a warning, got %v", err)
	}
}

type panickingGateAdapter struct{}

func (p *panickingGateAdapter) Name() string                       { return "panicking-scanner" }
func (p *panickingGateAdapter) Category() string                   { return CategorySecret }
func (p *panickingGateAdapter) IsApplicable(*DiscoveryResult) bool { return true }
func (p *panickingGateAdapter) Run(context.Context, string, *config.Config, *DiscoveryResult) ([]Finding, error) {
	panic("unexpected simulated panic in adapter")
}

func TestSchedulerCIErrorOnPanic(t *testing.T) {
	err := runGate(t, true, &panickingGateAdapter{})
	if err == nil {
		t.Fatal("expected CI mode to fail when an adapter panics, got nil")
	}
}
