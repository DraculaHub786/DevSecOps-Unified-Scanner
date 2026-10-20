package adapters

import (
	"context"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// Adapter is the common interface implemented by all scanner plugins.
type Adapter interface {
	Name() string
	Category() string
	IsApplicable(discovery *orchestrator.DiscoveryResult) bool
	Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error)
}
