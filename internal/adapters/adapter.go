package adapters

import (
	"context"

	"github.com/sentinel-dev/sentinel/internal/config"
	"github.com/sentinel-dev/sentinel/internal/orchestrator"
)

// Adapter is the common interface implemented by all scanner plugins.
type Adapter interface {
	Name() string
	Category() string
	IsApplicable(discovery *orchestrator.DiscoveryResult) bool
	Run(ctx context.Context, repoPath string, cfg *config.Config, discovery *orchestrator.DiscoveryResult) ([]orchestrator.Finding, error)
}
