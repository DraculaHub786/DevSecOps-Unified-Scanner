package orchestrator

import (
	"math"
	"strings"
)

// CalculateRiskScore evaluates the actual contextual risk (0.0 to 100.0) for a finding.
func CalculateRiskScore(f *Finding) float64 {
	// Base severity scores (0 - 50)
	var baseScore float64
	switch strings.ToLower(f.Severity) {
	case SeverityCritical:
		baseScore = 45.0
	case SeverityHigh:
		baseScore = 35.0
	case SeverityMedium:
		baseScore = 22.0
	case SeverityLow:
		baseScore = 12.0
	case SeverityInfo:
		baseScore = 4.0
	default:
		baseScore = 10.0
	}

	// CVSS weight (adds up to 35 points if CVSS is defined)
	if f.CVSS > 0 {
		cvssFactor := math.Min(10.0, math.Max(0.0, f.CVSS)) / 10.0
		baseScore = (baseScore * 0.6) + (cvssFactor * 40.0)
	}

	// Reachability multiplier (P-13)
	// - proven (call-graph level verified by govulncheck): 1.35x
	// - imported (actively imported in non-test application source code): 1.25x
	// - unimported / unreachable: 0.65x
	reachabilityMultiplier := 1.0
	if f.ReachabilityLevel == "proven" {
		reachabilityMultiplier = 1.35
	} else if f.ReachabilityLevel == "imported" {
		reachabilityMultiplier = 1.25
	} else if f.ReachabilityLevel == "unimported" {
		reachabilityMultiplier = 0.65
	} else if f.Reachable != nil {
		if *f.Reachable {
			reachabilityMultiplier = 1.35
		} else {
			reachabilityMultiplier = 0.65
		}
	}

	// Exposure multiplier
	// If the file is in an entry point, server, controller, handler, public API, or ingress
	exposureMultiplier := 1.0
	if f.Exposed != nil {
		if *f.Exposed {
			exposureMultiplier = 1.25
		} else {
			exposureMultiplier = 0.85
		}
	} else {
		// Heuristic detection based on file path
		lowPath := strings.ToLower(f.File)
		if strings.Contains(lowPath, "api/") ||
			strings.Contains(lowPath, "handler") ||
			strings.Contains(lowPath, "controller") ||
			strings.Contains(lowPath, "route") ||
			strings.Contains(lowPath, "server") {
			exposureMultiplier = 1.2
		} else if strings.Contains(lowPath, "test") ||
			strings.Contains(lowPath, "fixture") ||
			strings.Contains(lowPath, "mock") {
			exposureMultiplier = 0.6
		}
	}

	// Category bonus: exposed credentials are systematically critical
	categoryBonus := 0.0
	if f.Category == CategorySecret {
		categoryBonus = 15.0
	}

	finalScore := (baseScore * reachabilityMultiplier * exposureMultiplier) + categoryBonus

	// Clamp to 0.0 - 100.0
	if finalScore > 100.0 {
		finalScore = 100.0
	}
	if finalScore < 0.0 {
		finalScore = 0.0
	}

	// Round to 1 decimal place
	return math.Round(finalScore*10) / 10
}

// AssessReachability checks whether a vulnerable package or symbol is referenced in source files.
func AssessReachability(packageName string, sourceFiles []string, readFileFunc func(path string) (string, error)) bool {
	if packageName == "" || len(sourceFiles) == 0 {
		return false
	}
	cleanPkg := strings.ToLower(packageName)
	for _, f := range sourceFiles {
		content, err := readFileFunc(f)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(content), cleanPkg) {
			return true
		}
	}
	return false
}
