package report

import (
	"encoding/json"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// GenerateJSON produces formatted JSON representation of a scan result.
func GenerateJSON(result *orchestrator.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
