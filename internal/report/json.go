package report

import (
	"encoding/json"

	"github.com/sentinel-dev/sentinel/internal/orchestrator"
)

// GenerateJSON produces formatted JSON representation of a scan result.
func GenerateJSON(result *orchestrator.ScanResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
