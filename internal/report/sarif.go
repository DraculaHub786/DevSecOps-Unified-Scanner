package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// SARIF 2.1.0 JSON structures compatible with GitHub / GitLab Code Scanning.

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool      SARIFTool     `json:"tool"`
	Results   []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     SARIFMessage      `json:"shortDescription"`
	FullDescription      SARIFMessage      `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFRuleConfig   `json:"defaultConfiguration"`
	Properties           map[string]string `json:"properties,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"` // error | warning | note | none
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
	Locations           []SARIFLocation   `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI   string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// GenerateSARIF converts normalized Sentinel findings into valid SARIF 2.1.0 JSON.
func GenerateSARIF(findings []orchestrator.Finding) ([]byte, error) {
	ruleMap := make(map[string]SARIFRule)
	var results []SARIFResult

	for _, f := range findings {
		ruleID := f.Rule
		if ruleID == "" {
			ruleID = f.ID
		}

		level := sarifLevel(f.Severity)

		if _, exists := ruleMap[ruleID]; !exists {
			ruleMap[ruleID] = SARIFRule{
				ID:   ruleID,
				Name: f.Rule,
				ShortDescription: SARIFMessage{
					Text: f.Message,
				},
				DefaultConfiguration: SARIFRuleConfig{
					Level: level,
				},
				Properties: map[string]string{
					"category": f.Category,
					"cwe":      f.CWE,
					"cve":      f.CVE,
				},
			}
		}

		lineStart := f.LineStart
		if lineStart <= 0 {
			lineStart = 1
		}
		lineEnd := f.LineEnd
		if lineEnd < lineStart {
			lineEnd = lineStart
		}

		fp := f.Fingerprint
		if fp == "" {
			fp = f.ID
		}

		res := SARIFResult{
			RuleID: ruleID,
			Level:  level,
			Message: SARIFMessage{
				Text: f.Message,
			},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fp,
			},

			Properties: map[string]string{
				"engine":    f.Engine,
				"riskScore": fmt.Sprintf("%.1f", f.RiskScore),
				"category":  f.Category,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.File,
						},
						Region: SARIFRegion{
							StartLine:   lineStart,
							EndLine:     lineEnd,
							StartColumn: 1,
						},
					},
				},
			},
		}

		results = append(results, res)
	}

	var rules []SARIFRule
	for _, r := range ruleMap {
		rules = append(rules, r)
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Sentinel",
						Version:        "0.1.1",
						InformationURI: "https://github.com/DraculaHub786/DevSecOps-Unified-Scanner",
						Rules:          rules,
					},
				},

				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

func sarifLevel(sev string) string {
	switch strings.ToLower(sev) {
	case orchestrator.SeverityCritical, orchestrator.SeverityHigh:
		return "error"
	case orchestrator.SeverityMedium:
		return "warning"
	case orchestrator.SeverityLow, orchestrator.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}
