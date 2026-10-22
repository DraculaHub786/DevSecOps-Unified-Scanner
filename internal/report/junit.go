package report

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/orchestrator"
)

// JUnit XML structures for CI dashboards (e.g. GitHub Actions, GitLab CI, Jenkins).

type JUnitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Time     string           `xml:"time,attr"`
	Suites   []JUnitTestSuite `xml:"testsuite"`
}

type JUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      string          `xml:"time,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// GenerateJUnit serializes scan results into valid JUnit XML (T-086).
func GenerateJUnit(result *orchestrator.ScanResult, failOn string) ([]byte, error) {
	failRank := orchestrator.SeverityRank(failOn)
	durationSec := fmt.Sprintf("%.3f", float64(result.DurationMs)/1000.0)

	// Group findings by category
	catMap := make(map[string][]orchestrator.Finding)
	for _, f := range result.Findings {
		cat := f.Category
		if cat == "" {
			cat = "general"
		}
		catMap[cat] = append(catMap[cat], f)
	}

	totalFailures := 0
	var suites []JUnitTestSuite

	for cat, findings := range catMap {
		suiteFailures := 0
		var testCases []JUnitTestCase

		for _, f := range findings {
			isFailure := orchestrator.SeverityRank(f.Severity) >= failRank
			var failure *JUnitFailure
			if isFailure {
				suiteFailures++
				totalFailures++
				failure = &JUnitFailure{
					Message: fmt.Sprintf("[%s] %s: %s", strings.ToUpper(f.Severity), f.Rule, f.Message),
					Type:    f.Severity,
					Content: fmt.Sprintf("File: %s:%d\nRule: %s\nCategory: %s\nEngine: %s\nRisk Score: %.1f\nOWASP: %s\nFingerprint: %s",
						f.File, f.LineStart, f.Rule, f.Category, f.Engine, f.RiskScore, f.OWASP, f.Fingerprint),
				}
			}

			testCases = append(testCases, JUnitTestCase{
				Classname: f.File,
				Name:      fmt.Sprintf("%s (%s)", f.Rule, f.ID),
				Time:      "0.001",
				Failure:   failure,
			})
		}

		suites = append(suites, JUnitTestSuite{
			Name:      cat,
			Tests:     len(testCases),
			Failures:  suiteFailures,
			Errors:    0,
			Time:      durationSec,
			TestCases: testCases,
		})
	}

	// If no findings, write a single passing test suite
	if len(suites) == 0 {
		suites = append(suites, JUnitTestSuite{
			Name:     "clean-scan",
			Tests:    1,
			Failures: 0,
			Errors:   0,
			Time:     durationSec,
			TestCases: []JUnitTestCase{
				{
					Classname: "sentinel",
					Name:      "security-posture-clean",
					Time:      durationSec,
				},
			},
		})
	}

	totalTests := len(result.Findings)
	if totalTests == 0 {
		totalTests = 1
	}

	doc := JUnitTestSuites{
		Name:     "Sentinel Security Scan",
		Tests:    totalTests,
		Failures: totalFailures,
		Errors:   0,
		Time:     durationSec,
		Suites:   suites,
	}

	raw, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}

	header := []byte(xml.Header)
	return append(header, raw...), nil
}
