// Package sarif converts Armur scan results to SARIF 2.1.0 format.
// SARIF (Static Analysis Results Interchange Format) is an OASIS standard
// used by GitHub Code Scanning and many other CI security dashboards.
package sarif

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// --- SARIF 2.1.0 schema types ---

// Log is the top-level SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single tool execution.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the scanner that produced the results.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the scanning tool.
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationURI  string `json:"informationUri"`
	Rules           []Rule `json:"rules"`
}

// Rule describes a single analysis rule.
type Rule struct {
	ID               string                    `json:"id"`
	Name             string                    `json:"name,omitempty"`
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	HelpURI          string                    `json:"helpUri,omitempty"`
	Properties       map[string]interface{}    `json:"properties,omitempty"`
}

// Result represents a single finding.
type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"` // error, warning, note, none
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

// Location pinpoints where a finding was observed.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation holds the file and region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation holds the file URI.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region specifies line/column range.
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// Message holds the human-readable finding text.
type Message struct {
	Text string `json:"text"`
}

// MultiformatMessageString holds a plain-text and/or markdown description.
type MultiformatMessageString struct {
	Text string `json:"text"`
}

// severityToLevel converts Armur severity strings to SARIF levels.
func severityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

// FromScanResults converts Armur scan results (map[string]interface{}) to a SARIF Log.
// It expects the standard Armur output structure with a "security_issues" key.
func FromScanResults(results map[string]interface{}, toolVersion string) *Log {
	if toolVersion == "" {
		toolVersion = "dev"
	}

	var sarifResults []Result
	rulesSeen := make(map[string]Rule)

	// Process security_issues
	if rawIssues, ok := results["security_issues"]; ok {
		issues, _ := rawIssues.([]interface{})
		for _, rawGroup := range issues {
			group, ok := rawGroup.(map[string]interface{})
			if !ok {
				continue
			}

			cwe := getString(group, "cwe")
			if cwe == "" {
				cwe = "UNKNOWN"
			}
			ruleID := cwe

			// Ensure the rule is registered.
			if _, seen := rulesSeen[ruleID]; !seen {
				rulesSeen[ruleID] = Rule{
					ID:   ruleID,
					Name: ruleID,
					ShortDescription: &MultiformatMessageString{
						Text: fmt.Sprintf("Security issue: %s", ruleID),
					},
					HelpURI: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
						strings.TrimPrefix(ruleID, "CWE-")),
				}
			}

			// Iterate over file groups.
			filesRaw, _ := group["files"].([]interface{})
			for _, rawFile := range filesRaw {
				fileGroup, ok := rawFile.(map[string]interface{})
				if !ok {
					continue
				}
				filePath := getString(fileGroup, "path")

				issuesRaw, _ := fileGroup["issues"].([]interface{})
				for _, rawIssue := range issuesRaw {
					issue, ok := rawIssue.(map[string]interface{})
					if !ok {
						continue
					}

					line := getInt(issue, "line")
					col := getInt(issue, "column")
					msg := getString(issue, "message")
					sev := getString(issue, "severity")

					result := Result{
						RuleID:  ruleID,
						Level:   severityToLevel(sev),
						Message: Message{Text: msg},
					}

					if filePath != "" {
						loc := Location{
							PhysicalLocation: PhysicalLocation{
								ArtifactLocation: ArtifactLocation{URI: filePath},
							},
						}
						if line > 0 || col > 0 {
							loc.PhysicalLocation.Region = &Region{
								StartLine:   line,
								StartColumn: col,
							}
						}
						result.Locations = []Location{loc}
					}

					sarifResults = append(sarifResults, result)
				}
			}
		}
	}

	// Build the ordered rules list.
	var rules []Rule
	for _, r := range rulesSeen {
		rules = append(rules, r)
	}

	log := &Log{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "Armur Code Scanner",
						Version:        toolVersion,
						InformationURI: "https://armur.ai",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	return log
}

// Marshal returns the SARIF log as indented JSON.
func (l *Log) Marshal() ([]byte, error) {
	return json.MarshalIndent(l, "", "  ")
}

// Timestamp returns an ISO-8601 timestamp for SARIF invocation records.
func Timestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return 0
}
