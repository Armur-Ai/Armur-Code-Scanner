package models

import (
	"fmt"
	"strings"
)

// ConvertFromLegacy converts the existing map[string]interface{} scan results
// into a typed []Finding slice. This is a bridge layer that allows the new Finding
// type to be used without rewriting every tool wrapper at once.
func ConvertFromLegacy(results map[string]interface{}) []Finding {
	var findings []Finding

	for category, data := range results {
		// Skip non-finding keys
		if category == "scan_errors" || category == "status" || category == "error" {
			continue
		}

		issues, ok := data.([]interface{})
		if !ok {
			continue
		}

		for _, issue := range issues {
			m, ok := issue.(map[string]interface{})
			if !ok {
				continue
			}

			// Handle direct finding format
			if _, hasMessage := m["message"]; hasMessage {
				f := Finding{
					Tool:     getString(m, "tool"),
					Source:   "sast",
					Category: category,
					File:     getString(m, "path"),
					Line:     getInt(m, "line"),
					RuleID:   getString(m, "rule_id"),
					CWE:      getString(m, "cwe"),
					Severity: normalizeSev(getString(m, "severity")),
					Message:  getString(m, "message"),
				}
				f.ComputeID()
				findings = append(findings, f)
			}

			// Handle nested files -> issues structure
			if files, ok := m["files"].([]interface{}); ok {
				cwe := getString(m, "cwe")
				tool := getString(m, "tool")
				for _, file := range files {
					fm, ok := file.(map[string]interface{})
					if !ok {
						continue
					}
					fpath := getString(fm, "path")
					nested, ok := fm["issues"].([]interface{})
					if !ok {
						continue
					}
					for _, ni := range nested {
						nd, ok := ni.(map[string]interface{})
						if !ok {
							continue
						}
						f := Finding{
							Tool:     tool,
							Source:   "sast",
							Category: category,
							File:     fpath,
							Line:     getInt(nd, "line"),
							RuleID:   getString(nd, "rule_id"),
							CWE:      cwe,
							Severity: normalizeSev(getString(nd, "severity")),
							Message:  getString(nd, "message"),
						}
						f.ComputeID()
						findings = append(findings, f)
					}
				}
			}
		}
	}

	return findings
}

// ConvertToLegacy converts a []Finding back to the legacy map format for
// backwards compatibility with existing API consumers.
func ConvertToLegacy(findings []Finding) map[string]interface{} {
	byCategory := map[string][]interface{}{}
	for _, f := range findings {
		entry := map[string]interface{}{
			"id":       f.ID,
			"tool":     f.Tool,
			"path":     f.File,
			"line":     f.Line,
			"severity": string(f.Severity),
			"message":  f.Message,
		}
		if f.CWE != "" {
			entry["cwe"] = f.CWE
		}
		if f.RuleID != "" {
			entry["rule_id"] = f.RuleID
		}
		if f.Remediation != "" {
			entry["remediation"] = f.Remediation
		}
		if f.Snippet != "" {
			entry["snippet"] = f.Snippet
		}
		byCategory[f.Category] = append(byCategory[f.Category], entry)
	}

	result := map[string]interface{}{}
	for cat, items := range byCategory {
		result[cat] = items
	}
	return result
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%d", int(val))
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok && v != nil {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		case string:
			n := 0
			fmt.Sscanf(val, "%d", &n)
			return n
		}
	}
	return 0
}

func normalizeSev(raw string) Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH", "ERROR", "SEVERE":
		return SeverityHigh
	case "MEDIUM", "WARNING", "MODERATE":
		return SeverityMedium
	case "LOW", "MINOR":
		return SeverityLow
	case "INFO", "INFORMATIONAL", "NOTE":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}
