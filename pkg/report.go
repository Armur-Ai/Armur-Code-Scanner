package utils

import "fmt"

// ReportItem represents a single OWASP report entry
type ReportItem struct {
	Column               int    `json:"column"`
	Confidence           string `json:"confidence"`
	File                 string `json:"file"`
	Line                 int    `json:"line"`
	Message              string `json:"message"`
	Owasp                string `json:"owasp"`
	Severity             string `json:"severity"`
	SuggestedRemediation string `json:"suggested_remediation"`
}

// SANSReportItem represents a single SANS/CWE report entry
type SANSReportItem struct {
	CWE                  string `json:"cwe"`
	File                 string `json:"file"`
	Line                 int    `json:"line"`
	Column               int    `json:"column"`
	Message              string `json:"message"`
	Confidence           string `json:"confidence"`
	Severity             string `json:"severity"`
	SuggestedRemediation string `json:"suggested_remediation"`
}

// GenerateOwaspReport generates an OWASP report from task results
func GenerateOwaspReport(taskResult interface{}) ([]ReportItem, error) {
	var owaspReport []ReportItem

	// Ensure taskResult is a map
	taskResultMap, ok := taskResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("taskResult is not a valid map")
	}

	// Get SECURITY_ISSUES from the map
	securityIssues, ok := taskResultMap[SECURITY_ISSUES].([]interface{})
	if !ok {
		return nil, fmt.Errorf("SECURITY_ISSUES key not found or invalid")
	}

	// Iterate over SECURITY_ISSUES
	for _, rawIssue := range securityIssues {
		issueMap, ok := rawIssue.(map[string]interface{})
		if !ok {
			continue
		}

		// Iterate over "files" in each issue
		files, ok := issueMap["files"].([]interface{})
		if !ok {
			continue
		}
		for _, rawFile := range files {
			fileInfo, ok := rawFile.(map[string]interface{})
			if !ok {
				continue
			}

			// Iterate over "issues" in each file
			fileIssues, ok := fileInfo["issues"].([]interface{})
			if !ok {
				continue
			}
			for _, rawFileIssue := range fileIssues {
				fileIssue, ok := rawFileIssue.(map[string]interface{})
				if !ok {
					continue
				}

				// Extract OWASP entries
				owaspItems, ok := fileIssue["owasp"].([]interface{})
				if !ok {
					continue
				}
				for _, rawOwasp := range owaspItems {
					owaspItem, ok := rawOwasp.(string)
					if !ok {
						continue
					}

					// Construct the report item
					reportItem := ReportItem{
						Owasp:      owaspItem,
						File:       getString(fileIssue, "path"),
						Line:       getInt(fileIssue, "line"),
						Column:     getInt(fileIssue, "column"),
						Message:    getString(fileIssue, "message"),
						Confidence: getString(fileIssue, "confidence"),
						Severity:   getString(fileIssue, "severity"),
						SuggestedRemediation: fmt.Sprintf(
							"Bad Practice: %s\nSuggested Fix: %s",
							getString(fileIssue, "bad_practice"),
							getString(fileIssue, "good_practice"),
						),
					}

					// Append to the OWASP report
					owaspReport = append(owaspReport, reportItem)
				}
			}
		}
	}

	return owaspReport, nil
}

// GenerateSANSReports generates a SANS/CWE report from task results
func GenerateSANSReports(taskResult interface{}) ([]SANSReportItem, error) {
	var sansReport []SANSReportItem

	// Ensure taskResult is a map
	taskResultMap, ok := taskResult.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("taskResult is not a valid map")
	}

	// Get SECURITY_ISSUES from the map
	securityIssues, ok := taskResultMap[SECURITY_ISSUES].([]interface{})
	if !ok {
		return nil, fmt.Errorf("SECURITY_ISSUES key not found or invalid")
	}

	// Iterate over SECURITY_ISSUES
	for _, rawIssue := range securityIssues {
		issueMap, ok := rawIssue.(map[string]interface{})
		if !ok {
			continue
		}

		// Get CWE for this issue
		cwe, _ := issueMap["cwe"].(string)

		// Iterate over "files" in each issue
		files, ok := issueMap["files"].([]interface{})
		if !ok {
			continue
		}
		for _, rawFile := range files {
			fileInfo, ok := rawFile.(map[string]interface{})
			if !ok {
				continue
			}

			// Iterate over "issues" in each file
			fileIssues, ok := fileInfo["issues"].([]interface{})
			if !ok {
				continue
			}
			for _, rawFileIssue := range fileIssues {
				fileIssue, ok := rawFileIssue.(map[string]interface{})
				if !ok {
					continue
				}

				// Construct the report item
				reportItem := SANSReportItem{
					CWE:        cwe,
					File:       getString(fileIssue, "path"),
					Line:       getInt(fileIssue, "line"),
					Column:     getInt(fileIssue, "column"),
					Message:    getString(fileIssue, "message"),
					Confidence: getString(fileIssue, "confidence"),
					Severity:   getString(fileIssue, "severity"),
					SuggestedRemediation: fmt.Sprintf(
						"Bad Practice: %s\nSuggested Fix: %s",
						getString(fileIssue, "bad_practice"),
						getString(fileIssue, "good_practice"),
					),
				}

				// Append to the SANS report
				sansReport = append(sansReport, reportItem)
			}
		}
	}

	return sansReport, nil
}

// getString safely gets a string value from a map
func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return ""
}

// getInt safely gets an int value from a map
func getInt(data map[string]interface{}, key string) int {
	if val, ok := data[key]; ok {
		if floatVal, ok := val.(float64); ok {
			return int(floatVal)
		}
	}
	return 0
}
