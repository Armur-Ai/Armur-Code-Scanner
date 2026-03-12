package utils

import (
	"armur-codescanner/internal/logger"
	"strings"
)

// ReformatScanResults reformats simple scan results
func ReformatScanResults(results map[string]interface{}) map[string]interface{} {
	reformattedResults := map[string]interface{}{
		COMPLEX_FUNCTIONS: []interface{}{},
		DOCKSTRING_ABSENT: []interface{}{},
		ANTIPATTERNS_BUGS: []interface{}{},
		SECURITY_ISSUES:   []interface{}{},
	}

	if data := ReformatComplexFunctions(results); len(data) > 0 {
		reformattedResults[COMPLEX_FUNCTIONS] = data
	}
	if data := ReformatDocstringIssues(results); len(data) > 0 {
		reformattedResults[DOCKSTRING_ABSENT] = data
	}
	if data := ReformatAntipatternsBugs(results); len(data) > 0 {
		reformattedResults[ANTIPATTERNS_BUGS] = data
	}
	if data := ReformatSecurityIssues(results); len(data) > 0 {
		reformattedResults[SECURITY_ISSUES] = data
	}

	return reformattedResults
}

// ensureNonNull replaces nil values with empty slices
func ensureNonNull(value interface{}) interface{} {
	if value == nil {
		return []interface{}{} // Return empty slice instead of nil
	}
	return value
}

// ReformatAdvancedScanResults reformats advanced scan results
func ReformatAdvancedScanResults(results map[string]interface{}) map[string]interface{} {
	reformattedResults := map[string]interface{}{
		DEAD_CODE:        []interface{}{},
		DUPLICATE_CODE:   []interface{}{},
		SECRET_DETECTION: []interface{}{},
		INFRA_SECURITY:   []interface{}{},
		SCA:              []interface{}{},
	}

	if data := ReformatDeadCode(results); data != nil {
		reformattedResults[DEAD_CODE] = data
	}
	if data := ReformatDuplicateCode(results); data != nil {
		reformattedResults[DUPLICATE_CODE] = data
	}
	if data := ReformatSecretDetection(results); data != nil {
		reformattedResults[SECRET_DETECTION] = data
	}
	if data := ReformatInfraSecurity(results); data != nil {
		reformattedResults[INFRA_SECURITY] = data
	}
	if data := ReformatSCAIssues(results); data != nil {
		reformattedResults[SCA] = data
	}

	return reformattedResults
}

// ReformatDeadCode reformats dead code results
func ReformatDeadCode(results map[string]interface{}) []map[string]interface{} {
	deadCodeGroupedIssues := make(map[string][]map[string]interface{})
	deadCodeResults, ok := results[DEAD_CODE]
	if !ok {
		return []map[string]interface{}{}
	}
	deadCodeSlice, ok := deadCodeResults.([]interface{})
	if !ok || len(deadCodeSlice) == 0 {
		return []map[string]interface{}{}
	}
	for _, issue := range deadCodeSlice {
		issueMap, ok := issue.(map[string]interface{})
		if !ok {
			continue
		}

		checkID, ok := issueMap["check_id"].(string)
		if !ok {
			continue
		}

		deadCodeGroupedIssues[checkID] = append(deadCodeGroupedIssues[checkID], issueMap)
	}

	// Prepare the result array
	var result []map[string]interface{}
	for checkID, issues := range deadCodeGroupedIssues {
		result = append(result, map[string]interface{}{
			"check_id": checkID,
			"issues":   issues,
		})
	}

	return result
}

// ReformatVultureOutput parses vulture output lines into dead code results
func ReformatVultureOutput(vultureResults string, results map[string]interface{}) {
	// If the DEAD_CODE category doesn't exist, initialize it with an empty slice
	if _, ok := results[DEAD_CODE]; !ok {
		results[DEAD_CODE] = []interface{}{}
	}

	// Split the Vulture results by new lines
	lines := strings.Split(vultureResults, "\n")

	// Loop through each line to extract information
	for _, line := range lines {
		// Skip empty lines
		if len(line) == 0 {
			continue
		}

		// Parse the line into file, line, and message
		parts := strings.Split(line, " line:")
		if len(parts) < 2 {
			continue
		}

		fileAndMessage := parts[0]
		message := parts[1]

		// Split the file and message part
		fileParts := strings.Split(fileAndMessage, " message:")
		if len(fileParts) < 2 {
			continue
		}

		file := strings.TrimSpace(fileParts[0])
		msg := strings.TrimSpace(fileParts[1])

		// Create the issue map
		issue := map[string]interface{}{
			"file":    file,
			"line":    strings.TrimSpace(message),
			"message": msg,
		}

		// Append to the DEAD_CODE category
		results[DEAD_CODE] = append(results[DEAD_CODE].([]interface{}), issue)
	}
}

// ReformatDuplicateCode reformats duplicate code results
func ReformatDuplicateCode(results map[string]interface{}) interface{} {
	return results[DUPLICATE_CODE]
}

// ReformatSecretDetection reformats secret detection results
func ReformatSecretDetection(results map[string]interface{}) interface{} {
	return results[SECRET_DETECTION]
}

// ReformatInfraSecurity reformats infra security results
func ReformatInfraSecurity(results map[string]interface{}) []map[string]interface{} {
	if results[INFRA_SECURITY] == nil {
		return []map[string]interface{}{}
	}

	infraSecurityGroupedIssues := make(map[string][]interface{})

	for _, issue := range results[INFRA_SECURITY].([]interface{}) {
		issueMap := issue.(map[string]interface{})
		message := issueMap["message"].(string)
		infraSecurityGroupedIssues[message] = append(infraSecurityGroupedIssues[message], issue)
	}

	var result []map[string]interface{}
	for message, issues := range infraSecurityGroupedIssues {
		result = append(result, map[string]interface{}{
			"message": message,
			"issues":  issues,
		})
	}

	return result
}

// ReformatComplexFunctions reformats complex functions results
func ReformatComplexFunctions(results map[string]interface{}) []map[string]interface{} {
	complexGroupedIssues := make(map[string][]interface{})

	issues, ok := results[COMPLEX_FUNCTIONS]
	if !ok || issues == nil {
		logger.Debug().Msg("no COMPLEX_FUNCTIONS key or it is nil")
		return nil
	}

	issueList, ok := issues.([]interface{})
	if !ok {
		logger.Debug().Msg("COMPLEX_FUNCTIONS is not a []interface{}")
		return nil
	}

	for _, issue := range issueList {
		issueMap := issue.(map[string]interface{})
		path := issueMap["path"].(string)
		complexGroupedIssues[path] = append(complexGroupedIssues[path], issue)
	}

	var result []map[string]interface{}
	for path, issues := range complexGroupedIssues {
		result = append(result, map[string]interface{}{
			"path":   path,
			"issues": issues,
		})
	}
	return result
}

// ReformatDocstringIssues reformats docstring issues results
func ReformatDocstringIssues(results map[string]interface{}) []map[string]interface{} {
	docstringGroupedIssues := make(map[string][]interface{})

	for _, issue := range results[DOCKSTRING_ABSENT].([]interface{}) {
		issueMap := issue.(map[string]interface{})
		path := issueMap["path"].(string)
		docstringGroupedIssues[path] = append(docstringGroupedIssues[path], issue)
	}

	var result []map[string]interface{}
	for path, issues := range docstringGroupedIssues {
		result = append(result, map[string]interface{}{
			"path":   path,
			"issues": issues,
		})
	}
	return result
}

// ReformatSecurityIssues reformats security issues results
func ReformatSecurityIssues(results map[string]interface{}) []map[string]interface{} {
	securityGroupedIssues := make(map[string]map[string][]interface{})

	if securityIssues, ok := results[SECURITY_ISSUES].([]interface{}); ok {
		for _, issue := range securityIssues {
			issueMap, ok := issue.(map[string]interface{})
			if !ok {
				logger.Debug().Msg("skipping invalid issue format")
				continue
			}

			cweKey := UNKNOWN

			if cweArray, ok := issueMap["cwe"].([]string); ok && len(cweArray) > 0 {
				cweKey = cweArray[0]
			} else if cweInterfaceArray, ok := issueMap["cwe"].([]interface{}); ok && len(cweInterfaceArray) > 0 {
				if firstCWE, ok := cweInterfaceArray[0].(string); ok {
					cweKey = firstCWE
				} else {
					logger.Debug().Msgf("invalid CWE format in array: %v", cweInterfaceArray)
				}
			} else {
				logger.Debug().Msgf("CWE not found or invalid type: %v", issueMap["cwe"])
			}

			path, _ := issueMap["path"].(string)

			if _, exists := securityGroupedIssues[cweKey]; !exists {
				securityGroupedIssues[cweKey] = make(map[string][]interface{})
			}

			securityGroupedIssues[cweKey][path] = append(securityGroupedIssues[cweKey][path], issue)
		}
	} else {
		logger.Debug().Msg("no 'security_issues' found or invalid format")
	}

	// Convert the grouped map into the desired structure
	var resultCwePathGrouping []map[string]interface{}
	for cwe, files := range securityGroupedIssues {
		var fileIssues []map[string]interface{}
		for path, issues := range files {
			fileIssues = append(fileIssues, map[string]interface{}{
				"path":   path,
				"issues": issues,
			})
		}

		resultCwePathGrouping = append(resultCwePathGrouping, map[string]interface{}{
			"cwe":   cwe,
			"files": fileIssues,
		})
	}

	return resultCwePathGrouping
}

// ReformatAntipatternsBugs reformats antipatterns bugs results
func ReformatAntipatternsBugs(results map[string]interface{}) []map[string]interface{} {
	antipatternGroupedIssues := make(map[string]map[string][]interface{})

	for _, issue := range results[ANTIPATTERNS_BUGS].([]interface{}) {
		issueMap := issue.(map[string]interface{})
		messageKey := UNKNOWN
		if message, ok := issueMap["message"].(string); ok {
			messageKey = message
		}

		path := issueMap["path"].(string)
		if _, exists := antipatternGroupedIssues[messageKey]; !exists {
			antipatternGroupedIssues[messageKey] = make(map[string][]interface{})
		}
		antipatternGroupedIssues[messageKey][path] = append(antipatternGroupedIssues[messageKey][path], issue)
	}

	var resultMessagePathGrouping []map[string]interface{}
	for message, files := range antipatternGroupedIssues {
		var fileList []map[string]interface{}
		for path, issues := range files {
			fileList = append(fileList, map[string]interface{}{
				"path":   path,
				"issues": issues,
			})
		}
		resultMessagePathGrouping = append(resultMessagePathGrouping, map[string]interface{}{
			"message":       message,
			"seen_in_files": len(files),
			"files":         fileList,
		})
	}
	return resultMessagePathGrouping
}

// ReformatSCAIssues reformats SCA issues results
func ReformatSCAIssues(results map[string]interface{}) []map[string]interface{} {
	if results[SCA] == nil {
		return []map[string]interface{}{}
	}

	scaGroupedIssues := make(map[string][]interface{})

	for _, issue := range results[SCA].([]interface{}) {
		issueMap := issue.(map[string]interface{})
		path := issueMap["path"].(string)
		scaGroupedIssues[path] = append(scaGroupedIssues[path], issue)
	}

	var result []map[string]interface{}
	for path, issues := range scaGroupedIssues {
		result = append(result, map[string]interface{}{
			"path":   path,
			"issues": issues,
		})
	}
	return result
}
