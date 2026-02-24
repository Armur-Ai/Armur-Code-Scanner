package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func RunCheckov(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "checkov").Str("dir", directory).Msg("running")
	checkovResults := runCheckovOnRepo(directory)
	categorizedResults := categorizeCheckovResults(checkovResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func runCheckovOnRepo(directory string) string {
	cmd := exec.Command("checkov", "-d", directory, "--quiet", "--compact", "-o", "json")
	result, _ := cmd.CombinedOutput()
	return string(result)
}

func categorizeCheckovResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	if results == "" {
		return categorizedResults
	}

	var checkovResults interface{}
	err := json.Unmarshal([]byte(results), &checkovResults)
	if err != nil {
		logger.Error().Str("tool", "checkov").Err(err).Msg("failed to parse output")
		return categorizedResults
	}

	switch checkovResults := checkovResults.(type) {
	case []interface{}:
		for _, result := range checkovResults {
			resultMap, ok := result.(map[string]interface{})
			if !ok {
				logger.Debug().Str("tool", "checkov").Msgf("skipping non-map result: %v", result)
				continue
			}
			if resultsMap, ok := resultMap["results"].(map[string]interface{}); ok {
				if failedChecks, ok := resultsMap["failed_checks"].([]interface{}); ok {
					for _, failedCheck := range failedChecks {
						check, ok := failedCheck.(map[string]interface{})
						if !ok {
							logger.Debug().Str("tool", "checkov").Msgf("skipping non-map failed check: %v", failedCheck)
							continue
						}
						categorizedResults[utils.INFRA_SECURITY] = append(
							categorizedResults[utils.INFRA_SECURITY],
							formatCheckovIssue(check, directory),
						)
					}
				} else {
					logger.Debug().Str("tool", "checkov").Msg("no failed_checks in results map")
				}
			} else {
				logger.Debug().Str("tool", "checkov").Msg("no results map in result")
			}
		}
	case map[string]interface{}:
		if resultsMap, ok := checkovResults["results"].(map[string]interface{}); ok {
			if failedChecks, ok := resultsMap["failed_checks"].([]interface{}); ok {
				for _, failedCheck := range failedChecks {
					check, ok := failedCheck.(map[string]interface{})
					if !ok {
						logger.Debug().Str("tool", "checkov").Msgf("skipping non-map failed check: %v", failedCheck)
						continue
					}
					categorizedResults[utils.INFRA_SECURITY] = append(
						categorizedResults[utils.INFRA_SECURITY],
						formatCheckovIssue(check, directory),
					)
				}
			} else {
				logger.Debug().Str("tool", "checkov").Msg("no failed_checks in results map")
			}
		} else {
			logger.Debug().Str("tool", "checkov").Msg("no results map in checkovResults")
		}
	default:
		logger.Warn().Str("tool", "checkov").Msgf("unexpected results structure: %T", checkovResults)
	}

	return categorizedResults
}

func formatCheckovIssue(issue map[string]interface{}, directory string) map[string]interface{} {
	filePath, _ := issue["file_path"].(string)
	checkID, _ := issue["check_id"].(string)
	severity, _ := issue["severity"].(string)
	checkName, _ := issue["check_name"].(string)
	fileLineRange, _ := issue["file_line_range"].([]interface{})

	var fileLineRangeStr string
	if len(fileLineRange) == 2 {
		startLine, ok1 := fileLineRange[0].(float64)
		endLine, ok2 := fileLineRange[1].(float64)
		if ok1 && ok2 {
			fileLineRangeStr = fmt.Sprintf("%d:%d", int(startLine), int(endLine))
		}
	}

	return map[string]interface{}{
		"path":            strings.Replace(filePath, directory, "", 1),
		"check_id":        checkID,
		"severity":        severity,
		"message":         checkName,
		"file_line_range": fileLineRangeStr,
	}
}
