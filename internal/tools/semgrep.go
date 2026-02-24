package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func RunSemgrep(directory string, rules string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "semgrep").Str("dir", directory).Msg("running")
	semgrepResults, err := runSemgrepOnRepo(directory, "--config=auto")
	if err != nil {
		logger.Warn().Str("tool", "semgrep").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	categorizedResults := CategorizeSemgrepResults(semgrepResults, directory)
	newcatresult := utils.ConvertCategorizedResults(categorizedResults)
	return newcatresult, nil
}

func runSemgrepOnRepo(directory string, rules string) (string, error) {
	cmd := exec.Command("semgrep", rules, directory, "--json")
	output, err := cmd.Output()
	if err != nil {
		// semgrep exits non-zero when it finds issues; treat stdout as valid output
		logger.Debug().Str("tool", "semgrep").Err(err).Msg("non-zero exit (may still have results)")
	}
	return string(output), nil
}

func CategorizeSemgrepResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	data, err := utils.LoadCWEData("pkg/common/cwd.json")
	if err != nil {
		logger.Warn().Str("tool", "semgrep").Err(err).Msg("CWE data unavailable, skipping practice enrichment")
	}

	if results != "" {
		var parsedResults map[string]interface{}
		err := json.Unmarshal([]byte(results), &parsedResults)
		if err != nil {
			logger.Error().Str("tool", "semgrep").Err(err).Msg("failed to parse results")
			return categorizedResults
		}

		resultsArr, ok := parsedResults["results"].([]interface{})
		if !ok {
			logger.Debug().Str("tool", "semgrep").Msg("no 'results' array found in output")
			return categorizedResults
		}

		for _, res := range resultsArr {
			result, ok := res.(map[string]interface{})
			if !ok {
				logger.Debug().Str("tool", "semgrep").Msg("skipping invalid result entry")
				continue
			}

			checkID, ok := result["check_id"].(string)
			if !ok {
				logger.Debug().Str("tool", "semgrep").Msg("missing or invalid 'check_id', skipping")
				continue
			}
			path, ok := result["path"].(string)
			if !ok {
				logger.Debug().Str("tool", "semgrep").Msg("missing or invalid 'path', skipping")
				continue
			}

			path = strings.Replace(path, directory, "", 1)

			switch {
			case strings.Contains(strings.ToLower(checkID), "docstring"):
				categorizedResults[DOCKSTRING_ABSENT] = append(categorizedResults[DOCKSTRING_ABSENT], result)

			case strings.Contains(strings.ToLower(checkID), "security"):
				securityResult := make(map[string]interface{})
				securityResult["path"] = path

				if start, ok := result["start"].(map[string]interface{}); ok {
					securityResult["line"] = start["line"]
					securityResult["column"] = start["col"]
				}
				if end, ok := result["end"].(map[string]interface{}); ok {
					securityResult["endLine"] = end["line"]
				}
				if extra, ok := result["extra"].(map[string]interface{}); ok {
					securityResult["message"] = extra["message"]
					securityResult["severity"] = formatSeverity(result)
					if metadata, ok := extra["metadata"].(map[string]interface{}); ok {
						securityResult["confidence"] = metadata["confidence"]
						securityResult["likelihood"] = metadata["likelihood"]
						securityResult["cwe"] = metadata["cwe"]
						securityResult["owasp"] = metadata["owasp"]
					}
				}

				if cwe, ok := securityResult["cwe"].([]interface{}); ok && len(cwe) > 0 {
					practices := utils.GetPracticesFromJSON(data, utils.DetectFileLanguage(path), cwe[0].(string))
					for key, value := range practices {
						securityResult[key] = value
					}
				}

				categorizedResults[SECURITY_ISSUES] = append(categorizedResults[SECURITY_ISSUES], securityResult)

			case strings.Contains(strings.ToLower(checkID), "complexity"):
				categorizedResults[COMPLEX_FUNCTIONS] = append(categorizedResults[COMPLEX_FUNCTIONS], result)

			default:
				antipatternBug := map[string]interface{}{
					"column":  fmt.Sprintf("%v", result["start"].(map[string]interface{})["col"]),
					"line":    fmt.Sprintf("%v", result["start"].(map[string]interface{})["line"]),
					"message": result["extra"].(map[string]interface{})["message"],
					"path":    path,
				}
				categorizedResults[ANTIPATTERNS_BUGS] = append(categorizedResults[ANTIPATTERNS_BUGS], antipatternBug)
			}
		}
	}
	return categorizedResults
}

func formatSeverity(result map[string]interface{}) string {
	originalSeverity := result["extra"].(map[string]interface{})["severity"].(string)
	switch strings.ToUpper(originalSeverity) {
	case "INFO":
		return "LOW"
	case "WARNING":
		return "MEDIUM"
	case "ERROR":
		return "HIGH"
	default:
		return originalSeverity
	}
}
