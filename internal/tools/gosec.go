package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type CWEData struct {
	CWE                 string            `json:"cwe"`
	GoodPracticeExample map[string]string `json:"good_practice_example"`
	BadPracticeExample  map[string]string `json:"bad_practice_example"`
}

func GetPracticesFromJSON(data []CWEData, language string, cwe string) map[string]string {
	for _, item := range data {
		if item.CWE == cwe {
			goodPractice, goodFound := item.GoodPracticeExample[language]
			badPractice, badFound := item.BadPracticeExample[language]

			if goodFound && badFound {
				return map[string]string{
					"good_practice": goodPractice,
					"bad_practice":  badPractice,
				}
			}
		}
	}
	return map[string]string{}
}

func RunGosec(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "gosec").Str("dir", directory).Msg("running")
	results, err := RunGosecOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "gosec").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	categorizedResults := CategorizeGosecResults(results, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunGosecOnRepo(directory string) (string, error) {
	cmd := exec.Command("gosec", "-fmt=json", "./...")
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()
	logger.Debug().Str("tool", "gosec").Int("output_bytes", stdout.Len()).Msg("raw output received")
	return stdout.String(), nil
}

func CategorizeGosecResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	var cweData []CWEData
	cweDataFile, err := os.ReadFile("pkg/common/cwd.json")
	if err != nil {
		logger.Warn().Str("tool", "gosec").Err(err).Msg("CWE data unavailable, skipping practice enrichment")
	} else if err := json.Unmarshal(cweDataFile, &cweData); err != nil {
		logger.Warn().Str("tool", "gosec").Err(err).Msg("failed to parse CWE JSON, skipping practice enrichment")
	}

	if results != "" {
		var parsedResults map[string]interface{}
		if err := json.Unmarshal([]byte(results), &parsedResults); err != nil {
			logger.Error().Str("tool", "gosec").Err(err).Msg("failed to parse results")
			return categorizedResults
		}

		if issues, ok := parsedResults["Issues"].([]interface{}); ok {
			for _, issue := range issues {
				issueMap, mapOk := issue.(map[string]interface{})
				if !mapOk {
					logger.Debug().Str("tool", "gosec").Msgf("skipping invalid issue format: %v", issue)
					continue
				}

				cweID := "unknown"
				if cweObj, ok := issueMap["cwe"].(map[string]interface{}); ok {
					if id, ok := cweObj["id"].(string); ok {
						cweID = fmt.Sprintf("CWE-%s", id)
					}
				}

				formattedIssue := map[string]interface{}{
					"path":       strings.Replace(issueMap["file"].(string), directory, "", 1),
					"line":       issueMap["line"],
					"column":     issueMap["column"],
					"message":    issueMap["details"],
					"severity":   strings.ToUpper(issueMap["severity"].(string)),
					"check_id":   issueMap["rule_id"],
					"confidence": strings.ToUpper(issueMap["confidence"].(string)),
					"likelihood": "NA",
					"cwe":        []string{cweID},
					"owasp":      []string{},
					"endLine":    issueMap["line"],
				}

				practices := GetPracticesFromJSON(cweData, "go", cweID)
				for key, value := range practices {
					formattedIssue[key] = value
				}

				categorizedResults[SECURITY_ISSUES] = append(categorizedResults[SECURITY_ISSUES], formattedIssue)
			}
		}

		if golangErrors, ok := parsedResults["Golang errors"].(map[string]interface{}); ok {
			for path, errors := range golangErrors {
				errorList, listOk := errors.([]interface{})
				if !listOk {
					logger.Debug().Str("tool", "gosec").Msgf("invalid Golang errors format for path %s", path)
					continue
				}

				for _, err := range errorList {
					errorMap, mapOk := err.(map[string]interface{})
					if !mapOk {
						logger.Debug().Str("tool", "gosec").Msgf("invalid error format: %v", err)
						continue
					}

					antipatternsBug := map[string]interface{}{
						"path":    strings.Replace(path, directory, "", 1),
						"line":    fmt.Sprintf("%v", errorMap["line"]),
						"column":  fmt.Sprintf("%v", errorMap["column"]),
						"message": fmt.Sprintf("%v", errorMap["error"]),
					}

					categorizedResults[ANTIPATTERNS_BUGS] = append(categorizedResults[ANTIPATTERNS_BUGS], antipatternsBug)
				}
			}
		}
	}

	return categorizedResults
}
