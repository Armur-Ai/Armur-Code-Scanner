package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

func RunRadon(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "radon").Str("dir", directory).Msg("running")
	radonResults := RunRadonOnRepo(directory)
	categorizedResults := CategorizeRadonResults(radonResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunRadonOnRepo(directory string) string {
	cmd := exec.Command("radon", "cc", "-j", directory)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		logger.Warn().Str("tool", "radon").Err(err).Str("stderr", stderr.String()).Msg("tool exited with error")
		return ""
	}

	return out.String()
}

func CategorizeRadonResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results != "" {
		var parsedResults map[string][]map[string]interface{}
		err := json.Unmarshal([]byte(results), &parsedResults)
		if err != nil {
			logger.Error().Str("tool", "radon").Err(err).Msg("failed to parse results")
			return categorizedResults
		}

		for filePath, issues := range parsedResults {
			relativePath := strings.Replace(filePath, directory, "", 1)
			for _, issue := range issues {
				issue["path"] = relativePath
				categorizedResults[utils.COMPLEX_FUNCTIONS] = append(categorizedResults[utils.COMPLEX_FUNCTIONS], issue)
			}
		}
	}

	return categorizedResults
}
