package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"os/exec"
	"strings"
)

func RunVulture(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "vulture").Str("dir", directory).Msg("running")
	vultureResults, err := runVultureOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "vulture").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	ans := categorizeVultureResults(vultureResults, directory)
	return utils.ConvertCategorizedResults(ans), nil
}

func runVultureOnRepo(directory string) (string, error) {
	cmd := exec.Command("vulture", directory)
	output, _ := cmd.Output()
	return string(output), nil
}

func categorizeVultureResults(vultureResults string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	if vultureResults != "" {
		var results []map[string]interface{}
		lines := strings.Split(vultureResults, "\n")

		for _, line := range lines {
			match := strings.SplitN(line, ":", 3)
			if len(match) == 3 {
				result := map[string]interface{}{
					"file":    strings.Replace(match[0], directory, "", 1),
					"line":    match[1],
					"message": strings.TrimSpace(match[2]),
				}
				results = append(results, result)
			}
		}

		categorizedResults[utils.DEAD_CODE] = make([]interface{}, len(results))
		for i, res := range results {
			categorizedResults[utils.DEAD_CODE][i] = res
		}
	}

	return categorizedResults
}
