package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"os/exec"
	"strings"
)

func RunGoDeadcode(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "deadcode").Str("dir", directory).Msg("running")
	results, err := RunDecodeOnRepO(directory)
	if err != nil {
		logger.Warn().Str("tool", "deadcode").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	catresult := categorizeDeadCodeResults(results, directory)
	return utils.ConvertCategorizedResults(catresult), nil
}

func RunDecodeOnRepO(directory string) (string, error) {
	cmd := exec.Command("deadcode", directory)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debug().Str("tool", "deadcode").Err(err).Msg("non-zero exit (may still have results)")
	}
	return strings.TrimSpace(string(output)), nil
}

func categorizeDeadCodeResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	if results == "" || !strings.Contains(results, ":") {
		return categorizedResults
	}

	lines := strings.Split(results, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		formattedIssue := formatDeadCodeIssue(line, directory)
		if len(formattedIssue) > 0 {
			categorizedResults[utils.DEAD_CODE] = append(categorizedResults[utils.DEAD_CODE], formattedIssue)
		}
	}

	return categorizedResults
}

func formatDeadCodeIssue(issue string, directory string) map[string]interface{} {
	parts := strings.SplitN(issue, ":", 3)
	if len(parts) < 3 {
		return nil
	}
	return map[string]interface{}{
		"path":    strings.TrimPrefix(parts[0], directory),
		"line":    strings.TrimSpace(parts[1]),
		"message": strings.TrimSpace(parts[2]),
	}
}
