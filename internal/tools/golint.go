package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func RunGolint(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "golint").Str("dir", directory).Msg("running")
	golintResults, err := runGolintOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "golint").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	categorizedResults := CategorizeGolintResults(golintResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func runGolintOnRepo(directory string) (string, error) {
	cmd := exec.Command("golint", "./...")
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("failed to run golint: %v\nstderr: %s", err, stderr.String())
	}
	return strings.TrimSpace(stdout.String()), nil
}

func CategorizeGolintResults(results, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results != "" {
		issues := strings.Split(results, "\n")
		for _, issue := range issues {
			if issue != "" && len(strings.Split(issue, ":")) > 1 {
				formattedIssue := formatIssue(issue, directory)
				if strings.Contains(issue, "should have comment") {
					categorizedResults[utils.DOCKSTRING_ABSENT] = append(
						categorizedResults[utils.DOCKSTRING_ABSENT],
						formattedIssue,
					)
				} else if strings.Contains(issue, "cyclomatic complexity") {
					categorizedResults[utils.COMPLEX_FUNCTIONS] = append(
						categorizedResults[utils.COMPLEX_FUNCTIONS],
						formattedIssue,
					)
				} else {
					categorizedResults[utils.ANTIPATTERNS_BUGS] = append(
						categorizedResults[utils.ANTIPATTERNS_BUGS],
						formattedIssue,
					)
				}
			}
		}
	}

	return categorizedResults
}

func formatIssue(issue, directory string) map[string]interface{} {
	issueParts := strings.Split(issue, ":")
	if len(issueParts) > 3 {
		return map[string]interface{}{
			"path":    strings.Replace(issueParts[0], directory, "", 1),
			"line":    strings.TrimSpace(issueParts[1]),
			"column":  strings.TrimSpace(issueParts[2]),
			"message": strings.TrimSpace(issueParts[3]),
		}
	}

	return map[string]interface{}{
		"message": "Invalid issue format",
	}
}
