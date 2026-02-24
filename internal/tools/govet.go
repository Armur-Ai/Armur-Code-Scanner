package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func RunGovet(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "govet").Str("dir", directory).Msg("running")
	govetResults := runGovetOnRepo(directory)
	categorizedResults := categorizeGovetResults(govetResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func runGovetOnRepo(directory string) string {
	if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
		cmd := exec.Command("go", "vet", "./...")
		cmd.Dir = directory
		output, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(output))
	}

	files := []string{}
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(info.Name(), ".go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		logger.Error().Str("tool", "govet").Err(err).Msg("failed to scan Go files")
	}

	if len(files) == 0 {
		return ""
	}

	cmd := exec.Command("go", append([]string{"vet"}, files...)...)
	cmd.Dir = directory
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debug().Str("tool", "govet").Err(err).Msg("non-zero exit (may still have results)")
	}
	return strings.TrimSpace(string(output))
}

func categorizeGovetResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results != "" {
		issues := strings.Split(results, "\n")
		for _, issue := range issues {
			if issue != "" && len(strings.Split(issue, ":")) > 1 {
				formattedIssue := formatIssuess(issue, directory)
				categorizedResults[utils.ANTIPATTERNS_BUGS] = append(categorizedResults[utils.ANTIPATTERNS_BUGS], formattedIssue)
			}
		}
	}

	return categorizedResults
}

func formatIssuess(issue string, directory string) map[string]interface{} {
	issueParts := strings.Split(issue, ":")
	if len(issueParts) < 4 {
		return map[string]interface{}{
			"path":    strings.Replace(issueParts[0], directory, "", 1),
			"message": strings.Join(issueParts[1:], ":"),
		}
	}

	return map[string]interface{}{
		"path":    strings.Replace(issueParts[0], directory, "", 1),
		"line":    issueParts[1],
		"column":  issueParts[2],
		"message": issueParts[3],
	}
}
