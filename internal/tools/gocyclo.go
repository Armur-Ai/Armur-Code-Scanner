package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"os/exec"
	"strings"
)

func RunGocyclo(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "gocyclo").Str("dir", directory).Msg("running")
	gocycloResults, err := RunGoCycloOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "gocyclo").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	categorizedResults := CategorizeGocycloResults(gocycloResults, directory)
	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunGoCycloOnRepo(directory string) (string, error) {
	cmd := exec.Command("gocyclo", directory)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Run()
	return out.String(), nil
}

func CategorizeGocycloResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results == "" {
		logger.Debug().Str("tool", "gocyclo").Msg("no results found")
		return categorizedResults
	}

	lines := strings.Split(results, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		complexity := parts[0]
		pkg := parts[1]
		function := parts[2]

		locationParts := strings.Split(parts[3], ":")
		if len(locationParts) != 3 {
			logger.Debug().Str("tool", "gocyclo").Msgf("invalid location format: %s", parts[3])
			continue
		}

		filePath := strings.Replace(locationParts[0], directory, "", 1)
		lineNumber := locationParts[1]
		columnNumber := locationParts[2]

		resultEntry := map[string]interface{}{
			"complexity": complexity,
			"function":   function,
			"package":    pkg,
			"path":       filePath,
			"line":       lineNumber,
			"column":     columnNumber,
		}

		categorizedResults[utils.COMPLEX_FUNCTIONS] = append(categorizedResults[utils.COMPLEX_FUNCTIONS], resultEntry)
	}

	return categorizedResults
}
