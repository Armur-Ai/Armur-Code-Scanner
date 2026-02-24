package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

const (
	DUPLICATE_CODE_LINE_THRESHOLD = 10
)

func RunJSCPD(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "jscpd").Str("dir", directory).Msg("running")
	duplicates, err := RunJSCPDOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "jscpd").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	results := CategorizeJSCPDResults(duplicates, directory)
	return utils.ConvertCategorizedResults(results), nil
}

func RunJSCPDOnRepo(directory string) ([]map[string]interface{}, error) {
	cmd := exec.Command("jscpd", directory, "-r", "json", "-o", ".")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn().Str("tool", "jscpd").Err(err).Str("output", string(output)).Msg("tool exited with error")
		return nil, err
	}

	outputFile := "jscpd-report.json"
	if _, err := os.Stat(outputFile); err == nil {
		file, err := os.Open(outputFile)
		if err != nil {
			logger.Error().Str("tool", "jscpd").Err(err).Msg("failed to open report file")
			return nil, err
		}
		defer file.Close()

		var report map[string]interface{}
		if err := json.NewDecoder(file).Decode(&report); err != nil {
			logger.Error().Str("tool", "jscpd").Err(err).Msg("failed to parse JSON report")
			return nil, err
		}
		duplicates, ok := report["duplicates"].([]interface{})
		if !ok {
			logger.Debug().Str("tool", "jscpd").Msg("no duplicates found in report")
			return nil, nil
		}

		var result []map[string]interface{}
		for _, d := range duplicates {
			if dup, ok := d.(map[string]interface{}); ok {
				result = append(result, dup)
			}
		}
		return result, nil
	}

	logger.Debug().Str("tool", "jscpd").Msg("no report file generated")
	return nil, nil
}

func CategorizeJSCPDResults(results []map[string]interface{}, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	for _, duplicate := range results {
		firstFile, _ := duplicate["firstFile"].(map[string]interface{})
		secondFile, _ := duplicate["secondFile"].(map[string]interface{})

		firstFileName, _ := firstFile["name"].(string)
		secondFileName, _ := secondFile["name"].(string)
		startInFirstFile, _ := firstFile["start"].(float64)
		endInFirstFile, _ := firstFile["end"].(float64)
		startInSecondFile, _ := secondFile["start"].(float64)
		endInSecondFile, _ := secondFile["end"].(float64)

		cleanDirectory := strings.Replace(directory, "/armur/", "", -1)

		categorizedResults[utils.DUPLICATE_CODE] = append(categorizedResults[utils.DUPLICATE_CODE], map[string]interface{}{
			"first_file":           strings.Replace(firstFileName, cleanDirectory, "", -1),
			"second_file":          strings.Replace(secondFileName, cleanDirectory, "", -1),
			"start_in_first_file":  startInFirstFile,
			"end_in_first_file":    endInFirstFile,
			"start_in_second_file": startInSecondFile,
			"end_in_second_file":   endInSecondFile,
			"severity":             determineSeverity(endInFirstFile - startInFirstFile),
		})
	}

	return categorizedResults
}

func determineSeverity(lines float64) string {
	if lines < DUPLICATE_CODE_LINE_THRESHOLD {
		return "Minor"
	}
	return "Major"
}
