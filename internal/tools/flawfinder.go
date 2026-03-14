package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// RunFlawfinder runs Flawfinder on a C/C++ project directory.
// Flawfinder is a Python tool so it must be installed in the environment.
func RunFlawfinder(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "flawfinder").Str("dir", directory).Msg("running")

	cmd := exec.Command("flawfinder",
		"--csv",
		"--quiet",
		directory,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "flawfinder").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeFlawfinderResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

// Flawfinder CSV columns: File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context
func categorizeFlawfinderResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	r := csv.NewReader(strings.NewReader(raw))
	records, err := r.ReadAll()
	if err != nil {
		logger.Error().Str("tool", "flawfinder").Err(err).Msg("failed to parse CSV output")
		return categorized
	}

	levelToSeverity := func(level int) string {
		switch {
		case level >= 4:
			return "HIGH"
		case level >= 2:
			return "MEDIUM"
		default:
			return "LOW"
		}
	}

	for i, row := range records {
		if i == 0 { // skip header
			continue
		}
		if len(row) < 8 {
			continue
		}

		filePath := strings.TrimPrefix(row[0], directory)
		lineNum, _ := strconv.Atoi(row[1])
		levelNum, _ := strconv.Atoi(row[3])
		category := row[4]
		funcName := row[5]
		warning := row[6]
		cweField := ""
		if len(row) >= 10 {
			cweField = row[9]
		}

		cweList := []string{}
		if cweField != "" {
			for _, c := range strings.Split(cweField, ",") {
				c = strings.TrimSpace(c)
				if c != "" {
					cweList = append(cweList, c)
				}
			}
		}

		finding := map[string]interface{}{
			"path":       filePath,
			"line":       lineNum,
			"message":    fmt.Sprintf("%s: %s", funcName, warning),
			"severity":   levelToSeverity(levelNum),
			"check_id":   category,
			"confidence": "MEDIUM",
			"likelihood": "MEDIUM",
			"cwe":        cweList,
			"owasp":      []string{},
			"endLine":    lineNum,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
