package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunPMD runs PMD static analysis on a Java/Kotlin project directory.
func RunPMD(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "pmd").Str("dir", directory).Msg("running")

	cmd := exec.Command("pmd", "check",
		"-d", directory,
		"-R", "rulesets/java/quickstart.xml",
		"-f", "json",
		"--no-cache",
	)
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "pmd").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizePMDResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizePMDResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Files []struct {
			Filename  string `json:"filename"`
			Violations []struct {
				BeginLine   int    `json:"beginline"`
				EndLine     int    `json:"endline"`
				Description string `json:"description"`
				Rule        string `json:"rule"`
				Ruleset     string `json:"ruleset"`
				Priority    int    `json:"priority"`
			} `json:"violations"`
		} `json:"files"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "pmd").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	priorityToSeverity := map[int]string{
		1: "HIGH",
		2: "HIGH",
		3: "MEDIUM",
		4: "LOW",
		5: "INFO",
	}

	for _, file := range report.Files {
		filePath := strings.TrimPrefix(file.Filename, directory)
		for _, v := range file.Violations {
			severity := priorityToSeverity[v.Priority]
			if severity == "" {
				severity = "LOW"
			}
			finding := map[string]interface{}{
				"path":       filePath,
				"line":       v.BeginLine,
				"message":    v.Description,
				"severity":   severity,
				"check_id":   v.Rule,
				"confidence": "MEDIUM",
				"likelihood": "MEDIUM",
				"cwe":        []string{},
				"owasp":      []string{},
				"endLine":    v.EndLine,
			}
			categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
		}
	}

	return categorized
}
