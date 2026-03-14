package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunPHPCS runs PHP_CodeSniffer with security sniffs on a PHP project directory.
func RunPHPCS(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "phpcs").Str("dir", directory).Msg("running")

	cmd := exec.Command("phpcs",
		"--standard=Generic,Security",
		"--report=json",
		"--extensions=php",
		directory,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "phpcs").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizePHPCSResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizePHPCSResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Files map[string]struct {
			Messages []struct {
				Message  string `json:"message"`
				Source   string `json:"source"`
				Severity int    `json:"severity"`
				Type     string `json:"type"`
				Line     int    `json:"line"`
				Column   int    `json:"column"`
			} `json:"messages"`
		} `json:"files"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "phpcs").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for filePath, fileData := range report.Files {
		relPath := strings.TrimPrefix(filePath, directory)
		for _, msg := range fileData.Messages {
			severity := "LOW"
			if msg.Type == "ERROR" {
				severity = "HIGH"
			} else if msg.Severity >= 5 {
				severity = "MEDIUM"
			}
			finding := map[string]interface{}{
				"path":       relPath,
				"line":       msg.Line,
				"message":    msg.Message,
				"severity":   severity,
				"check_id":   msg.Source,
				"confidence": "MEDIUM",
				"likelihood": "MEDIUM",
				"cwe":        []string{},
				"owasp":      []string{},
				"endLine":    msg.Line,
			}
			categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
		}
	}

	return categorized
}
