package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunPsalm runs the Psalm PHP static analysis tool on a project directory.
func RunPsalm(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "psalm").Str("dir", directory).Msg("running")

	cmd := exec.Command("psalm",
		"--output-format=json",
		"--no-progress",
		directory,
	)
	cmd.Dir = directory
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "psalm").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizePsalmResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizePsalmResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var issues []struct {
		Type      string `json:"type"`
		Severity  string `json:"severity"`
		FilePath  string `json:"file_path"`
		Line      int    `json:"line_from"`
		EndLine   int    `json:"line_to"`
		Message   string `json:"message"`
		ErrorCode int    `json:"error_code"`
	}

	if err := json.Unmarshal([]byte(raw), &issues); err != nil {
		logger.Error().Str("tool", "psalm").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, issue := range issues {
		severity := strings.ToUpper(issue.Severity)
		if severity == "" {
			severity = "MEDIUM"
		}
		filePath := strings.TrimPrefix(issue.FilePath, directory)
		finding := map[string]interface{}{
			"path":       filePath,
			"line":       issue.Line,
			"message":    issue.Message,
			"severity":   severity,
			"check_id":   issue.Type,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    issue.EndLine,
		}
		if issue.Severity == "error" {
			categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
		} else {
			categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
		}
	}

	return categorized
}
