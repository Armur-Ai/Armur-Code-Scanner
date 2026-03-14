package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunKICS runs Checkmarx KICS (multi-IaC scanner) on the given directory.
func RunKICS(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "kics").Str("dir", directory).Msg("running")

	outDir, err := os.MkdirTemp("", "kics-out")
	if err != nil {
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	defer os.RemoveAll(outDir)

	cmd := exec.Command("kics", "scan",
		"-p", directory,
		"-o", outDir,
		"--report-formats", "json",
		"--no-progress",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	reportPath := filepath.Join(outDir, "results.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		logger.Debug().Str("tool", "kics").Msg("report not found, returning empty")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeKICSResults(string(data), directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeKICSResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Queries []struct {
			QueryName string `json:"query_name"`
			Severity  string `json:"severity"`
			Platform  string `json:"platform"`
			Files     []struct {
				FileName     string `json:"file_name"`
				Line         int    `json:"line"`
				IssueType    string `json:"issue_type"`
				SearchKey    string `json:"search_key"`
				KeyExpected  string `json:"expected_value"`
				KeyActual    string `json:"actual_value"`
				SimID        string `json:"similarity_id"`
			} `json:"files"`
			CISDescriptionID string `json:"cis_description_id"`
		} `json:"queries"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "kics").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, q := range report.Queries {
		severity := strings.ToUpper(q.Severity)
		if severity == "" {
			severity = "MEDIUM"
		}
		for _, f := range q.Files {
			filePath := strings.TrimPrefix(f.FileName, directory)
			msg := fmt.Sprintf("%s (expected: %s, actual: %s)", q.QueryName, f.KeyExpected, f.KeyActual)
			finding := map[string]interface{}{
				"path":       filePath,
				"line":       f.Line,
				"message":    msg,
				"severity":   severity,
				"check_id":   q.QueryName,
				"confidence": "HIGH",
				"likelihood": "MEDIUM",
				"cwe":        []string{},
				"owasp":      []string{},
				"endLine":    f.Line,
			}
			categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
		}
	}

	return categorized
}
