package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// RunSlither runs the Slither Solidity static analyzer on a project directory.
func RunSlither(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "slither").Str("dir", directory).Msg("running")

	cmd := exec.Command("slither", ".", "--json", "-")
	cmd.Dir = directory
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "slither").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeSlitherResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeSlitherResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Success bool `json:"success"`
		Results struct {
			Detectors []struct {
				Check       string  `json:"check"`
				Impact      string  `json:"impact"`
				Confidence  string  `json:"confidence"`
				Description string  `json:"description"`
				Elements    []struct {
					Name string `json:"name"`
					Type string `json:"type"`
					SourceMapping *struct {
						Filename string `json:"filename"`
						Lines    []int  `json:"lines"`
					} `json:"source_mapping"`
				} `json:"elements"`
			} `json:"detectors"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "slither").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	impactToSeverity := map[string]string{
		"High":          "HIGH",
		"Medium":        "MEDIUM",
		"Low":           "LOW",
		"Informational": "INFO",
		"Optimization":  "INFO",
	}

	for _, det := range report.Results.Detectors {
		severity := impactToSeverity[det.Impact]
		if severity == "" {
			severity = "MEDIUM"
		}

		filePath := ""
		lineNum := 0
		if len(det.Elements) > 0 && det.Elements[0].SourceMapping != nil {
			filePath = strings.TrimPrefix(det.Elements[0].SourceMapping.Filename, directory)
			if len(det.Elements[0].SourceMapping.Lines) > 0 {
				lineNum = det.Elements[0].SourceMapping.Lines[0]
			}
		}

		finding := map[string]interface{}{
			"path":       filePath,
			"line":       lineNum,
			"message":    fmt.Sprintf("[%s] %s", det.Check, det.Description),
			"severity":   severity,
			"check_id":   det.Check,
			"confidence": strings.ToUpper(det.Confidence),
			"likelihood": "HIGH",
			"cwe":        []string{},
			"owasp":      []string{"A06:2021 - Vulnerable and Outdated Components"},
			"endLine":    lineNum,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
