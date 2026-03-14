package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunKubeScore runs kube-score on Kubernetes manifests in the given directory.
func RunKubeScore(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "kube-score").Str("dir", directory).Msg("running")

	// kube-score reads from stdin or files; find all yaml files first
	cmd := exec.Command("sh", "-c",
		"find "+directory+" -name '*.yaml' -o -name '*.yml' | xargs kube-score score --output-format json 2>/dev/null",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "kube-score").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeKubeScoreResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeKubeScoreResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var results []struct {
		ObjectName string `json:"object_name"`
		FileName   string `json:"file_name"`
		Checks     []struct {
			Check struct {
				Name string `json:"name"`
			} `json:"check"`
			Grade    int    `json:"grade"`
			Comments []struct {
				Path        string `json:"path"`
				Summary     string `json:"summary"`
				Description string `json:"description"`
			} `json:"comments"`
		} `json:"checks"`
	}

	if err := json.Unmarshal([]byte(raw), &results); err != nil {
		logger.Error().Str("tool", "kube-score").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, obj := range results {
		filePath := strings.TrimPrefix(obj.FileName, directory)
		for _, check := range obj.Checks {
			if check.Grade >= 5 { // grade 5+ is passing
				continue
			}
			severity := "MEDIUM"
			if check.Grade == 1 {
				severity = "HIGH"
			}
			for _, comment := range check.Comments {
				msg := comment.Summary
				if comment.Description != "" {
					msg += ": " + comment.Description
				}
				finding := map[string]interface{}{
					"path":       filePath,
					"line":       0,
					"message":    msg,
					"severity":   severity,
					"check_id":   check.Check.Name,
					"confidence": "HIGH",
					"likelihood": "MEDIUM",
					"cwe":        []string{},
					"owasp":      []string{},
					"endLine":    0,
				}
				categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
			}
		}
	}

	return categorized
}
