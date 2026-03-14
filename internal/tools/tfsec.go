package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunTfsec runs tfsec on a Terraform project directory.
func RunTfsec(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "tfsec").Str("dir", directory).Msg("running")

	cmd := exec.Command("tfsec", "--format", "json", "--no-color", directory)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "tfsec").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeTfsecResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeTfsecResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Results []struct {
			RuleID      string `json:"rule_id"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
			Location    struct {
				Filename  string `json:"filename"`
				StartLine int    `json:"start_line"`
				EndLine   int    `json:"end_line"`
			} `json:"location"`
			Links []string `json:"links"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "tfsec").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, res := range report.Results {
		filePath := strings.TrimPrefix(res.Location.Filename, directory)
		severity := strings.ToUpper(res.Severity)
		if severity == "" {
			severity = "MEDIUM"
		}

		cweList := []string{}
		owaspList := []string{}
		for _, link := range res.Links {
			if strings.Contains(link, "cwe.mitre.org") {
				cweList = append(cweList, link)
			}
			if strings.Contains(link, "owasp.org") {
				owaspList = append(owaspList, link)
			}
		}

		finding := map[string]interface{}{
			"path":       filePath,
			"line":       res.Location.StartLine,
			"message":    res.Description,
			"severity":   severity,
			"check_id":   res.RuleID,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        cweList,
			"owasp":      owaspList,
			"endLine":    res.Location.EndLine,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
