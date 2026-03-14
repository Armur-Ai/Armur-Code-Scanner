package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunMythril runs the Mythril symbolic execution tool on all .sol files in directory.
func RunMythril(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "mythril").Str("dir", directory).Msg("running")

	// Find all .sol files and run myth analyze on each.
	categorized := utils.InitCategorizedResults()

	// Use find to locate .sol files
	findCmd := exec.Command("find", directory, "-name", "*.sol", "-not", "-path", "*/node_modules/*")
	var findOut bytes.Buffer
	findCmd.Stdout = &findOut
	findCmd.Run()

	solFiles := strings.Split(strings.TrimSpace(findOut.String()), "\n")
	if len(solFiles) == 0 || (len(solFiles) == 1 && solFiles[0] == "") {
		logger.Debug().Str("tool", "mythril").Msg("no .sol files found")
		return utils.ConvertCategorizedResults(categorized), nil
	}

	for _, solFile := range solFiles {
		if solFile == "" {
			continue
		}

		cmd := exec.Command("myth", "analyze", solFile,
			"--solv", "0.8.0",
			"-o", "json",
			"--execution-timeout", "60",
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Run()

		output := stdout.String()
		if strings.TrimSpace(output) == "" {
			continue
		}

		partial := categorizeMythrilResults(output, directory, filepath.Base(solFile))
		for key, vals := range partial {
			categorized[key] = append(categorized[key], vals...)
		}
	}

	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeMythrilResults(raw, directory, filename string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Success bool `json:"success"`
		Error   string `json:"error"`
		Issues  []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
			SWCID       string `json:"swcID"`
			SWCURL      string `json:"swcURL"`
			Locations   []struct {
				SourceMap string `json:"sourceMap"`
			} `json:"locations"`
		} `json:"issues"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "mythril").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	severityMap := map[string]string{
		"High":   "HIGH",
		"Medium": "MEDIUM",
		"Low":    "LOW",
	}

	for _, issue := range report.Issues {
		severity := severityMap[issue.Severity]
		if severity == "" {
			severity = "MEDIUM"
		}
		finding := map[string]interface{}{
			"path":       filename,
			"line":       0,
			"message":    fmt.Sprintf("[%s] %s: %s", issue.SWCID, issue.Title, issue.Description),
			"severity":   severity,
			"check_id":   issue.SWCID,
			"confidence": "HIGH",
			"likelihood": "HIGH",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    0,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
