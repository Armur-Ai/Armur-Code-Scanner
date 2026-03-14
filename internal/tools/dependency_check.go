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

// RunDependencyCheck runs OWASP Dependency-Check on a Java project directory.
func RunDependencyCheck(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "dependency-check").Str("dir", directory).Msg("running")

	// Dependency-Check writes a JSON report to a temp output dir.
	outDir, err := os.MkdirTemp("", "dep-check-out")
	if err != nil {
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	defer os.RemoveAll(outDir)

	cmd := exec.Command("dependency-check",
		"--scan", directory,
		"--format", "JSON",
		"--out", outDir,
		"--project", "armur-scan",
		"--noupdate",
	)
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	// Read the generated report.
	reportPath := filepath.Join(outDir, "dependency-check-report.json")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		logger.Debug().Str("tool", "dependency-check").Msg("report file not found, returning empty results")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeDependencyCheckResults(string(data), directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeDependencyCheckResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Dependencies []struct {
			FileName         string `json:"fileName"`
			Vulnerabilities  []struct {
				Name        string  `json:"name"`
				Severity    string  `json:"severity"`
				Description string  `json:"description"`
				CVSSv3      *struct{ BaseScore float64 `json:"baseScore"` } `json:"cvssv3"`
			} `json:"vulnerabilities"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "dependency-check").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, dep := range report.Dependencies {
		for _, vuln := range dep.Vulnerabilities {
			score := ""
			if vuln.CVSSv3 != nil {
				score = fmt.Sprintf("CVSS %.1f", vuln.CVSSv3.BaseScore)
			}
			finding := map[string]interface{}{
				"path":       strings.TrimPrefix(dep.FileName, directory),
				"line":       0,
				"message":    fmt.Sprintf("%s: %s %s", vuln.Name, vuln.Description, score),
				"severity":   strings.ToUpper(vuln.Severity),
				"check_id":   vuln.Name,
				"confidence": "HIGH",
				"likelihood": "HIGH",
				"cwe":        []string{},
				"owasp":      []string{"A06:2021 - Vulnerable and Outdated Components"},
				"endLine":    0,
			}
			categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
		}
	}

	return categorized
}
