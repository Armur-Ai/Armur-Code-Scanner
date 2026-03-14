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

// RunCargoAudit runs cargo-audit on a Rust project directory and returns findings.
func RunCargoAudit(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "cargo-audit").Str("dir", directory).Msg("running")

	cmd := exec.Command("cargo", "audit", "--json")
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run() // cargo-audit exits non-zero when vulnerabilities found — ignore exit code

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "cargo-audit").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeCargoAuditResults(output)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeCargoAuditResults(raw string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Vulnerabilities struct {
			List []struct {
				Advisory struct {
					ID          string `json:"id"`
					Title       string `json:"title"`
					Description string `json:"description"`
					CVE         string `json:"cvss"`
				} `json:"advisory"`
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Severity string `json:"severity"`
			} `json:"list"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "cargo-audit").Err(err).Msg("failed to parse output")
		return categorized
	}

	for _, vuln := range report.Vulnerabilities.List {
		finding := map[string]interface{}{
			"path":       fmt.Sprintf("Cargo.lock (%s@%s)", vuln.Package.Name, vuln.Package.Version),
			"line":       0,
			"message":    vuln.Advisory.Title,
			"severity":   strings.ToUpper(vuln.Severity),
			"check_id":   vuln.Advisory.ID,
			"confidence": "HIGH",
			"likelihood": "HIGH",
			"cwe":        []string{},
			"owasp":      []string{"A06:2021 - Vulnerable and Outdated Components"},
			"endLine":    0,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
