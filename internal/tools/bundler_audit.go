package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// RunBundlerAudit runs bundler-audit on a Ruby project to check for gem vulnerabilities.
func RunBundlerAudit(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "bundler-audit").Str("dir", directory).Msg("running")

	cmd := exec.Command("bundle", "audit", "check", "--update")
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "bundler-audit").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeBundlerAuditResults(output)
	return utils.ConvertCategorizedResults(categorized), nil
}

// bundler-audit text output has blocks like:
//
//	Name: rails
//	Version: 5.2.4
//	Advisory: CVE-2020-8164
//	Criticality: High
//	Title: ...
//	Solution: upgrade to ...
func categorizeBundlerAuditResults(raw string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	// Split on blank lines to get per-advisory blocks.
	blocks := regexp.MustCompile(`\n\n+`).Split(raw, -1)

	for _, block := range blocks {
		if !strings.Contains(block, "Advisory:") {
			continue
		}

		gemName := extractField(block, "Name:")
		version := extractField(block, "Version:")
		advisory := extractField(block, "Advisory:")
		criticality := extractField(block, "Criticality:")
		title := extractField(block, "Title:")

		severity := strings.ToUpper(criticality)
		if severity == "" {
			severity = "MEDIUM"
		}

		finding := map[string]interface{}{
			"path":       fmt.Sprintf("Gemfile.lock (%s@%s)", gemName, version),
			"line":       0,
			"message":    title,
			"severity":   severity,
			"check_id":   advisory,
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

// extractField pulls the value after a label (e.g. "Name: rails" → "rails").
func extractField(block, label string) string {
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, label) {
			return strings.TrimSpace(strings.TrimPrefix(line, label))
		}
	}
	return ""
}
