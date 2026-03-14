package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"os/exec"
	"regexp"
	"strings"
)

// RunCargoGeiger runs cargo-geiger to detect unsafe Rust code and returns findings.
func RunCargoGeiger(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "cargo-geiger").Str("dir", directory).Msg("running")

	cmd := exec.Command("cargo", "geiger", "--output-format", "GitHubMarkdown", "--quiet")
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "cargo-geiger").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeCargoGeigerResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

// categorizeCargoGeigerResults parses the text/markdown output from cargo-geiger.
// Lines with non-zero unsafe counts are reported as security issues.
func categorizeCargoGeigerResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	// cargo-geiger --output-format GitHubMarkdown produces lines like:
	// | crate_name | unsafe_fns/total_fns | ... |
	tableLineRe := regexp.MustCompile(`^\|\s*(\S+)\s*\|\s*(\d+)/(\d+)`)

	for _, line := range strings.Split(raw, "\n") {
		m := tableLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		crate := m[1]
		unsafeCount := m[2]
		if unsafeCount == "0" {
			continue
		}
		finding := map[string]interface{}{
			"path":       "Cargo.toml",
			"line":       0,
			"message":    "Crate '" + crate + "' contains " + unsafeCount + " unsafe function(s)",
			"severity":   "MEDIUM",
			"check_id":   "UNSAFE_CODE",
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{"CWE-119"},
			"owasp":      []string{},
			"endLine":    0,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
