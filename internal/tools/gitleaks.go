package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// RunGitleaks runs the gitleaks secret scanner on the given directory.
func RunGitleaks(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("gitleaks", "detect",
		"--source", dirPath,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-banner",
	)

	output, err := cmd.Output()
	if err != nil {
		// Gitleaks exits 1 when findings are found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// Findings found — parse them
		} else {
			return nil, fmt.Errorf("gitleaks error: %w", err)
		}
	}

	return parseGitleaksOutput(output)
}

// RunGitleaksHistory runs gitleaks against the full git history.
func RunGitleaksHistory(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("gitleaks", "detect",
		"--source", dirPath,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-banner",
		"--log-opts=--all",
	)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// Findings found
		} else {
			return nil, fmt.Errorf("gitleaks history error: %w", err)
		}
	}

	return parseGitleaksOutput(output)
}

func parseGitleaksOutput(output []byte) (map[string]interface{}, error) {
	if len(output) == 0 {
		return map[string]interface{}{"secret_detection": []interface{}{}}, nil
	}

	var findings []map[string]interface{}
	if err := json.Unmarshal(output, &findings); err != nil {
		return map[string]interface{}{"secret_detection": []interface{}{}}, nil
	}

	results := []interface{}{}
	for _, f := range findings {
		ruleID, _ := f["RuleID"].(string)
		description, _ := f["Description"].(string)
		file, _ := f["File"].(string)
		startLine, _ := f["StartLine"].(float64)
		commit, _ := f["Commit"].(string)
		author, _ := f["Author"].(string)
		date, _ := f["Date"].(string)

		finding := map[string]interface{}{
			"path":     file,
			"line":     int(startLine),
			"severity": "CRITICAL",
			"message":  fmt.Sprintf("%s: %s", ruleID, description),
			"tool":     "gitleaks",
			"rule_id":  ruleID,
		}

		if commit != "" {
			finding["commit"] = commit
			finding["author"] = author
			finding["date"] = date
		}

		results = append(results, finding)
	}

	return map[string]interface{}{"secret_detection": results}, nil
}
