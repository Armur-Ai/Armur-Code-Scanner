package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// RunSwiftLint runs SwiftLint for Swift code security checks.
func RunSwiftLint(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("swiftlint", "lint", "--reporter", "json", dirPath)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() <= 2 {
			// SwiftLint exits 2 for violations found
		} else {
			return nil, fmt.Errorf("swiftlint error: %w", err)
		}
	}

	return parseSwiftLintOutput(output)
}

func parseSwiftLintOutput(output []byte) (map[string]interface{}, error) {
	var violations []map[string]interface{}
	if err := json.Unmarshal(output, &violations); err != nil {
		return map[string]interface{}{"security_issues": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, v := range violations {
		severity := "MEDIUM"
		if s, ok := v["severity"].(string); ok {
			switch s {
			case "Error":
				severity = "HIGH"
			case "Warning":
				severity = "MEDIUM"
			}
		}

		findings = append(findings, map[string]interface{}{
			"path":     v["file"],
			"line":     v["line"],
			"severity": severity,
			"message":  v["reason"],
			"rule_id":  v["rule_id"],
			"tool":     "swiftlint",
		})
	}

	return map[string]interface{}{"security_issues": findings}, nil
}

// RunShellCheck runs ShellCheck for shell script analysis.
func RunShellCheck(filePath string) (map[string]interface{}, error) {
	cmd := exec.Command("shellcheck", "--format=json", filePath)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// ShellCheck exits 1 when issues found
		} else {
			return nil, fmt.Errorf("shellcheck error: %w", err)
		}
	}

	var comments []map[string]interface{}
	if err := json.Unmarshal(output, &comments); err != nil {
		return map[string]interface{}{"security_issues": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, c := range comments {
		severity := "LOW"
		if level, ok := c["level"].(string); ok {
			switch level {
			case "error":
				severity = "HIGH"
			case "warning":
				severity = "MEDIUM"
			case "info":
				severity = "LOW"
			}
		}

		findings = append(findings, map[string]interface{}{
			"path":     c["file"],
			"line":     c["line"],
			"severity": severity,
			"message":  c["message"],
			"rule_id":  fmt.Sprintf("SC%v", c["code"]),
			"tool":     "shellcheck",
		})
	}

	return map[string]interface{}{"security_issues": findings}, nil
}
