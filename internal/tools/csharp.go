package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// RunSecurityCodeScan runs the Roslyn-based C# security scanner.
func RunSecurityCodeScan(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("dotnet-scs", "--project", dirPath, "--export-sarif-file", "/dev/stdout")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("security code scan error: %w", err)
	}

	var sarif map[string]interface{}
	if err := json.Unmarshal(output, &sarif); err != nil {
		return map[string]interface{}{"security_issues": []interface{}{}}, nil
	}

	return parseSARIFOutput(sarif, "security-code-scan")
}

// RunRoslynator runs the Roslynator code quality analyzer.
func RunRoslynator(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("roslynator", "analyze", dirPath, "--output", "/dev/stdout", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("roslynator error: %w", err)
	}

	return parseGenericJSONFindings(output, "roslynator", "antipatterns_bugs")
}

// parseSARIFOutput parses SARIF format results into the standard format.
func parseSARIFOutput(sarif map[string]interface{}, toolName string) (map[string]interface{}, error) {
	findings := []interface{}{}

	runs, ok := sarif["runs"].([]interface{})
	if !ok {
		return map[string]interface{}{"security_issues": findings}, nil
	}

	for _, run := range runs {
		runMap, ok := run.(map[string]interface{})
		if !ok {
			continue
		}
		results, ok := runMap["results"].([]interface{})
		if !ok {
			continue
		}
		for _, result := range results {
			rm, ok := result.(map[string]interface{})
			if !ok {
				continue
			}

			severity := "MEDIUM"
			if level, ok := rm["level"].(string); ok {
				switch level {
				case "error":
					severity = "HIGH"
				case "warning":
					severity = "MEDIUM"
				case "note":
					severity = "LOW"
				}
			}

			message := ""
			if msg, ok := rm["message"].(map[string]interface{}); ok {
				if text, ok := msg["text"].(string); ok {
					message = text
				}
			}

			ruleID := ""
			if r, ok := rm["ruleId"].(string); ok {
				ruleID = r
			}

			findings = append(findings, map[string]interface{}{
				"severity": severity,
				"message":  message,
				"rule_id":  ruleID,
				"tool":     toolName,
			})
		}
	}

	return map[string]interface{}{"security_issues": findings}, nil
}

func parseGenericJSONFindings(output []byte, toolName, category string) (map[string]interface{}, error) {
	findings := []interface{}{}

	var results []map[string]interface{}
	if err := json.Unmarshal(output, &results); err != nil {
		return map[string]interface{}{category: findings}, nil
	}

	for _, r := range results {
		findings = append(findings, map[string]interface{}{
			"path":     r["file"],
			"line":     r["line"],
			"severity": r["severity"],
			"message":  r["message"],
			"tool":     toolName,
		})
	}

	return map[string]interface{}{category: findings}, nil
}
