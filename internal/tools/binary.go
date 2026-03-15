package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// RunChecksec runs checksec on a binary to check security hardening.
func RunChecksec(binaryPath string) (map[string]interface{}, error) {
	cmd := exec.Command("checksec", "--format=json", "--file="+binaryPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("checksec error: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	findings := []interface{}{}

	// Parse checksec results
	for file, data := range result {
		props, ok := data.(map[string]interface{})
		if !ok {
			continue
		}

		checks := map[string]struct {
			field    string
			badValue string
			message  string
			severity string
		}{
			"RELRO":     {"relro", "no", "No RELRO — GOT overwrite attacks possible", "HIGH"},
			"Stack Canary": {"canary", "no", "No stack canary — buffer overflow exploitation easier", "HIGH"},
			"NX":        {"nx", "no", "NX disabled — code execution on stack possible", "CRITICAL"},
			"PIE":       {"pie", "no", "No PIE — ASLR bypass easier", "MEDIUM"},
			"FORTIFY":   {"fortify_source", "no", "FORTIFY_SOURCE not enabled", "LOW"},
		}

		for name, check := range checks {
			if val, ok := props[check.field].(string); ok && strings.ToLower(val) == check.badValue {
				findings = append(findings, map[string]interface{}{
					"path":     file,
					"line":     0,
					"severity": check.severity,
					"message":  fmt.Sprintf("%s: %s", name, check.message),
					"tool":     "checksec",
				})
			}
		}
	}

	return map[string]interface{}{"binary_security": findings}, nil
}

// RunGoVersionM extracts dependency info from compiled Go binaries.
func RunGoVersionM(binaryPath string) (map[string]interface{}, error) {
	cmd := exec.Command("go", "version", "-m", binaryPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go version -m error: %w", err)
	}

	findings := []interface{}{}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "dep\t") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				findings = append(findings, map[string]interface{}{
					"path":     binaryPath,
					"line":     0,
					"severity": "INFO",
					"message":  fmt.Sprintf("Embedded dependency: %s@%s", parts[1], parts[2]),
					"tool":     "go-version-m",
				})
			}
		}
	}

	return map[string]interface{}{"binary_dependencies": findings}, nil
}

// RunStringScan scans a binary for potentially sensitive hardcoded strings.
func RunStringScan(binaryPath string) (map[string]interface{}, error) {
	cmd := exec.Command("strings", binaryPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("strings error: %w", err)
	}

	findings := []interface{}{}
	sensitivePatterns := []struct {
		pattern  string
		message  string
		severity string
	}{
		{"password", "Possible hardcoded password string", "HIGH"},
		{"secret", "Possible hardcoded secret string", "HIGH"},
		{"api_key", "Possible hardcoded API key", "HIGH"},
		{"private_key", "Possible embedded private key reference", "CRITICAL"},
		{"BEGIN RSA PRIVATE", "Embedded RSA private key", "CRITICAL"},
		{"BEGIN EC PRIVATE", "Embedded EC private key", "CRITICAL"},
		{"AKIA", "Possible AWS access key ID", "CRITICAL"},
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, p := range sensitivePatterns {
			if strings.Contains(lower, p.pattern) && len(line) > 8 && len(line) < 200 {
				findings = append(findings, map[string]interface{}{
					"path":     binaryPath,
					"line":     0,
					"severity": p.severity,
					"message":  fmt.Sprintf("%s: \"%s\"", p.message, truncateStr(line, 80)),
					"tool":     "string-scan",
				})
				break
			}
		}
	}

	// Cap findings
	if len(findings) > 50 {
		findings = findings[:50]
	}

	return map[string]interface{}{"binary_security": findings}, nil
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
