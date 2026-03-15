package internal

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PII patterns for detecting personally identifiable information in source code.
var piiPatterns = []struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	CWE      string
}{
	{"Email Address", regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), "MEDIUM", "CWE-359"},
	{"SSN (US)", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), "CRITICAL", "CWE-359"},
	{"Credit Card (Visa)", regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`), "CRITICAL", "CWE-311"},
	{"Credit Card (Mastercard)", regexp.MustCompile(`\b5[1-5][0-9]{14}\b`), "CRITICAL", "CWE-311"},
	{"Phone (US)", regexp.MustCompile(`\b\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`), "MEDIUM", "CWE-359"},
	{"Phone (E.164)", regexp.MustCompile(`\+[1-9]\d{6,14}\b`), "MEDIUM", "CWE-359"},
	{"IP Address (IPv4)", regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`), "LOW", "CWE-200"},
	{"Date of Birth Pattern", regexp.MustCompile(`(?i)\b(?:date_of_birth|dob|birth_date|birthdate)\b`), "MEDIUM", "CWE-359"},
	{"Password Field", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`), "HIGH", "CWE-798"},
}

// Exclude patterns to reduce false positives.
var piiExcludes = []string{
	"test", "example", "mock", "fixture", "spec",
	"node_modules", "vendor", ".git", "__pycache__",
}

// RunPIIDetection scans source files for PII patterns.
func RunPIIDetection(dirPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip directories and non-source files
		if info.IsDir() {
			base := filepath.Base(path)
			for _, excl := range piiExcludes {
				if base == excl {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Only scan source code files
		if !isSourceFile(path) {
			return nil
		}

		// Skip test files
		rel, _ := filepath.Rel(dirPath, path)
		if isTestPath(rel) {
			return nil
		}

		fileFindings := scanFileForPII(path, rel)
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	// Cap findings to prevent alert fatigue
	if len(findings) > 200 {
		findings = findings[:200]
	}

	return map[string]interface{}{"pii_detection": findings}, nil
}

func scanFileForPII(absPath, relPath string) []interface{} {
	file, err := os.Open(absPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var findings []interface{}
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments and import lines (high FP rate)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "import") || strings.HasPrefix(trimmed, "from") {
			continue
		}

		for _, pattern := range piiPatterns {
			if pattern.Pattern.MatchString(line) {
				// Skip if it looks like a test/example value
				if isLikelyTestValue(line) {
					continue
				}

				findings = append(findings, map[string]interface{}{
					"path":     relPath,
					"line":     lineNum,
					"severity": pattern.Severity,
					"message":  fmt.Sprintf("Potential %s found in source code", pattern.Name),
					"cwe":      pattern.CWE,
					"tool":     "pii-detect",
				})
				break // One finding per line
			}
		}
	}

	return findings
}

func isSourceFile(path string) bool {
	exts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".java": true, ".kt": true, ".rb": true, ".php": true, ".rs": true,
		".c": true, ".cpp": true, ".h": true, ".cs": true, ".swift": true,
		".yaml": true, ".yml": true, ".json": true, ".xml": true, ".env": true,
		".conf": true, ".cfg": true, ".ini": true, ".toml": true,
	}
	return exts[filepath.Ext(path)]
}

func isTestPath(relPath string) bool {
	lower := strings.ToLower(relPath)
	return strings.Contains(lower, "test") || strings.Contains(lower, "spec") ||
		strings.Contains(lower, "mock") || strings.Contains(lower, "fixture")
}

func isLikelyTestValue(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "example") || strings.Contains(lower, "test") ||
		strings.Contains(lower, "dummy") || strings.Contains(lower, "placeholder") ||
		strings.Contains(lower, "sample") || strings.Contains(lower, "fake") ||
		strings.Contains(lower, "xxx") || strings.Contains(lower, "000-00-0000")
}
