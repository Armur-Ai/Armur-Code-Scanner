package internal

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// OWASP LLM Top 10 patterns for detecting AI/LLM security issues in code.
var llmSecurityPatterns = []struct {
	Name     string
	ID       string // OWASP LLM Top 10 ID
	Pattern  *regexp.Regexp
	Severity string
	CWE      string
	Message  string
}{
	// LLM01: Prompt Injection
	{
		"Prompt Injection Risk",
		"LLM01",
		regexp.MustCompile(`(?i)(?:user_input|user_message|request\.body).*(?:prompt|system_prompt|messages)`),
		"HIGH",
		"CWE-74",
		"User input concatenated into LLM prompt without sanitization — risk of prompt injection",
	},
	{
		"f-string Prompt",
		"LLM01",
		regexp.MustCompile(`(?:f"|f').*\{.*(?:user|input|query|request).*\}.*(?:prompt|message|system)`),
		"HIGH",
		"CWE-74",
		"User input interpolated into prompt via f-string — use parameterized prompts instead",
	},

	// LLM02: Insecure Output Handling
	{
		"Unsanitized LLM Output",
		"LLM02",
		regexp.MustCompile(`(?i)(?:response|completion|output|result).*(?:exec|eval|subprocess|os\.system|dangerouslySetInnerHTML)`),
		"CRITICAL",
		"CWE-94",
		"LLM output passed directly to code execution or HTML rendering without sanitization",
	},
	{
		"LLM Output to SQL",
		"LLM02",
		regexp.MustCompile(`(?i)(?:response|completion|generated).*(?:query|sql|execute)`),
		"HIGH",
		"CWE-89",
		"LLM-generated content used in SQL query without parameterization",
	},

	// LLM03: Training Data Poisoning (detection limited to code patterns)
	{
		"Unvalidated Training Data Source",
		"LLM03",
		regexp.MustCompile(`(?i)(?:fine_tune|training_data|dataset).*(?:url|http|download|fetch)`),
		"MEDIUM",
		"CWE-20",
		"Training data loaded from external URL without integrity verification",
	},

	// LLM05: Supply Chain (LLM model download)
	{
		"Unverified Model Download",
		"LLM05",
		regexp.MustCompile(`(?i)(?:model|checkpoint|weights).*(?:download|fetch|http|url).*(?:load|from_pretrained)`),
		"MEDIUM",
		"CWE-494",
		"LLM model downloaded from external source without checksum verification",
	},

	// LLM06: Sensitive Information Disclosure
	{
		"API Key in Prompt",
		"LLM06",
		regexp.MustCompile(`(?i)(?:api_key|secret|password|token).*(?:prompt|message|system)`),
		"HIGH",
		"CWE-200",
		"Sensitive credential may be included in LLM prompt — risk of leakage via model output",
	},
	{
		"PII in LLM Context",
		"LLM06",
		regexp.MustCompile(`(?i)(?:email|phone|ssn|address|credit_card).*(?:prompt|context|message)`),
		"MEDIUM",
		"CWE-359",
		"Personal data may be sent to LLM — risk of PII leakage",
	},

	// LLM07: Insecure Plugin Design
	{
		"LLM Tool Without Auth",
		"LLM07",
		regexp.MustCompile(`(?i)(?:tool|function|plugin).*(?:execute|run|call).*(?:no_auth|skip_auth|bypass)`),
		"HIGH",
		"CWE-306",
		"LLM tool/plugin executes without authentication check",
	},

	// LLM08: Excessive Agency
	{
		"LLM Auto-Execute",
		"LLM08",
		regexp.MustCompile(`(?i)(?:auto_execute|auto_approve|confirm\s*=\s*False|require_approval\s*=\s*False)`),
		"HIGH",
		"CWE-284",
		"LLM agent configured to auto-execute actions without human approval — excessive agency risk",
	},
	{
		"Unrestricted Tool Access",
		"LLM08",
		regexp.MustCompile(`(?i)(?:all_tools|tools\s*=\s*\*|allow_all)`),
		"MEDIUM",
		"CWE-284",
		"LLM has unrestricted access to all tools — apply least-privilege principle",
	},

	// LLM SDK Detection
	{
		"OpenAI SDK",
		"LLM-SDK",
		regexp.MustCompile(`(?:from openai|import openai|require\(['"]openai['"]\)|@anthropic-ai/sdk|anthropic)`),
		"INFO",
		"",
		"LLM SDK detected — ensure OWASP LLM Top 10 controls are implemented",
	},
}

// RunLLMSecurityCheck scans source code for AI/LLM security issues.
func RunLLMSecurityCheck(dirPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isSourceFile(path) {
			return nil
		}

		// Skip vendor/node_modules
		rel, _ := filepath.Rel(dirPath, path)
		if strings.Contains(rel, "vendor") || strings.Contains(rel, "node_modules") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			for _, p := range llmSecurityPatterns {
				if p.Pattern.MatchString(line) {
					findings = append(findings, map[string]interface{}{
						"path":     rel,
						"line":     lineNum,
						"severity": p.Severity,
						"message":  fmt.Sprintf("[%s] %s: %s", p.ID, p.Name, p.Message),
						"cwe":      p.CWE,
						"rule_id":  p.ID,
						"tool":     "llm-security",
					})
					break
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return map[string]interface{}{"llm_security": findings}, nil
}
