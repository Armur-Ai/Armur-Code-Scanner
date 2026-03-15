package sandbox

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"armur-codescanner/internal/logger"
)

// DASTResult holds findings from dynamic testing.
type DASTResult struct {
	Findings    []DASTFinding `json:"findings"`
	TestedPaths int           `json:"tested_paths"`
	Duration    float64       `json:"duration_secs"`
}

// DASTFinding represents a single DAST-discovered vulnerability.
type DASTFinding struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	Parameter   string `json:"parameter,omitempty"`
	Type        string `json:"type"` // sqli, xss, cmd_injection, path_traversal, etc.
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Evidence    string `json:"evidence,omitempty"` // response snippet proving the issue
	Confirmed   bool   `json:"confirmed"`
	HTTPRequest string `json:"http_request,omitempty"`
}

// RunPassiveChecks performs passive security header and configuration checks.
func RunPassiveChecks(baseURL string) (*DASTResult, error) {
	start := time.Now()
	var findings []DASTFinding

	// Check security headers
	resp, err := http.Get(baseURL)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s: %w", baseURL, err)
	}
	defer resp.Body.Close()

	headerChecks := map[string]string{
		"Strict-Transport-Security": "Missing HSTS header — site vulnerable to SSL stripping",
		"X-Content-Type-Options":    "Missing X-Content-Type-Options — risk of MIME type sniffing",
		"X-Frame-Options":           "Missing X-Frame-Options — risk of clickjacking",
		"Content-Security-Policy":   "Missing CSP header — risk of XSS attacks",
		"Referrer-Policy":           "Missing Referrer-Policy — sensitive URLs may leak via Referer header",
		"X-XSS-Protection":         "Missing X-XSS-Protection header",
	}

	for header, message := range headerChecks {
		if resp.Header.Get(header) == "" {
			findings = append(findings, DASTFinding{
				URL:      baseURL,
				Method:   "GET",
				Type:     "missing_header",
				Severity: "MEDIUM",
				Message:  message,
			})
		}
	}

	// Check cookie security
	for _, cookie := range resp.Cookies() {
		if !cookie.HttpOnly {
			findings = append(findings, DASTFinding{
				URL:      baseURL,
				Method:   "GET",
				Type:     "insecure_cookie",
				Severity: "MEDIUM",
				Message:  fmt.Sprintf("Cookie '%s' missing HttpOnly flag — accessible to JavaScript", cookie.Name),
			})
		}
		if !cookie.Secure {
			findings = append(findings, DASTFinding{
				URL:      baseURL,
				Method:   "GET",
				Type:     "insecure_cookie",
				Severity: "LOW",
				Message:  fmt.Sprintf("Cookie '%s' missing Secure flag — sent over HTTP", cookie.Name),
			})
		}
	}

	// Check for information disclosure
	if server := resp.Header.Get("Server"); server != "" {
		findings = append(findings, DASTFinding{
			URL:      baseURL,
			Method:   "GET",
			Type:     "info_disclosure",
			Severity: "INFO",
			Message:  fmt.Sprintf("Server header discloses technology: %s", server),
			Evidence: server,
		})
	}
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		findings = append(findings, DASTFinding{
			URL:      baseURL,
			Method:   "GET",
			Type:     "info_disclosure",
			Severity: "LOW",
			Message:  fmt.Sprintf("X-Powered-By header discloses technology: %s", powered),
			Evidence: powered,
		})
	}

	// Check CORS
	if cors := resp.Header.Get("Access-Control-Allow-Origin"); cors == "*" {
		findings = append(findings, DASTFinding{
			URL:      baseURL,
			Method:   "GET",
			Type:     "cors_misconfiguration",
			Severity: "MEDIUM",
			Message:  "Wildcard CORS policy — any origin can make requests",
			Evidence: cors,
		})
	}

	return &DASTResult{
		Findings:    findings,
		TestedPaths: 1,
		Duration:    time.Since(start).Seconds(),
	}, nil
}

// RunNucleiScan runs Nuclei against the target URL.
func RunNucleiScan(baseURL string) (*DASTResult, error) {
	start := time.Now()

	cmd := exec.Command("nuclei",
		"-u", baseURL,
		"-severity", "medium,high,critical",
		"-j", // JSON output
		"-silent",
		"-timeout", "10",
		"-retries", "1",
	)

	output, err := cmd.Output()
	if err != nil {
		logger.Warn().Err(err).Msg("nuclei scan failed or not installed")
		return &DASTResult{}, nil
	}

	var findings []DASTFinding
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}

		severity := "MEDIUM"
		if s, ok := result["info"].(map[string]interface{}); ok {
			if sv, ok := s["severity"].(string); ok {
				severity = strings.ToUpper(sv)
			}
		}

		name := ""
		if info, ok := result["info"].(map[string]interface{}); ok {
			if n, ok := info["name"].(string); ok {
				name = n
			}
		}

		matchedAt := ""
		if m, ok := result["matched-at"].(string); ok {
			matchedAt = m
		}

		findings = append(findings, DASTFinding{
			URL:       matchedAt,
			Method:    "GET",
			Type:      "nuclei_finding",
			Severity:  severity,
			Message:   name,
			Confirmed: true,
		})
	}

	return &DASTResult{
		Findings:    findings,
		TestedPaths: 1,
		Duration:    time.Since(start).Seconds(),
	}, nil
}
