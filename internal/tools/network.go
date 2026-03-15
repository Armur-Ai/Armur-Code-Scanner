package internal

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Network/protocol configuration security patterns.
var networkPatterns = []struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	CWE      string
	Message  string
	Files    []string // file patterns to check
}{
	// Nginx
	{"Nginx SSL Off", regexp.MustCompile(`(?i)ssl\s+off`), "HIGH", "CWE-319", "SSL disabled in Nginx config", []string{"nginx.conf", "*.conf"}},
	{"Nginx Server Tokens", regexp.MustCompile(`(?i)server_tokens\s+on`), "LOW", "CWE-200", "Nginx version disclosure enabled", []string{"nginx.conf", "*.conf"}},
	{"Nginx Autoindex", regexp.MustCompile(`(?i)autoindex\s+on`), "MEDIUM", "CWE-548", "Directory listing enabled", []string{"nginx.conf", "*.conf"}},

	// Apache
	{"Apache ServerSignature", regexp.MustCompile(`(?i)ServerSignature\s+On`), "LOW", "CWE-200", "Apache version disclosure enabled", []string{"httpd.conf", ".htaccess", "apache2.conf"}},
	{"Apache Directory Listing", regexp.MustCompile(`(?i)Options.*Indexes`), "MEDIUM", "CWE-548", "Directory listing enabled", []string{"httpd.conf", ".htaccess"}},

	// Kubernetes Ingress
	{"K8s Ingress No TLS", regexp.MustCompile(`(?i)kind:\s*Ingress`), "MEDIUM", "CWE-319", "Kubernetes Ingress may lack TLS — check for tls: section", []string{"*.yaml", "*.yml"}},

	// General
	{"HTTP (not HTTPS)", regexp.MustCompile(`http://[^l][^o][^c]`), "MEDIUM", "CWE-319", "HTTP URL (non-localhost) — should use HTTPS", []string{"*.yaml", "*.yml", "*.json", "*.toml", "*.env"}},
	{"Bind to 0.0.0.0", regexp.MustCompile(`(?:listen|bind|host)\s*[:=]\s*["']?0\.0\.0\.0`), "LOW", "CWE-284", "Service bound to all interfaces — consider restricting to localhost", []string{"*"}},
	{"Debug Mode", regexp.MustCompile(`(?i)(?:DEBUG|debug_mode|debug)\s*[:=]\s*(?:true|1|"true"|'true')`), "MEDIUM", "CWE-489", "Debug mode enabled — disable in production", []string{"*.yaml", "*.yml", "*.json", "*.toml", "*.env", "*.conf"}},
}

// RunNetworkConfigCheck scans configuration files for network security issues.
func RunNetworkConfigCheck(dirPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Skip common non-config dirs
		base := filepath.Base(filepath.Dir(path))
		if base == "node_modules" || base == "vendor" || base == ".git" {
			return filepath.SkipDir
		}

		rel, _ := filepath.Rel(dirPath, path)
		name := filepath.Base(path)

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

			for _, p := range networkPatterns {
				if !matchesFilePattern(name, p.Files) {
					continue
				}
				if p.Pattern.MatchString(line) {
					// Skip comments
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
						continue
					}

					findings = append(findings, map[string]interface{}{
						"path":     rel,
						"line":     lineNum,
						"severity": p.Severity,
						"message":  fmt.Sprintf("%s: %s", p.Name, p.Message),
						"cwe":      p.CWE,
						"tool":     "network-config-check",
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

	return map[string]interface{}{"network_security": findings}, nil
}

func matchesFilePattern(filename string, patterns []string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		matched, _ := filepath.Match(p, filename)
		if matched {
			return true
		}
	}
	return false
}
