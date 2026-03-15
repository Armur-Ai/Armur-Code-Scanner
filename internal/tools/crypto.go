package internal

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Weak crypto patterns across languages.
var weakCryptoPatterns = []struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	CWE      string
	Message  string
}{
	// Weak algorithms
	{"MD5", regexp.MustCompile(`(?i)\b(?:md5|MD5)\s*[\.(]`), "HIGH", "CWE-327", "MD5 is cryptographically broken — use SHA-256 or SHA-3"},
	{"SHA1", regexp.MustCompile(`(?i)\b(?:sha1|SHA1)\s*[\.(]`), "HIGH", "CWE-327", "SHA-1 is deprecated — use SHA-256 or SHA-3"},
	{"DES/3DES", regexp.MustCompile(`(?i)\b(?:DES|3DES|TripleDES|DESede)\b`), "HIGH", "CWE-327", "DES/3DES is deprecated — use AES-256"},
	{"RC4", regexp.MustCompile(`(?i)\bRC4\b`), "HIGH", "CWE-327", "RC4 is broken — use AES-GCM"},
	{"Blowfish", regexp.MustCompile(`(?i)\bBlowfish\b`), "MEDIUM", "CWE-327", "Blowfish has a 64-bit block size — use AES-256"},

	// Weak key sizes
	{"RSA < 2048", regexp.MustCompile(`(?:rsa|RSA).*(?:1024|512)\b`), "HIGH", "CWE-326", "RSA key size < 2048 bits is insecure — use 2048+ or switch to Ed25519"},
	{"AES-128", regexp.MustCompile(`(?i)AES.*128`), "LOW", "CWE-326", "AES-128 is acceptable but AES-256 is recommended for post-quantum readiness"},

	// Insecure modes
	{"ECB Mode", regexp.MustCompile(`(?i)\bECB\b`), "HIGH", "CWE-327", "ECB mode leaks patterns — use CBC, CTR, or GCM"},

	// Hardcoded keys/IVs
	{"Hardcoded IV", regexp.MustCompile(`(?i)(?:iv|nonce)\s*[:=]\s*(?:[\[{]|"[0-9a-fA-F])`), "HIGH", "CWE-329", "Initialization vector should be randomly generated, not hardcoded"},

	// TLS/SSL
	{"SSLv3", regexp.MustCompile(`(?i)\b(?:SSLv3|SSL_v3|sslv3)\b`), "CRITICAL", "CWE-326", "SSLv3 is broken (POODLE) — use TLS 1.2+"},
	{"TLS 1.0", regexp.MustCompile(`(?i)\b(?:TLS_?1[._]0|TLSv1[._]0|tls10)\b`), "HIGH", "CWE-326", "TLS 1.0 is deprecated — use TLS 1.2+"},
	{"TLS 1.1", regexp.MustCompile(`(?i)\b(?:TLS_?1[._]1|TLSv1[._]1|tls11)\b`), "MEDIUM", "CWE-326", "TLS 1.1 is deprecated — use TLS 1.2+"},

	// Insecure random
	{"math/rand", regexp.MustCompile(`(?:math/rand|random\.random|Math\.random)`), "MEDIUM", "CWE-330", "Non-cryptographic random — use crypto/rand for security-sensitive operations"},
}

// RunCryptoHealthCheck scans source code for weak cryptographic patterns.
func RunCryptoHealthCheck(dirPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isSourceFile(path) {
			return nil
		}

		rel, _ := filepath.Rel(dirPath, path)
		if isTestPath(rel) {
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

			// Skip comments
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}

			for _, pattern := range weakCryptoPatterns {
				if pattern.Pattern.MatchString(line) {
					findings = append(findings, map[string]interface{}{
						"path":     rel,
						"line":     lineNum,
						"severity": pattern.Severity,
						"message":  fmt.Sprintf("%s: %s", pattern.Name, pattern.Message),
						"cwe":      pattern.CWE,
						"tool":     "crypto-check",
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

	return map[string]interface{}{"crypto_health": findings}, nil
}
