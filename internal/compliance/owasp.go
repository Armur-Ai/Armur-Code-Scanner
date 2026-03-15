package compliance

import (
	"armur-codescanner/internal/models"
	"fmt"
	"strings"
)

// OWASPCategory represents an OWASP Top 10 2021 category.
type OWASPCategory struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	FindingCount int   `json:"finding_count"`
	Status      string `json:"status"` // "pass", "fail", "not_applicable"
}

// OWASPTop10 is the full OWASP Top 10 2021 list.
var OWASPTop10 = []OWASPCategory{
	{ID: "A01:2021", Name: "Broken Access Control", Description: "Failures related to access control enforcement"},
	{ID: "A02:2021", Name: "Cryptographic Failures", Description: "Failures related to cryptography that lead to exposure of sensitive data"},
	{ID: "A03:2021", Name: "Injection", Description: "SQL, NoSQL, OS, LDAP injection flaws"},
	{ID: "A04:2021", Name: "Insecure Design", Description: "Design flaws and missing security controls"},
	{ID: "A05:2021", Name: "Security Misconfiguration", Description: "Missing security hardening, default configurations"},
	{ID: "A06:2021", Name: "Vulnerable and Outdated Components", Description: "Using components with known vulnerabilities"},
	{ID: "A07:2021", Name: "Identification and Authentication Failures", Description: "Authentication and session management flaws"},
	{ID: "A08:2021", Name: "Software and Data Integrity Failures", Description: "Code and infrastructure that does not protect against integrity violations"},
	{ID: "A09:2021", Name: "Security Logging and Monitoring Failures", Description: "Insufficient logging, detection, monitoring"},
	{ID: "A10:2021", Name: "Server-Side Request Forgery (SSRF)", Description: "SSRF flaws occur when a web app fetches a remote resource without validating the user-supplied URL"},
}

// CWEToOWASP maps CWE IDs to OWASP Top 10 2021 categories.
var CWEToOWASP = map[string]string{
	"CWE-22":  "A01:2021", // Path Traversal → Broken Access Control
	"CWE-284": "A01:2021", // Improper Access Control
	"CWE-285": "A01:2021", // Improper Authorization
	"CWE-352": "A01:2021", // CSRF
	"CWE-639": "A01:2021", // IDOR

	"CWE-261": "A02:2021", // Weak Encoding for Password
	"CWE-296": "A02:2021", // Improper Following of Chain of Trust
	"CWE-310": "A02:2021", // Cryptographic Issues
	"CWE-319": "A02:2021", // Cleartext Transmission
	"CWE-321": "A02:2021", // Hardcoded Cryptographic Key
	"CWE-327": "A02:2021", // Use of Broken Crypto
	"CWE-328": "A02:2021", // Reversible One-Way Hash
	"CWE-330": "A02:2021", // Insufficient Randomness

	"CWE-77":  "A03:2021", // Command Injection
	"CWE-78":  "A03:2021", // OS Command Injection
	"CWE-79":  "A03:2021", // XSS
	"CWE-89":  "A03:2021", // SQL Injection
	"CWE-94":  "A03:2021", // Code Injection
	"CWE-917": "A03:2021", // Expression Language Injection

	"CWE-209": "A04:2021", // Error Message Information Leak
	"CWE-256": "A04:2021", // Plaintext Storage of Password

	"CWE-2":   "A05:2021", // Missing Security Configuration
	"CWE-16":  "A05:2021", // Configuration
	"CWE-611": "A05:2021", // XXE

	"CWE-1104": "A06:2021", // Use of Unmaintained Third-Party Components

	"CWE-287": "A07:2021", // Improper Authentication
	"CWE-306": "A07:2021", // Missing Authentication
	"CWE-384": "A07:2021", // Session Fixation
	"CWE-798": "A07:2021", // Hardcoded Credentials

	"CWE-345": "A08:2021", // Insufficient Verification of Data Authenticity
	"CWE-502": "A08:2021", // Deserialization of Untrusted Data

	"CWE-117": "A09:2021", // Log Injection
	"CWE-223": "A09:2021", // Omission of Security-relevant Information
	"CWE-778": "A09:2021", // Insufficient Logging

	"CWE-918": "A10:2021", // SSRF
}

// MapFindings maps a list of findings to OWASP Top 10 categories and returns the compliance report.
func MapFindings(findings []models.Finding) []OWASPCategory {
	// Clone the categories
	report := make([]OWASPCategory, len(OWASPTop10))
	copy(report, OWASPTop10)

	for _, f := range findings {
		if f.CWE == "" {
			continue
		}
		cwe := strings.ToUpper(f.CWE)
		if !strings.HasPrefix(cwe, "CWE-") {
			cwe = "CWE-" + cwe
		}

		if owaspID, ok := CWEToOWASP[cwe]; ok {
			for i := range report {
				if report[i].ID == owaspID {
					report[i].FindingCount++
					break
				}
			}
		}
	}

	// Set status
	for i := range report {
		if report[i].FindingCount > 0 {
			report[i].Status = "fail"
		} else {
			report[i].Status = "pass"
		}
	}

	return report
}

// FormatOWASPReport generates a text report from the OWASP mapping.
func FormatOWASPReport(report []OWASPCategory) string {
	var b strings.Builder
	b.WriteString("OWASP Top 10 2021 — Compliance Report\n")
	b.WriteString(strings.Repeat("═", 70) + "\n\n")

	for _, cat := range report {
		icon := "✓"
		if cat.Status == "fail" {
			icon = "✗"
		}
		b.WriteString(fmt.Sprintf("%s  %-12s  %-40s  %d findings\n",
			icon, cat.ID, cat.Name, cat.FindingCount))
	}

	return b.String()
}
