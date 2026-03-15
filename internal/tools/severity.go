package internal

import (
	"armur-codescanner/internal/models"
	"strconv"
	"strings"
)

// NormalizeSeverity converts a raw severity string from any tool to the canonical Severity enum.
func NormalizeSeverity(tool, raw string) models.Severity {
	upper := strings.ToUpper(strings.TrimSpace(raw))

	// Tool-specific normalization
	switch tool {
	case "semgrep":
		return normalizeSemgrep(upper)
	case "eslint":
		return normalizeESLint(raw)
	case "trufflehog", "trufflehog3":
		return models.SeverityCritical // credentials are always critical
	case "gocyclo", "radon":
		return normalizeComplexity(raw)
	case "checkov":
		return normalizeCheckov(upper)
	case "osv-scanner":
		return normalizeOSV(raw)
	}

	// Generic normalization — works for gosec, bandit, trivy, and most tools
	switch upper {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH", "ERROR", "SEVERE":
		return models.SeverityHigh
	case "MEDIUM", "WARNING", "MODERATE":
		return models.SeverityMedium
	case "LOW", "MINOR":
		return models.SeverityLow
	case "INFO", "INFORMATIONAL", "NOTE", "STYLE":
		return models.SeverityInfo
	default:
		return models.SeverityInfo
	}
}

func normalizeSemgrep(upper string) models.Severity {
	switch upper {
	case "ERROR":
		return models.SeverityHigh
	case "WARNING":
		return models.SeverityMedium
	case "INFO":
		return models.SeverityInfo
	default:
		return models.SeverityInfo
	}
}

func normalizeESLint(raw string) models.Severity {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		// Try string-based
		switch strings.ToUpper(raw) {
		case "ERROR":
			return models.SeverityHigh
		case "WARNING", "WARN":
			return models.SeverityMedium
		default:
			return models.SeverityInfo
		}
	}
	switch n {
	case 2:
		return models.SeverityHigh
	case 1:
		return models.SeverityMedium
	default:
		return models.SeverityInfo
	}
}

func normalizeComplexity(raw string) models.Severity {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return models.SeverityMedium
	}
	if n > 20 {
		return models.SeverityHigh
	}
	if n > 10 {
		return models.SeverityMedium
	}
	return models.SeverityLow
}

func normalizeCheckov(upper string) models.Severity {
	switch upper {
	case "FAILED", "FAIL":
		return models.SeverityMedium
	case "PASSED", "PASS":
		return models.SeverityInfo
	default:
		return models.SeverityMedium
	}
}

func normalizeOSV(raw string) models.Severity {
	// Try to parse as CVSS score
	score, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		// Fall back to string-based
		return NormalizeSeverity("", raw)
	}
	if score >= 9.0 {
		return models.SeverityCritical
	}
	if score >= 7.0 {
		return models.SeverityHigh
	}
	if score >= 4.0 {
		return models.SeverityMedium
	}
	return models.SeverityLow
}
