package internal

import (
	"armur-codescanner/internal/models"
	"testing"
)

func TestNormalizeSeverityGeneric(t *testing.T) {
	tests := []struct {
		tool, raw string
		want      models.Severity
	}{
		{"gosec", "HIGH", models.SeverityHigh},
		{"gosec", "MEDIUM", models.SeverityMedium},
		{"gosec", "LOW", models.SeverityLow},
		{"bandit", "HIGH", models.SeverityHigh},
		{"trivy", "CRITICAL", models.SeverityCritical},
		{"trivy", "UNKNOWN", models.SeverityInfo},
		{"", "WARNING", models.SeverityMedium},
		{"", "ERROR", models.SeverityHigh},
		{"", "SEVERE", models.SeverityHigh},
		{"", "MINOR", models.SeverityLow},
		{"", "nonsense", models.SeverityInfo},
	}

	for _, tt := range tests {
		got := NormalizeSeverity(tt.tool, tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(%q, %q) = %q, want %q", tt.tool, tt.raw, got, tt.want)
		}
	}
}

func TestNormalizeSemgrep(t *testing.T) {
	tests := []struct {
		raw  string
		want models.Severity
	}{
		{"ERROR", models.SeverityHigh},
		{"WARNING", models.SeverityMedium},
		{"INFO", models.SeverityInfo},
	}

	for _, tt := range tests {
		got := NormalizeSeverity("semgrep", tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(semgrep, %q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestNormalizeESLint(t *testing.T) {
	tests := []struct {
		raw  string
		want models.Severity
	}{
		{"2", models.SeverityHigh},
		{"1", models.SeverityMedium},
		{"0", models.SeverityInfo},
		{"error", models.SeverityHigh},
		{"warn", models.SeverityMedium},
	}

	for _, tt := range tests {
		got := NormalizeSeverity("eslint", tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(eslint, %q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestNormalizeTrufflehog(t *testing.T) {
	// Trufflehog findings are always critical (credentials)
	got := NormalizeSeverity("trufflehog", "anything")
	if got != models.SeverityCritical {
		t.Errorf("trufflehog should always be CRITICAL, got %q", got)
	}
}

func TestNormalizeComplexity(t *testing.T) {
	tests := []struct {
		raw  string
		want models.Severity
	}{
		{"25", models.SeverityHigh},
		{"15", models.SeverityMedium},
		{"5", models.SeverityLow},
	}

	for _, tt := range tests {
		got := NormalizeSeverity("gocyclo", tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(gocyclo, %q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestNormalizeOSV(t *testing.T) {
	tests := []struct {
		raw  string
		want models.Severity
	}{
		{"9.8", models.SeverityCritical},
		{"7.5", models.SeverityHigh},
		{"5.0", models.SeverityMedium},
		{"2.0", models.SeverityLow},
	}

	for _, tt := range tests {
		got := NormalizeSeverity("osv-scanner", tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(osv-scanner, %q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}

func TestNormalizeCheckov(t *testing.T) {
	tests := []struct {
		raw  string
		want models.Severity
	}{
		{"FAILED", models.SeverityMedium},
		{"PASSED", models.SeverityInfo},
	}

	for _, tt := range tests {
		got := NormalizeSeverity("checkov", tt.raw)
		if got != tt.want {
			t.Errorf("NormalizeSeverity(checkov, %q) = %q, want %q", tt.raw, got, tt.want)
		}
	}
}
