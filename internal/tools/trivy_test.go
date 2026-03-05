package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeTrivyResults_Empty(t *testing.T) {
	result := categorizeTrivyResults("")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
}

func TestCategorizeTrivyResults_InvalidJSON(t *testing.T) {
	result := categorizeTrivyResults("{bad json}")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[utils.INFRA_SECURITY]) != 0 {
		t.Errorf("expected 0 infra security entries for invalid JSON, got %d", len(result[utils.INFRA_SECURITY]))
	}
}

func TestCategorizeTrivyResults_WithHighSeverityVuln(t *testing.T) {
	input := `{
		"Results": [
			{
				"Target": "go.sum",
				"Class": "lang-pkgs",
				"Type": "gomod",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-0001",
						"PkgName": "example.com/vulnerable",
						"InstalledVersion": "1.0.0",
						"FixedVersion": "1.0.1",
						"Severity": "HIGH",
						"Title": "Remote code execution",
						"CweIDs": ["CWE-79"]
					}
				]
			}
		]
	}`
	result := categorizeTrivyResults(input)
	if len(result[utils.INFRA_SECURITY]) != 1 {
		t.Errorf("expected 1 infra security entry for HIGH vuln, got %d", len(result[utils.INFRA_SECURITY]))
	}
	entry := result[utils.INFRA_SECURITY][0].(map[string]interface{})
	if entry["check_id"] != "CVE-2023-0001" {
		t.Errorf("expected CVE ID, got %v", entry["check_id"])
	}
}

func TestCategorizeTrivyResults_SecretInTitle(t *testing.T) {
	input := `{
		"Results": [
			{
				"Target": "config.yaml",
				"Class": "secret",
				"Type": "secrets",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "SECRET-001",
						"PkgName": "config",
						"InstalledVersion": "1.0.0",
						"FixedVersion": "",
						"Severity": "HIGH",
						"Title": "Exposed secret token found"
					}
				]
			}
		]
	}`
	result := categorizeTrivyResults(input)
	if len(result[utils.SECRET_DETECTION]) != 1 {
		t.Errorf("expected 1 secret detection entry, got %d", len(result[utils.SECRET_DETECTION]))
	}
}

func TestCategorizeTrivyResults_NoVulnerabilities(t *testing.T) {
	input := `{"Results": []}`
	result := categorizeTrivyResults(input)
	if len(result[utils.INFRA_SECURITY]) != 0 {
		t.Errorf("expected 0 infra security entries, got %d", len(result[utils.INFRA_SECURITY]))
	}
}

func TestIsSeverityHigh(t *testing.T) {
	tests := []struct {
		severity string
		expected bool
	}{
		{"CRITICAL", true},
		{"HIGH", true},
		{"MEDIUM", true},
		{"LOW", true},
		{"critical", true},
		{"high", true},
		{"UNKNOWN", false},
		{"", false},
		{"INFORMATIONAL", false},
	}
	for _, tt := range tests {
		got := isSeverityHigh(tt.severity)
		if got != tt.expected {
			t.Errorf("isSeverityHigh(%q) = %v, want %v", tt.severity, got, tt.expected)
		}
	}
}
