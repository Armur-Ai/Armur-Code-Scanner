package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeOSVResults_Empty(t *testing.T) {
	result := categorizeOSVResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.SCA]) != 0 {
		t.Errorf("expected 0 SCA entries for empty input, got %d", len(result[utils.SCA]))
	}
}

func TestCategorizeOSVResults_InvalidJSON(t *testing.T) {
	result := categorizeOSVResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[utils.SCA]) != 0 {
		t.Errorf("expected 0 SCA entries for invalid JSON, got %d", len(result[utils.SCA]))
	}
}

func TestCategorizeOSVResults_WithVulnerability(t *testing.T) {
	input := `{
		"results": [
			{
				"source": {"path": "/tmp/test/go.sum"},
				"packages": [
					{
						"package": {"name": "example.com/pkg", "version": "1.0.0"},
						"vulnerabilities": [
							{
								"id": "GHSA-xxxx-xxxx-xxxx",
								"summary": "Remote code execution in example package",
								"severity": "HIGH"
							}
						]
					}
				]
			}
		]
	}`
	result := categorizeOSVResults(input, "/tmp/test")
	if len(result[utils.SCA]) != 1 {
		t.Errorf("expected 1 SCA entry, got %d", len(result[utils.SCA]))
	}
	entry := result[utils.SCA][0].(map[string]interface{})
	if entry["package"] != "example.com/pkg" {
		t.Errorf("expected package name, got %v", entry["package"])
	}
	if entry["check_id"] != "GHSA-xxxx-xxxx-xxxx" {
		t.Errorf("expected check_id, got %v", entry["check_id"])
	}
}

func TestCategorizeOSVResults_SeverityArray(t *testing.T) {
	input := `{
		"results": [
			{
				"source": {"path": "/tmp/test/go.sum"},
				"packages": [
					{
						"package": {"name": "pkg", "version": "0.1.0"},
						"vulnerabilities": [
							{
								"id": "CVE-2023-0001",
								"summary": "test vuln",
								"severity": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
							}
						]
					}
				]
			}
		]
	}`
	result := categorizeOSVResults(input, "/tmp/test")
	if len(result[utils.SCA]) != 1 {
		t.Errorf("expected 1 SCA entry, got %d", len(result[utils.SCA]))
	}
}

func TestCategorizeOSVResults_NoVulnerabilities(t *testing.T) {
	input := `{"results": []}`
	result := categorizeOSVResults(input, "/tmp/test")
	if len(result[utils.SCA]) != 0 {
		t.Errorf("expected 0 SCA entries for empty results, got %d", len(result[utils.SCA]))
	}
}
