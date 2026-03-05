package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeCheckovResults_Empty(t *testing.T) {
	result := categorizeCheckovResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.INFRA_SECURITY]) != 0 {
		t.Errorf("expected 0 infra security entries for empty input, got %d", len(result[utils.INFRA_SECURITY]))
	}
}

func TestCategorizeCheckovResults_InvalidJSON(t *testing.T) {
	result := categorizeCheckovResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[utils.INFRA_SECURITY]) != 0 {
		t.Errorf("expected 0 infra security entries for invalid JSON, got %d", len(result[utils.INFRA_SECURITY]))
	}
}

func TestCategorizeCheckovResults_MapWithFailedChecks(t *testing.T) {
	input := `{
		"results": {
			"failed_checks": [
				{
					"check_id": "CKV_AWS_1",
					"check_name": "Ensure S3 bucket has versioning enabled",
					"file_path": "/tmp/test/main.tf",
					"file_line_range": [1, 10],
					"severity": "HIGH"
				}
			]
		}
	}`
	result := categorizeCheckovResults(input, "/tmp/test")
	if len(result[utils.INFRA_SECURITY]) != 1 {
		t.Errorf("expected 1 infra security entry, got %d", len(result[utils.INFRA_SECURITY]))
	}
}

func TestCategorizeCheckovResults_ArrayWithFailedChecks(t *testing.T) {
	input := `[
		{
			"results": {
				"failed_checks": [
					{
						"check_id": "CKV_AWS_2",
						"check_name": "Ensure S3 bucket logging is enabled",
						"file_path": "/tmp/test/main.tf",
						"file_line_range": [5, 15],
						"severity": "MEDIUM"
					}
				]
			}
		}
	]`
	result := categorizeCheckovResults(input, "/tmp/test")
	if len(result[utils.INFRA_SECURITY]) != 1 {
		t.Errorf("expected 1 infra security entry from array, got %d", len(result[utils.INFRA_SECURITY]))
	}
}

func TestFormatCheckovIssue_WithLineRange(t *testing.T) {
	issue := map[string]interface{}{
		"check_id":        "CKV_AWS_1",
		"check_name":      "Ensure versioning",
		"file_path":       "/tmp/test/main.tf",
		"file_line_range": []interface{}{float64(1), float64(10)},
		"severity":        "HIGH",
	}
	result := formatCheckovIssue(issue, "/tmp/test")
	if result["check_id"] != "CKV_AWS_1" {
		t.Errorf("expected check_id CKV_AWS_1, got %v", result["check_id"])
	}
	if result["file_line_range"] != "1:10" {
		t.Errorf("expected file_line_range 1:10, got %v", result["file_line_range"])
	}
}
