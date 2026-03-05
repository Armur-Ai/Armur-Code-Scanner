package internal

import (
	"testing"
)

func TestCategorizeGosecResults_Empty(t *testing.T) {
	result := CategorizeGosecResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 security issues for empty input, got %d", len(result[SECURITY_ISSUES]))
	}
}

func TestCategorizeGosecResults_WithIssues(t *testing.T) {
	input := `{
		"Issues": [
			{
				"file": "/tmp/test/main.go",
				"line": "10",
				"column": "5",
				"details": "Potential SQL injection",
				"severity": "HIGH",
				"rule_id": "G201",
				"confidence": "MEDIUM",
				"cwe": {"id": "89", "url": "https://cwe.mitre.org/data/definitions/89.html"}
			}
		],
		"Golang errors": {},
		"Stats": {}
	}`

	result := CategorizeGosecResults(input, "/tmp/test")
	if len(result[SECURITY_ISSUES]) != 1 {
		t.Errorf("expected 1 security issue, got %d", len(result[SECURITY_ISSUES]))
	}

	issue := result[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", issue["severity"])
	}
}

func TestCategorizeGosecResults_InvalidJSON(t *testing.T) {
	result := CategorizeGosecResults("{invalid json", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	// Should return empty categorized results, not panic
	if len(result[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues for invalid JSON, got %d", len(result[SECURITY_ISSUES]))
	}
}

func TestCategorizeGosecResults_GolangErrors(t *testing.T) {
	input := `{
		"Issues": [],
		"Golang errors": {
			"/tmp/test/main.go": [
				{"line": "5", "column": "1", "error": "undefined: someFunc"}
			]
		}
	}`

	result := CategorizeGosecResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Errorf("expected 1 antipattern bug from Golang error, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}
