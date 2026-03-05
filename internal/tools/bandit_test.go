package internal

import (
	"testing"
)

func TestCategorizeBanditResults_Empty(t *testing.T) {
	result := CategorizeBanditResults("")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 security issues for empty input, got %d", len(result[SECURITY_ISSUES]))
	}
}

func TestCategorizeBanditResults_WithIssues(t *testing.T) {
	input := `{
		"results": [
			{
				"filename": "/tmp/test/app.py",
				"line_number": 10,
				"issue_text": "Use of MD5 is insecure",
				"issue_severity": "high",
				"test_id": "B324",
				"issue_confidence": "high"
			}
		]
	}`

	result := CategorizeBanditResults(input)
	if len(result[SECURITY_ISSUES]) != 1 {
		t.Errorf("expected 1 security issue, got %d", len(result[SECURITY_ISSUES]))
	}

	issue := result[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", issue["severity"])
	}
	if issue["line"] != 10 {
		t.Errorf("expected line 10, got %v", issue["line"])
	}
}

func TestCategorizeBanditResults_InvalidJSON(t *testing.T) {
	result := CategorizeBanditResults("{not valid json")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues for invalid JSON, got %d", len(result[SECURITY_ISSUES]))
	}
}

func TestCategorizeBanditResults_MultipleIssues(t *testing.T) {
	input := `{
		"results": [
			{
				"filename": "/tmp/test/a.py",
				"line_number": 1,
				"issue_text": "issue 1",
				"issue_severity": "medium",
				"test_id": "B101",
				"issue_confidence": "high"
			},
			{
				"filename": "/tmp/test/b.py",
				"line_number": 20,
				"issue_text": "issue 2",
				"issue_severity": "low",
				"test_id": "B102",
				"issue_confidence": "medium"
			}
		]
	}`

	result := CategorizeBanditResults(input)
	if len(result[SECURITY_ISSUES]) != 2 {
		t.Errorf("expected 2 security issues, got %d", len(result[SECURITY_ISSUES]))
	}
}
