package internal

import (
	"testing"
)

func TestCategorizeSemgrepResults_Empty(t *testing.T) {
	result := CategorizeSemgrepResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
}

func TestCategorizeSemgrepResults_InvalidJSON(t *testing.T) {
	result := CategorizeSemgrepResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues for invalid JSON, got %d", len(result[SECURITY_ISSUES]))
	}
}

func TestCategorizeSemgrepResults_SecurityResult(t *testing.T) {
	input := `{
		"results": [
			{
				"check_id": "python.security.audit.sqli",
				"path": "/tmp/test/app.py",
				"start": {"line": 5, "col": 1},
				"end": {"line": 5, "col": 30},
				"extra": {
					"message": "SQL injection detected",
					"severity": "ERROR",
					"metadata": {
						"confidence": "HIGH",
						"likelihood": "HIGH",
						"cwe": ["CWE-89"],
						"owasp": ["A03:2021"]
					}
				}
			}
		]
	}`

	result := CategorizeSemgrepResults(input, "/tmp/test")
	if len(result[SECURITY_ISSUES]) != 1 {
		t.Errorf("expected 1 security issue, got %d", len(result[SECURITY_ISSUES]))
	}
}

func TestCategorizeSemgrepResults_AntipatternResult(t *testing.T) {
	input := `{
		"results": [
			{
				"check_id": "generic.best-practice.use-of-eval",
				"path": "/tmp/test/app.py",
				"start": {"line": 10, "col": 1},
				"end": {"line": 10, "col": 20},
				"extra": {
					"message": "Use of eval is dangerous",
					"severity": "WARNING",
					"metadata": {}
				}
			}
		]
	}`

	result := CategorizeSemgrepResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Errorf("expected 1 antipattern, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestFormatSeverity(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"INFO", "LOW"},
		{"WARNING", "MEDIUM"},
		{"ERROR", "HIGH"},
		{"CRITICAL", "CRITICAL"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			result := map[string]interface{}{
				"extra": map[string]interface{}{
					"severity": tt.severity,
				},
			}
			got := formatSeverity(result)
			if got != tt.expected {
				t.Errorf("formatSeverity(%q) = %q, want %q", tt.severity, got, tt.expected)
			}
		})
	}
}
