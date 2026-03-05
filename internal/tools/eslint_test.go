package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeESLintResults_Empty(t *testing.T) {
	result := CategorizeESLintResults([]map[string]interface{}{}, "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 antipatterns for empty input, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeESLintResults_AntipatternRule(t *testing.T) {
	input := []map[string]interface{}{
		{
			"filePath": "/tmp/test/index.js",
			"messages": []interface{}{
				map[string]interface{}{
					"ruleId":  "no-console",
					"line":    float64(5),
					"message": "Unexpected console statement",
				},
			},
		},
	}
	result := CategorizeESLintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Errorf("expected 1 antipattern, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeESLintResults_SkipsMissingRuleID(t *testing.T) {
	input := []map[string]interface{}{
		{
			"filePath": "/tmp/test/index.js",
			"messages": []interface{}{
				map[string]interface{}{
					"line":    float64(1),
					"message": "Parsing error",
				},
			},
		},
	}
	result := CategorizeESLintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 antipatterns for missing ruleId, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeESLintAdvancedResults_Empty(t *testing.T) {
	result := CategorizeESLintAdvancedResults([]map[string]interface{}{}, "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.DEAD_CODE]) != 0 {
		t.Errorf("expected 0 dead code entries for empty input, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeESLintAdvancedResults_NoUnusedVars(t *testing.T) {
	input := []map[string]interface{}{
		{
			"filePath": "/tmp/test/index.js",
			"messages": []interface{}{
				map[string]interface{}{
					"ruleId":  "no-unused-vars",
					"line":    float64(3),
					"message": "'x' is assigned a value but never used",
				},
			},
		},
	}
	result := CategorizeESLintAdvancedResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 1 {
		t.Errorf("expected 1 dead code entry for no-unused-vars, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestContains(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if !contains(slice, "b") {
		t.Error("contains should return true for existing element")
	}
	if contains(slice, "d") {
		t.Error("contains should return false for missing element")
	}
}

func TestFormatIssues_Basic(t *testing.T) {
	issues := []map[string]interface{}{
		{
			"filePath": "/tmp/test/index.js",
			"messages": []interface{}{
				map[string]interface{}{
					"line":    float64(1),
					"column":  float64(2),
					"message": "test message",
					"ruleId":  "some-rule",
				},
			},
		},
	}
	result := FormatIssues(issues, "/tmp/test")
	if len(result) != 1 {
		t.Errorf("expected 1 formatted issue, got %d", len(result))
	}
}
