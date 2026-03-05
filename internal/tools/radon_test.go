package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeRadonResults_Empty(t *testing.T) {
	result := CategorizeRadonResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.COMPLEX_FUNCTIONS]) != 0 {
		t.Errorf("expected 0 complex functions for empty input, got %d", len(result[utils.COMPLEX_FUNCTIONS]))
	}
}

func TestCategorizeRadonResults_InvalidJSON(t *testing.T) {
	result := CategorizeRadonResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[utils.COMPLEX_FUNCTIONS]) != 0 {
		t.Errorf("expected 0 complex functions for invalid JSON, got %d", len(result[utils.COMPLEX_FUNCTIONS]))
	}
}

func TestCategorizeRadonResults_WithComplexity(t *testing.T) {
	input := `{
		"/tmp/test/app.py": [
			{
				"name": "complex_function",
				"complexity": 15,
				"rank": "C",
				"lineno": 10,
				"col_offset": 0
			}
		]
	}`
	result := CategorizeRadonResults(input, "/tmp/test")
	if len(result[utils.COMPLEX_FUNCTIONS]) != 1 {
		t.Errorf("expected 1 complex function, got %d", len(result[utils.COMPLEX_FUNCTIONS]))
	}
	entry := result[utils.COMPLEX_FUNCTIONS][0].(map[string]interface{})
	if entry["path"] != "/app.py" {
		t.Errorf("expected path /app.py, got %v", entry["path"])
	}
}

func TestCategorizeRadonResults_MultipleFiles(t *testing.T) {
	input := `{
		"/tmp/test/a.py": [
			{"name": "func_a", "complexity": 10, "rank": "B", "lineno": 1, "col_offset": 0}
		],
		"/tmp/test/b.py": [
			{"name": "func_b", "complexity": 20, "rank": "D", "lineno": 5, "col_offset": 0},
			{"name": "func_c", "complexity": 8, "rank": "B", "lineno": 15, "col_offset": 0}
		]
	}`
	result := CategorizeRadonResults(input, "/tmp/test")
	if len(result[utils.COMPLEX_FUNCTIONS]) != 3 {
		t.Errorf("expected 3 complex functions across 2 files, got %d", len(result[utils.COMPLEX_FUNCTIONS]))
	}
}
