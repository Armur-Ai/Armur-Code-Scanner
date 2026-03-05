package internal

import (
	"testing"
)

func TestCategorizePylintResults_Empty(t *testing.T) {
	result := CategorizePylintResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 antipatterns for empty input, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePylintResults_InvalidJSON(t *testing.T) {
	result := CategorizePylintResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 antipatterns for invalid JSON, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePylintResults_WithIssues(t *testing.T) {
	input := `[
		{
			"type": "error",
			"module": "app",
			"obj": "my_func",
			"line": 10,
			"column": 0,
			"path": "/tmp/test/app.py",
			"symbol": "undefined-variable",
			"message": "Undefined variable 'x'",
			"message-id": "E0602"
		}
	]`
	result := CategorizePylintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Errorf("expected 1 antipattern bug, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePylintResults_MultipleIssues(t *testing.T) {
	input := `[
		{"type": "warning", "line": 5, "column": 0, "path": "/tmp/test/app.py", "message": "W0001"},
		{"type": "error", "line": 10, "column": 0, "path": "/tmp/test/app.py", "message": "E0001"},
		{"type": "convention", "line": 15, "column": 0, "path": "/tmp/test/app.py", "message": "C0001"}
	]`
	result := CategorizePylintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 3 {
		t.Errorf("expected 3 antipattern bugs, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePylintResults_PathStripping(t *testing.T) {
	input := `[{"type": "error", "line": 1, "column": 0, "path": "/tmp/test/app.py", "message": "E0001"}]`
	result := CategorizePylintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
	entry := result[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	path, _ := entry["path"].(string)
	if path == "/tmp/test/app.py" {
		t.Error("expected path to be stripped of directory prefix")
	}
}
