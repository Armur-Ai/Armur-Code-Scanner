package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeVultureResults_Empty(t *testing.T) {
	result := categorizeVultureResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.DEAD_CODE]) != 0 {
		t.Errorf("expected 0 dead code entries for empty input, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeVultureResults_WithIssues(t *testing.T) {
	input := `/tmp/test/app.py:10: unused function 'foo' (60% confidence)`
	result := categorizeVultureResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 1 {
		t.Errorf("expected 1 dead code entry, got %d", len(result[utils.DEAD_CODE]))
	}
	entry := result[utils.DEAD_CODE][0].(map[string]interface{})
	if entry["line"] != "10" {
		t.Errorf("expected line 10, got %v", entry["line"])
	}
}

func TestCategorizeVultureResults_MultipleIssues(t *testing.T) {
	input := `/tmp/test/a.py:5: unused variable 'x' (100% confidence)
/tmp/test/b.py:15: unused function 'bar' (60% confidence)
/tmp/test/c.py:25: unused import 'os' (100% confidence)`
	result := categorizeVultureResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 3 {
		t.Errorf("expected 3 dead code entries, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeVultureResults_SkipsEmptyLines(t *testing.T) {
	input := `/tmp/test/a.py:5: unused variable 'x' (100% confidence)

/tmp/test/b.py:10: unused function 'y' (100% confidence)`
	result := categorizeVultureResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 2 {
		t.Errorf("expected 2 dead code entries (empty line skipped), got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeVultureResults_PathStripping(t *testing.T) {
	input := `/tmp/test/app.py:1: unused function 'unused' (100% confidence)`
	result := categorizeVultureResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result[utils.DEAD_CODE]))
	}
	entry := result[utils.DEAD_CODE][0].(map[string]interface{})
	if entry["file"] == "/tmp/test/app.py" {
		t.Error("expected file path to have directory prefix stripped")
	}
}
