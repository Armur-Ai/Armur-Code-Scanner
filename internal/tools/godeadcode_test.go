package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeDeadCodeResults_Empty(t *testing.T) {
	result := categorizeDeadCodeResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.DEAD_CODE]) != 0 {
		t.Errorf("expected 0 dead code entries for empty input, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeDeadCodeResults_NoColon(t *testing.T) {
	result := categorizeDeadCodeResults("no colons here", "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 0 {
		t.Errorf("expected 0 dead code entries for input with no colon, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeDeadCodeResults_WithIssues(t *testing.T) {
	input := "/tmp/test/main.go:15: func unusedFunc is never called"
	result := categorizeDeadCodeResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 1 {
		t.Errorf("expected 1 dead code entry, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestCategorizeDeadCodeResults_MultipleLines(t *testing.T) {
	input := "/tmp/test/main.go:10: func foo is never called\n/tmp/test/main.go:20: func bar is never called"
	result := categorizeDeadCodeResults(input, "/tmp/test")
	if len(result[utils.DEAD_CODE]) != 2 {
		t.Errorf("expected 2 dead code entries, got %d", len(result[utils.DEAD_CODE]))
	}
}

func TestFormatDeadCodeIssue_Valid(t *testing.T) {
	result := formatDeadCodeIssue("/tmp/test/main.go:15: unused func", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["line"] != "15" {
		t.Errorf("expected line 15, got %v", result["line"])
	}
}

func TestFormatDeadCodeIssue_TooFewParts(t *testing.T) {
	result := formatDeadCodeIssue("no colons", "/tmp/test")
	if result != nil {
		t.Error("expected nil for too-few-parts input")
	}
}
