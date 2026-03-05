package internal

import (
	"testing"
)

func TestCategorizeGovetResults_Empty(t *testing.T) {
	result := categorizeGovetResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 antipattern bugs for empty input, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeGovetResults_WithIssues(t *testing.T) {
	input := "/tmp/test/main.go:10:5: undefined: someFunc"
	result := categorizeGovetResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Errorf("expected 1 antipattern bug, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeGovetResults_MultipleIssues(t *testing.T) {
	input := "/tmp/test/main.go:10:5: undefined: foo\n/tmp/test/main.go:20:3: undefined: bar"
	result := categorizeGovetResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 2 {
		t.Errorf("expected 2 antipattern bugs, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestFormatIssuess_FullFormat(t *testing.T) {
	issue := "/tmp/test/main.go:10:5:undefined: someFunc"
	result := formatIssuess(issue, "/tmp/test")
	if result["line"] != "10" {
		t.Errorf("expected line 10, got %v", result["line"])
	}
	if result["column"] != "5" {
		t.Errorf("expected column 5, got %v", result["column"])
	}
}

func TestFormatIssuess_ShortFormat(t *testing.T) {
	issue := "/tmp/test/main.go:undefined"
	result := formatIssuess(issue, "/tmp/test")
	if result["path"] == nil {
		t.Error("expected path to be set")
	}
}
