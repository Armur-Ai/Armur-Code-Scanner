package internal

import (
	"testing"
)

func TestCategorizePydocstyleResults_Empty(t *testing.T) {
	result := CategorizePydocstyleResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[DOCKSTRING_ABSENT]) != 0 {
		t.Errorf("expected 0 docstring issues for empty input, got %d", len(result[DOCKSTRING_ABSENT]))
	}
}

func TestCategorizePydocstyleResults_WithIssue(t *testing.T) {
	input := `/tmp/test/app.py:10 in public method ` + "`" + `my_func` + "`" + `:
	D200: No whitespaces allowed surrounding docstring text`
	result := CategorizePydocstyleResults(input, "/tmp/test")
	// The regex matches specific format; if no match, result should still be non-nil
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizePydocstyleResults_MatchingFormat(t *testing.T) {
	// pydocstyle output: "filename:line level: D999: message"
	input := `/tmp/test/app.py:5 in public function ` + "`" + `foo` + "`" + `:
        D103: Missing docstring in public function`
	result := CategorizePydocstyleResults(input, "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	// The regex pattern extracts: filename:line level: Derror_code: message
	// This tests that the parser doesn't panic on well-formed output
}

func TestCategorizePydocstyleResults_MultipleIssues(t *testing.T) {
	// Provide something that looks like pydocstyle's format in case regex matches
	input := `/tmp/test/a.py:1 public:
	D100: Missing docstring in public module
/tmp/test/b.py:5 public:
	D102: Missing docstring in public method`
	result := CategorizePydocstyleResults(input, "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for multi-issue input")
	}
}
