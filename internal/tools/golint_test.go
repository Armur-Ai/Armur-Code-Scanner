package internal

import (
	"strings"
	"testing"
)

func TestCategorizeGolintResults_Empty(t *testing.T) {
	result := CategorizeGolintResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	for _, v := range result {
		if len(v) != 0 {
			t.Errorf("expected all empty slices for empty input, got non-empty: %v", v)
		}
	}
}

func TestCategorizeGolintResults_DocstringIssue(t *testing.T) {
	input := "/tmp/test/main.go:10:1: exported function Foo should have comment or be unexported"
	result := CategorizeGolintResults(input, "/tmp/test")
	if len(result[DOCKSTRING_ABSENT]) != 1 {
		t.Errorf("expected 1 docstring issue, got %d", len(result[DOCKSTRING_ABSENT]))
	}
}

func TestCategorizeGolintResults_AntipatternIssue(t *testing.T) {
	input := "/tmp/test/main.go:5:2: error return value not checked"
	result := CategorizeGolintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Errorf("expected 1 antipattern bug, got %d", len(result[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeGolintResults_PathStripping(t *testing.T) {
	input := "/tmp/test/main.go:10:1: error return value not checked"
	result := CategorizeGolintResults(input, "/tmp/test")
	if len(result[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 issue")
	}
	issue := result[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	path := issue["path"].(string)
	if strings.Contains(path, "/tmp/test") {
		t.Errorf("path should have directory stripped, got %q", path)
	}
}

func TestFormatIssue_ValidFormat(t *testing.T) {
	issue := "/path/to/file.go:10:5:some message here"
	result := formatIssue(issue, "/path/to")
	// strings.Replace strips the prefix, leaving the leading slash
	if result["path"] != "/file.go" {
		t.Errorf("unexpected path: %v", result["path"])
	}
	if result["line"] != "10" {
		t.Errorf("unexpected line: %v", result["line"])
	}
}

func TestFormatIssue_TooFewParts(t *testing.T) {
	issue := "file.go:10"
	result := formatIssue(issue, "")
	if result["message"] != "Invalid issue format" {
		t.Errorf("expected 'Invalid issue format', got %v", result["message"])
	}
}
