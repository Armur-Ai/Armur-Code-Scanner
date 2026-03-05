package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeStaticcheckResults_Empty(t *testing.T) {
	result := CategorizeStaticcheckResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.DOCKSTRING_ABSENT]) != 0 {
		t.Errorf("expected 0 docstring issues for empty input, got %d", len(result[utils.DOCKSTRING_ABSENT]))
	}
}

func TestCategorizeStaticcheckResults_StyleIssue(t *testing.T) {
	input := `{"code":"ST1000","location":{"file":"/tmp/test/main.go","line":1,"column":1},"message":"package comment should be of the form..."}`
	result := CategorizeStaticcheckResults(input, "/tmp/test")
	if len(result[utils.DOCKSTRING_ABSENT]) != 1 {
		t.Errorf("expected 1 docstring issue for ST code, got %d", len(result[utils.DOCKSTRING_ABSENT]))
	}
}

func TestCategorizeStaticcheckResults_SA1Issue(t *testing.T) {
	input := `{"code":"SA1000","location":{"file":"/tmp/test/main.go","line":5,"column":2},"message":"invalid regex"}`
	result := CategorizeStaticcheckResults(input, "/tmp/test")
	if len(result[utils.COMPLEX_FUNCTIONS]) != 1 {
		t.Errorf("expected 1 complex function for SA1 code, got %d", len(result[utils.COMPLEX_FUNCTIONS]))
	}
}

func TestCategorizeStaticcheckResults_SA2Issue(t *testing.T) {
	input := `{"code":"SA2000","location":{"file":"/tmp/test/main.go","line":10,"column":3},"message":"sync.WaitGroup..."}`
	result := CategorizeStaticcheckResults(input, "/tmp/test")
	if len(result[utils.COMPLEX_FUNCTIONS]) != 1 {
		t.Errorf("expected 1 complex function for SA2 code, got %d", len(result[utils.COMPLEX_FUNCTIONS]))
	}
}

func TestCategorizeStaticcheckResults_InvalidJSON(t *testing.T) {
	result := CategorizeStaticcheckResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
}

func TestFormatIssueForStatic_ValidInput(t *testing.T) {
	issue := map[string]interface{}{
		"code": "ST1000",
		"location": map[string]interface{}{
			"file":   "/tmp/test/main.go",
			"line":   float64(10),
			"column": float64(5),
		},
		"message": "package comment required",
	}
	result := FormatIssueForStatic(issue, "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil formatted result")
	}
	if result["message"] != "package comment required" {
		t.Errorf("expected message, got %v", result["message"])
	}
}

func TestFormatIssueForStatic_MissingLocation(t *testing.T) {
	issue := map[string]interface{}{
		"code":    "ST1000",
		"message": "something",
	}
	result := FormatIssueForStatic(issue, "/tmp/test")
	if result != nil {
		t.Error("expected nil for missing location")
	}
}
