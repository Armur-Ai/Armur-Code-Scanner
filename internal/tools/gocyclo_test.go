package internal

import (
	"testing"
)

func TestCategorizeGocycloResults_Empty(t *testing.T) {
	result := CategorizeGocycloResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result[COMPLEX_FUNCTIONS]) != 0 {
		t.Errorf("expected 0 complex functions for empty input, got %d", len(result[COMPLEX_FUNCTIONS]))
	}
}

func TestCategorizeGocycloResults_ValidEntry(t *testing.T) {
	// Format: <complexity> <package> <function> <file:line:col>
	input := "12 main (*Handler).ServeHTTP /tmp/test/handler.go:45:1"
	result := CategorizeGocycloResults(input, "/tmp/test")
	if len(result[COMPLEX_FUNCTIONS]) != 1 {
		t.Errorf("expected 1 complex function, got %d", len(result[COMPLEX_FUNCTIONS]))
	}
	entry := result[COMPLEX_FUNCTIONS][0].(map[string]interface{})
	if entry["complexity"] != "12" {
		t.Errorf("expected complexity 12, got %v", entry["complexity"])
	}
	if entry["function"] != "(*Handler).ServeHTTP" {
		t.Errorf("unexpected function name: %v", entry["function"])
	}
}

func TestCategorizeGocycloResults_MultipleEntries(t *testing.T) {
	input := "15 main FuncA /tmp/test/a.go:10:1\n8 main FuncB /tmp/test/b.go:20:1"
	result := CategorizeGocycloResults(input, "/tmp/test")
	if len(result[COMPLEX_FUNCTIONS]) != 2 {
		t.Errorf("expected 2 complex functions, got %d", len(result[COMPLEX_FUNCTIONS]))
	}
}

func TestCategorizeGocycloResults_InvalidLocationFormat(t *testing.T) {
	// Location without the 3-part colon format — should be skipped
	input := "15 main FuncA /tmp/test/a.go"
	result := CategorizeGocycloResults(input, "/tmp/test")
	if len(result[COMPLEX_FUNCTIONS]) != 0 {
		t.Errorf("expected 0 complex functions for invalid format, got %d", len(result[COMPLEX_FUNCTIONS]))
	}
}
