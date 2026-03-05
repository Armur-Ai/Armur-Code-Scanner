package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeJSCPDResults_Empty(t *testing.T) {
	result := CategorizeJSCPDResults([]map[string]interface{}{}, "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.DUPLICATE_CODE]) != 0 {
		t.Errorf("expected 0 duplicate code entries for empty input, got %d", len(result[utils.DUPLICATE_CODE]))
	}
}

func TestCategorizeJSCPDResults_WithDuplicate(t *testing.T) {
	duplicates := []map[string]interface{}{
		{
			"firstFile": map[string]interface{}{
				"name":  "/tmp/test/a.js",
				"start": float64(1),
				"end":   float64(15),
			},
			"secondFile": map[string]interface{}{
				"name":  "/tmp/test/b.js",
				"start": float64(10),
				"end":   float64(24),
			},
		},
	}
	result := CategorizeJSCPDResults(duplicates, "/tmp/test")
	if len(result[utils.DUPLICATE_CODE]) != 1 {
		t.Errorf("expected 1 duplicate code entry, got %d", len(result[utils.DUPLICATE_CODE]))
	}
	entry := result[utils.DUPLICATE_CODE][0].(map[string]interface{})
	if entry["severity"] != "Major" {
		t.Errorf("expected Major severity for 14-line duplicate, got %v", entry["severity"])
	}
}

func TestCategorizeJSCPDResults_MinorSeverity(t *testing.T) {
	duplicates := []map[string]interface{}{
		{
			"firstFile": map[string]interface{}{
				"name":  "/tmp/test/a.js",
				"start": float64(1),
				"end":   float64(5),
			},
			"secondFile": map[string]interface{}{
				"name":  "/tmp/test/b.js",
				"start": float64(1),
				"end":   float64(5),
			},
		},
	}
	result := CategorizeJSCPDResults(duplicates, "/tmp/test")
	entry := result[utils.DUPLICATE_CODE][0].(map[string]interface{})
	if entry["severity"] != "Minor" {
		t.Errorf("expected Minor severity for 4-line duplicate, got %v", entry["severity"])
	}
}

func TestDetermineSeverity(t *testing.T) {
	tests := []struct {
		lines    float64
		expected string
	}{
		{5, "Minor"},
		{9, "Minor"},
		{10, "Major"},
		{50, "Major"},
	}
	for _, tt := range tests {
		got := determineSeverity(tt.lines)
		if got != tt.expected {
			t.Errorf("determineSeverity(%v) = %v, want %v", tt.lines, got, tt.expected)
		}
	}
}
