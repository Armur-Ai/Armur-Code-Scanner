package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFileLanguage(t *testing.T) {
	tests := []struct {
		file     string
		expected string
	}{
		{"main.go", "go"},
		{"app.py", "py"},
		{"index.js", "js"},
		{"README.md", ""},
		{"", ""},
		{"/path/to/file.go", "go"},
		{"/path/to/script.py", "py"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got := DetectFileLanguage(tt.file)
			if got != tt.expected {
				t.Errorf("DetectFileLanguage(%q) = %q, want %q", tt.file, got, tt.expected)
			}
		})
	}
}

func TestDetectRepoLanguage(t *testing.T) {
	dir := t.TempDir()

	// Create 3 Go files, 1 Python file — expect "go"
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		os.WriteFile(filepath.Join(dir, name), []byte("package main"), 0644)
	}
	os.WriteFile(filepath.Join(dir, "script.py"), []byte("pass"), 0644)

	lang := DetectRepoLanguage(dir)
	if lang != "go" {
		t.Errorf("DetectRepoLanguage = %q, want %q", lang, "go")
	}
}

func TestInitCategorizedResults(t *testing.T) {
	r := InitCategorizedResults()

	expected := []string{DOCKSTRING_ABSENT, SECURITY_ISSUES, COMPLEX_FUNCTIONS, ANTIPATTERNS_BUGS}
	for _, key := range expected {
		if _, ok := r[key]; !ok {
			t.Errorf("InitCategorizedResults missing key %q", key)
		}
	}
}

func TestInitAdvancedCategorizedResults(t *testing.T) {
	r := InitAdvancedCategorizedResults()

	expected := []string{DEAD_CODE, DUPLICATE_CODE, SECRET_DETECTION, INFRA_SECURITY, SCA}
	for _, key := range expected {
		if _, ok := r[key]; !ok {
			t.Errorf("InitAdvancedCategorizedResults missing key %q", key)
		}
	}
}

func TestConvertCategorizedResults(t *testing.T) {
	input := map[string][]interface{}{
		"key1": {1, 2, 3},
		"key2": nil,
	}
	output := ConvertCategorizedResults(input)

	if v, ok := output["key1"].([]interface{}); !ok || len(v) != 3 {
		t.Error("ConvertCategorizedResults: key1 not converted correctly")
	}
	if v, ok := output["key2"].([]interface{}); !ok || len(v) != 0 {
		t.Error("ConvertCategorizedResults: nil value should become empty slice")
	}
}

func TestReformatScanResults_EmptyInput(t *testing.T) {
	input := map[string]interface{}{
		COMPLEX_FUNCTIONS: []interface{}{},
		DOCKSTRING_ABSENT: []interface{}{},
		ANTIPATTERNS_BUGS: []interface{}{},
		SECURITY_ISSUES:   []interface{}{},
	}
	result := ReformatScanResults(input)
	if result == nil {
		t.Fatal("ReformatScanResults returned nil for empty input")
	}
}

func TestLoadCWEData(t *testing.T) {
	// This test requires the cwd.json fixture to be present relative to the test run dir.
	// Run from the repo root: go test ./pkg/...
	data, err := LoadCWEData("common/cwd.json")
	if err != nil {
		t.Skipf("cwd.json not found at expected path, skipping: %v", err)
	}
	if len(data) == 0 {
		t.Error("LoadCWEData returned empty slice")
	}
}

func TestGetPracticesFromJSON_KnownCWE(t *testing.T) {
	data := []CWEData{
		{
			CWE: "CWE-89",
			GoodPracticeExample: map[string]string{"go": "use parameterized queries"},
			BadPracticeExample:  map[string]string{"go": "string concatenation"},
		},
	}
	result := GetPracticesFromJSON(data, "go", "CWE-89")
	if result["good_practice"] != "use parameterized queries" {
		t.Errorf("unexpected good_practice: %v", result["good_practice"])
	}
	if result["bad_practice"] != "string concatenation" {
		t.Errorf("unexpected bad_practice: %v", result["bad_practice"])
	}
}

func TestGetPracticesFromJSON_UnknownCWE(t *testing.T) {
	data := []CWEData{}
	result := GetPracticesFromJSON(data, "go", "CWE-9999")
	if len(result) != 0 {
		t.Errorf("expected empty map for unknown CWE, got %v", result)
	}
}

func TestReformatSecurityIssues_GroupsByCWE(t *testing.T) {
	input := map[string]interface{}{
		SECURITY_ISSUES: []interface{}{
			map[string]interface{}{
				"cwe":  []interface{}{"CWE-89"},
				"path": "/main.go",
				"line": float64(10),
			},
			map[string]interface{}{
				"cwe":  []interface{}{"CWE-89"},
				"path": "/main.go",
				"line": float64(20),
			},
			map[string]interface{}{
				"cwe":  []interface{}{"CWE-79"},
				"path": "/handler.go",
				"line": float64(5),
			},
		},
	}

	result := ReformatSecurityIssues(input)
	if len(result) != 2 {
		t.Errorf("expected 2 CWE groups, got %d", len(result))
	}
}

func TestReformatDeadCode_Empty(t *testing.T) {
	result := ReformatDeadCode(map[string]interface{}{})
	if result == nil {
		t.Error("ReformatDeadCode should return non-nil empty slice for missing key")
	}
}

func TestRemoveNonRelevantFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a mix of file types
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "script.py"), []byte("pass"), 0644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("notes"), 0644)

	if err := RemoveNonRelevantFiles(dir, "go"); err != nil {
		t.Fatalf("RemoveNonRelevantFiles error: %v", err)
	}

	// .go should remain, .py and .txt should be removed
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
		t.Error("main.go should not have been removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "script.py")); !os.IsNotExist(err) {
		t.Error("script.py should have been removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); !os.IsNotExist(err) {
		t.Error("notes.txt should have been removed")
	}
}
