package tasks

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// maxConcurrency
// ---------------------------------------------------------------------------

func TestMaxConcurrency_Default(t *testing.T) {
	os.Unsetenv("MAX_TOOL_CONCURRENCY")
	if got := maxConcurrency(); got != 5 {
		t.Errorf("maxConcurrency() = %d, want 5", got)
	}
}

func TestMaxConcurrency_EnvVar(t *testing.T) {
	os.Setenv("MAX_TOOL_CONCURRENCY", "3")
	defer os.Unsetenv("MAX_TOOL_CONCURRENCY")
	if got := maxConcurrency(); got != 3 {
		t.Errorf("maxConcurrency() = %d, want 3", got)
	}
}

func TestMaxConcurrency_InvalidEnvVar(t *testing.T) {
	os.Setenv("MAX_TOOL_CONCURRENCY", "not-a-number")
	defer os.Unsetenv("MAX_TOOL_CONCURRENCY")
	if got := maxConcurrency(); got != 5 {
		t.Errorf("maxConcurrency() with invalid env = %d, want default 5", got)
	}
}

func TestMaxConcurrency_ZeroEnvVar(t *testing.T) {
	os.Setenv("MAX_TOOL_CONCURRENCY", "0")
	defer os.Unsetenv("MAX_TOOL_CONCURRENCY")
	// 0 is not > 0, so should return default 5
	if got := maxConcurrency(); got != 5 {
		t.Errorf("maxConcurrency() with 0 = %d, want default 5", got)
	}
}

// ---------------------------------------------------------------------------
// runParallel
// ---------------------------------------------------------------------------

func TestRunParallel_AllSucceed(t *testing.T) {
	runners := []func() toolResult{
		func() toolResult {
			return toolResult{
				name:   "tool1",
				result: map[string]interface{}{"security_issues": []interface{}{"issue1"}},
				err:    nil,
			}
		},
		func() toolResult {
			return toolResult{
				name:   "tool2",
				result: map[string]interface{}{"security_issues": []interface{}{"issue2"}},
				err:    nil,
			}
		},
	}

	results, errs := runParallel("", runners)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
	if len(results["security_issues"]) != 2 {
		t.Errorf("expected 2 security_issues, got %d", len(results["security_issues"]))
	}
}

func TestRunParallel_ToolError(t *testing.T) {
	runners := []func() toolResult{
		func() toolResult {
			return toolResult{name: "bad-tool", result: nil, err: os.ErrNotExist}
		},
		func() toolResult {
			return toolResult{
				name:   "good-tool",
				result: map[string]interface{}{"security_issues": []interface{}{"issue1"}},
				err:    nil,
			}
		},
	}

	results, errs := runParallel("", runners)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Tool != "bad-tool" {
		t.Errorf("expected error from bad-tool, got %q", errs[0].Tool)
	}
	if len(results["security_issues"]) != 1 {
		t.Errorf("expected 1 security issue from good-tool, got %d", len(results["security_issues"]))
	}
}

func TestRunParallel_Empty(t *testing.T) {
	results, errs := runParallel("", nil)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors for empty runners, got %d", len(errs))
	}
	if results == nil {
		t.Error("runParallel should return non-nil results map for empty runners")
	}
}

func TestRunParallelAdvanced_AllSucceed(t *testing.T) {
	runners := []func() toolResult{
		func() toolResult {
			return toolResult{
				name:   "trivy",
				result: map[string]interface{}{"sca": []interface{}{"vuln1"}},
				err:    nil,
			}
		},
	}

	results, errs := runParallelAdvanced("", runners)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d", len(errs))
	}
	if len(results["sca"]) != 1 {
		t.Errorf("expected 1 sca result, got %d", len(results["sca"]))
	}
}

func TestRunParallelAdvanced_ToolError(t *testing.T) {
	runners := []func() toolResult{
		func() toolResult {
			return toolResult{name: "bad-tool", result: nil, err: os.ErrPermission}
		},
	}
	_, errs := runParallelAdvanced("", runners)
	if len(errs) != 1 {
		t.Errorf("expected 1 error, got %d", len(errs))
	}
}

// ---------------------------------------------------------------------------
// buildSimpleScanRunners
// ---------------------------------------------------------------------------

func TestBuildSimpleScanRunners_Go(t *testing.T) {
	runners := buildSimpleScanRunners("/tmp", "go")
	// semgrep + 5 go tools = 6
	if len(runners) < 2 {
		t.Errorf("expected at least 2 runners for go, got %d", len(runners))
	}
}

func TestBuildSimpleScanRunners_Python(t *testing.T) {
	runners := buildSimpleScanRunners("/tmp", "py")
	if len(runners) < 2 {
		t.Errorf("expected at least 2 runners for py, got %d", len(runners))
	}
}

func TestBuildSimpleScanRunners_JS(t *testing.T) {
	runners := buildSimpleScanRunners("/tmp", "js")
	if len(runners) < 2 {
		t.Errorf("expected at least 2 runners for js, got %d", len(runners))
	}
}

func TestBuildSimpleScanRunners_Unknown(t *testing.T) {
	runners := buildSimpleScanRunners("/tmp", "unknown")
	// Only semgrep for unknown language
	if len(runners) != 1 {
		t.Errorf("expected 1 runner (semgrep) for unknown language, got %d", len(runners))
	}
}

// ---------------------------------------------------------------------------
// mergeResultss
// ---------------------------------------------------------------------------

func TestMergeResultss_NilInput(t *testing.T) {
	base := map[string][]interface{}{
		"key1": {1, 2, 3},
	}
	mergeResultss(base, nil)
	if len(base["key1"]) != 3 {
		t.Errorf("base should be unchanged after merging nil, got %d items", len(base["key1"]))
	}
}

func TestMergeResultss_NewKey(t *testing.T) {
	base := map[string][]interface{}{}
	incoming := map[string]interface{}{
		"security_issues": []interface{}{"issue1", "issue2"},
	}
	mergeResultss(base, incoming)
	if len(base["security_issues"]) != 2 {
		t.Errorf("expected 2 items in security_issues, got %d", len(base["security_issues"]))
	}
}

func TestMergeResultss_AppendToExisting(t *testing.T) {
	base := map[string][]interface{}{
		"security_issues": {"existing"},
	}
	incoming := map[string]interface{}{
		"security_issues": []interface{}{"new1", "new2"},
	}
	mergeResultss(base, incoming)
	if len(base["security_issues"]) != 3 {
		t.Errorf("expected 3 items after merge, got %d", len(base["security_issues"]))
	}
}

func TestMergeResultss_NilValue(t *testing.T) {
	base := map[string][]interface{}{}
	incoming := map[string]interface{}{
		"security_issues": nil,
	}
	mergeResultss(base, incoming)
	if _, ok := base["security_issues"]; !ok {
		t.Error("expected key 'security_issues' to be initialized")
	}
	if len(base["security_issues"]) != 0 {
		t.Errorf("expected 0 items for nil value, got %d", len(base["security_issues"]))
	}
}

func TestMergeResultss_EmptySlice(t *testing.T) {
	base := map[string][]interface{}{}
	incoming := map[string]interface{}{
		"dead_code": []interface{}{},
	}
	mergeResultss(base, incoming)
	if _, ok := base["dead_code"]; !ok {
		t.Error("expected key 'dead_code' to be initialized for empty slice")
	}
}

func TestMergeResultss_NonSliceValue(t *testing.T) {
	base := map[string][]interface{}{}
	incoming := map[string]interface{}{
		"scan_errors": "not a slice",
	}
	mergeResultss(base, incoming)
}

func TestScanError_JSON(t *testing.T) {
	se := ScanError{Tool: "gosec", Message: "binary not found"}
	if se.Tool != "gosec" {
		t.Errorf("unexpected tool: %v", se.Tool)
	}
	if se.Message != "binary not found" {
		t.Errorf("unexpected message: %v", se.Message)
	}
}

// ---------------------------------------------------------------------------
// Integration tests — skip unless INTEGRATION_TESTS=1 is set.
// Run: INTEGRATION_TESTS=1 go test ./internal/tasks/...
// ---------------------------------------------------------------------------

// findTestdataDir locates the testdata directory walking up from cwd.
func findTestdataDir(t *testing.T, lang string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Skipf("could not get wd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "testdata", lang)
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("testdata/%s not found starting from %s", lang, dir)
		}
		dir = parent
	}
}

func TestRunScanTaskLocal_GoTestdata(t *testing.T) {
	if os.Getenv("INTEGRATION_TESTS") == "" {
		t.Skip("set INTEGRATION_TESTS=1 to run integration tests")
	}
	path := findTestdataDir(t, "go")
	result := RunScanTaskLocal(path, "go")
	if result == nil {
		t.Fatal("RunScanTaskLocal returned nil")
	}
	if status, ok := result["status"].(string); ok && status == "failed" {
		t.Fatalf("scan failed: %v", result["error"])
	}
}

func TestRunScanTaskLocal_PythonTestdata(t *testing.T) {
	if os.Getenv("INTEGRATION_TESTS") == "" {
		t.Skip("set INTEGRATION_TESTS=1 to run integration tests")
	}
	path := findTestdataDir(t, "python")
	result := RunScanTaskLocal(path, "py")
	if result == nil {
		t.Fatal("RunScanTaskLocal returned nil")
	}
	if status, ok := result["status"].(string); ok && status == "failed" {
		t.Fatalf("scan failed: %v", result["error"])
	}
}

func TestRunScanTaskLocal_JSTestdata(t *testing.T) {
	if os.Getenv("INTEGRATION_TESTS") == "" {
		t.Skip("set INTEGRATION_TESTS=1 to run integration tests")
	}
	path := findTestdataDir(t, "js")
	result := RunScanTaskLocal(path, "js")
	if result == nil {
		t.Fatal("RunScanTaskLocal returned nil")
	}
	if status, ok := result["status"].(string); ok && status == "failed" {
		t.Fatalf("scan failed: %v", result["error"])
	}
}

func TestRunSimpleScanLocal_DoesNotPanic(t *testing.T) {
	// Use a temp dir — tools will fail but should not panic.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}"), 0644)

	results, scanErrors, err := RunSimpleScanLocal(dir, "go")
	_ = scanErrors
	if err != nil {
		t.Logf("RunSimpleScanLocal returned error (tools may not be installed): %v", err)
		return
	}
	if results == nil {
		t.Error("expected non-nil results map")
	}
}
