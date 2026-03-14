package internal

import (
	"testing"
)

// --- cargo-audit ---

func TestRunCargoAudit_EmptyOutput(t *testing.T) {
	result, err := RunCargoAudit(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeCargoAuditResults_Empty(t *testing.T) {
	r := categorizeCargoAuditResults("")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeCargoAuditResults_Vulnerability(t *testing.T) {
	raw := `{
		"vulnerabilities": {
			"list": [{
				"advisory": {"id":"RUSTSEC-2023-0001","title":"Buffer overflow in foo","description":"desc","cvss":"7.5"},
				"package": {"name":"foo","version":"1.0.0"},
				"severity": "high"
			}]
		}
	}`
	r := categorizeCargoAuditResults(raw)
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", issue["severity"])
	}
	if issue["check_id"] != "RUSTSEC-2023-0001" {
		t.Errorf("unexpected check_id: %v", issue["check_id"])
	}
}

func TestCategorizeCargoAuditResults_InvalidJSON(t *testing.T) {
	r := categorizeCargoAuditResults("{not valid json}")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues on parse error, got %d", len(r[SECURITY_ISSUES]))
	}
}

// --- cargo-geiger ---

func TestRunCargoGeiger_EmptyOutput(t *testing.T) {
	result, err := RunCargoGeiger(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeCargoGeigerResults_NoUnsafe(t *testing.T) {
	raw := "| my_crate | 0/10 | 0 | 0 | 0 | 0 |"
	r := categorizeCargoGeigerResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues for zero unsafe count, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeCargoGeigerResults_WithUnsafe(t *testing.T) {
	raw := "| risky_crate | 5/10 | 5 | 0 | 0 | 0 |"
	r := categorizeCargoGeigerResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
}

// --- clippy ---

func TestRunClippy_EmptyDir(t *testing.T) {
	result, err := RunClippy(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeClippyResults_Empty(t *testing.T) {
	r := categorizeClippyResults("", "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeClippyResults_Warning(t *testing.T) {
	raw := `{"reason":"compiler-message","message":{"message":"unused variable: x","level":"warning","code":{"code":"unused_variables"},"spans":[{"file_name":"src/main.rs","line_start":5,"line_end":5}]}}`
	r := categorizeClippyResults(raw, "/repo/")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
	bug := r[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	if bug["severity"] != "LOW" {
		t.Errorf("expected LOW severity for warning, got %v", bug["severity"])
	}
}

func TestCategorizeClippyResults_Error(t *testing.T) {
	raw := `{"reason":"compiler-message","message":{"message":"use of unsafe code","level":"error","code":null,"spans":[{"file_name":"src/lib.rs","line_start":10,"line_end":12}]}}`
	r := categorizeClippyResults(raw, "/repo/")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
	bug := r[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	if bug["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity for error, got %v", bug["severity"])
	}
}

func TestCategorizeClippyResults_SkipsNonCompilerMessage(t *testing.T) {
	raw := `{"reason":"build-script-executed","message":null}`
	r := categorizeClippyResults(raw, "/repo/")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs for non-compiler-message, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}
