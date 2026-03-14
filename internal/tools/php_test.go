package internal

import (
	"testing"
)

// --- PHPCS ---

func TestRunPHPCS_EmptyDir(t *testing.T) {
	result, err := RunPHPCS(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizePHPCSResults_Empty(t *testing.T) {
	r := categorizePHPCSResults(`{"files":{}}`, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePHPCSResults_WithError(t *testing.T) {
	raw := `{"files":{"/repo/index.php":{"messages":[{"message":"eval() is a security risk","source":"Security.Utility.EvalFound","severity":10,"type":"ERROR","line":5,"column":1}]}}}`
	r := categorizePHPCSResults(raw, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
	bug := r[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	if bug["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity for ERROR type, got %v", bug["severity"])
	}
}

func TestCategorizePHPCSResults_InvalidJSON(t *testing.T) {
	r := categorizePHPCSResults("not json", "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs on parse error, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

// --- Psalm ---

func TestRunPsalm_EmptyDir(t *testing.T) {
	result, err := RunPsalm(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizePsalmResults_Empty(t *testing.T) {
	r := categorizePsalmResults("[]", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 security issues, got %d", len(r[SECURITY_ISSUES]))
	}
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePsalmResults_WithError(t *testing.T) {
	raw := `[{"type":"TaintedInput","severity":"error","file_path":"/repo/src/foo.php","line_from":10,"line_to":10,"message":"Tainted input may reach SQL","error_code":4}]`
	r := categorizePsalmResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 security issue, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizePsalmResults_WithWarning(t *testing.T) {
	raw := `[{"type":"UndefinedVariable","severity":"warning","file_path":"/repo/src/bar.php","line_from":5,"line_to":5,"message":"Variable $x is not defined","error_code":101}]`
	r := categorizePsalmResults(raw, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePsalmResults_InvalidJSON(t *testing.T) {
	r := categorizePsalmResults("not json", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 && len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Error("expected empty results on parse error")
	}
}
