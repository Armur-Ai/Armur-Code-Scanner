package internal

import (
	"testing"
)

// --- cppcheck ---

func TestRunCppcheck_EmptyDir(t *testing.T) {
	result, err := RunCppcheck(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeCppcheckResults_Empty(t *testing.T) {
	r := categorizeCppcheckResults(`<?xml version="1.0"?><results version="2"><errors></errors></results>`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 || len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Error("expected empty results for empty cppcheck XML")
	}
}

func TestCategorizeCppcheckResults_WithError(t *testing.T) {
	raw := `<?xml version="1.0"?><results version="2"><errors>
		<error id="bufferAccessOutOfBounds" severity="error" msg="Buffer overrun" verbose="Array out of bounds">
			<location file="/repo/main.c" line="10" column="5"/>
		</error>
	</errors></results>`
	r := categorizeCppcheckResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 security issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity for error, got %v", issue["severity"])
	}
}

func TestCategorizeCppcheckResults_WithWarning(t *testing.T) {
	raw := `<?xml version="1.0"?><results version="2"><errors>
		<error id="uninitialisedVariable" severity="warning" msg="Uninitialized variable" verbose="Variable x is used before initialization">
			<location file="/repo/main.c" line="5" column="1"/>
		</error>
	</errors></results>`
	r := categorizeCppcheckResults(raw, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeCppcheckResults_SkipsMissingInclude(t *testing.T) {
	raw := `<?xml version="1.0"?><results version="2"><errors>
		<error id="missingInclude" severity="information" msg="Include file not found">
		</error>
	</errors></results>`
	r := categorizeCppcheckResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 || len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Error("expected missingInclude to be filtered out")
	}
}

func TestCategorizeCppcheckResults_InvalidXML(t *testing.T) {
	r := categorizeCppcheckResults("not xml", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Error("expected 0 results on parse error")
	}
}

// --- Flawfinder ---

func TestRunFlawfinder_EmptyDir(t *testing.T) {
	result, err := RunFlawfinder(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeFlawfinderResults_Empty(t *testing.T) {
	r := categorizeFlawfinderResults("File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context\n", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues from header-only CSV, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeFlawfinderResults_WithFinding(t *testing.T) {
	raw := "File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context\n/repo/main.c,10,5,4,buffer,strcpy,\"strcpy can overflow\",\"Use strncpy\",\"\",CWE-120,\"strcpy(buf, input)\"\n"
	r := categorizeFlawfinderResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r[SECURITY_ISSUES]))
	}
	f := r[SECURITY_ISSUES][0].(map[string]interface{})
	if f["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity for level 4, got %v", f["severity"])
	}
}

func TestCategorizeFlawfinderResults_LevelMapping(t *testing.T) {
	tests := []struct {
		level    int
		expected string
	}{
		{5, "HIGH"},
		{4, "HIGH"},
		{3, "MEDIUM"},
		{2, "MEDIUM"},
		{1, "LOW"},
		{0, "LOW"},
	}

	for _, tc := range tests {
		raw := "File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context\n"
		raw += "/repo/f.c,1,1," + string(rune('0'+tc.level)) + ",cat,func,warn,sug,note,,"
		r := categorizeFlawfinderResults(raw, "/repo")
		if len(r[SECURITY_ISSUES]) == 1 {
			f := r[SECURITY_ISSUES][0].(map[string]interface{})
			if f["severity"] != tc.expected {
				t.Errorf("level %d: expected %s, got %v", tc.level, tc.expected, f["severity"])
			}
		}
	}
}
