package internal

import (
	"testing"
)

// --- SpotBugs ---

func TestRunSpotBugs_EmptyDir(t *testing.T) {
	result, err := RunSpotBugs(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeSpotBugsResults_EmptyXML(t *testing.T) {
	r := categorizeSpotBugsResults("<BugCollection/>", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeSpotBugsResults_InvalidXML(t *testing.T) {
	r := categorizeSpotBugsResults("not xml", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues on parse error, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeSpotBugsResults_WithBug(t *testing.T) {
	raw := `<BugCollection>
		<BugInstance type="SQL_INJECTION_JDBC" priority="1" category="SECURITY">
			<Class classname="Foo">
				<SourceLine sourcepath="Foo.java" start="10" end="10"/>
			</Class>
			<ShortMessage>SQL injection</ShortMessage>
			<LongMessage>User input used in SQL query without sanitization</LongMessage>
		</BugInstance>
	</BugCollection>`
	r := categorizeSpotBugsResults(raw, "/repo/")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity for priority 1, got %v", issue["severity"])
	}
	if issue["check_id"] != "SQL_INJECTION_JDBC" {
		t.Errorf("unexpected check_id: %v", issue["check_id"])
	}
}

// --- PMD ---

func TestRunPMD_EmptyDir(t *testing.T) {
	result, err := RunPMD(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizePMDResults_Empty(t *testing.T) {
	r := categorizePMDResults(`{"files":[]}`, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizePMDResults_WithViolation(t *testing.T) {
	raw := `{"files":[{"filename":"/repo/Foo.java","violations":[{"beginline":5,"endline":5,"description":"Empty catch block","rule":"EmptyCatchBlock","ruleset":"Error Prone","priority":3}]}]}`
	r := categorizePMDResults(raw, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
	bug := r[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	if bug["check_id"] != "EmptyCatchBlock" {
		t.Errorf("unexpected check_id: %v", bug["check_id"])
	}
	if bug["severity"] != "MEDIUM" {
		t.Errorf("expected MEDIUM severity for priority 3, got %v", bug["severity"])
	}
}

func TestCategorizePMDResults_InvalidJSON(t *testing.T) {
	r := categorizePMDResults("not json", "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs on parse error, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

// --- OWASP Dependency-Check ---

func TestRunDependencyCheck_EmptyDir(t *testing.T) {
	result, err := RunDependencyCheck(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeDependencyCheckResults_Empty(t *testing.T) {
	r := categorizeDependencyCheckResults(`{"dependencies":[]}`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeDependencyCheckResults_WithVulnerability(t *testing.T) {
	raw := `{"dependencies":[{"fileName":"log4j-core-2.14.1.jar","vulnerabilities":[{"name":"CVE-2021-44228","severity":"CRITICAL","description":"Log4Shell RCE","cvssv3":{"baseScore":10.0}}]}]}`
	r := categorizeDependencyCheckResults(raw, "")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %v", issue["severity"])
	}
}
