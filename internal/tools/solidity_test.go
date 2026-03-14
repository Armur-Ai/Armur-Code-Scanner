package internal

import (
	"testing"
)

// --- Slither ---

func TestRunSlither_EmptyDir(t *testing.T) {
	result, err := RunSlither(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeSlitherResults_Empty(t *testing.T) {
	r := categorizeSlitherResults(`{"success":true,"results":{"detectors":[]}}`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeSlitherResults_WithFinding(t *testing.T) {
	raw := `{"success":true,"results":{"detectors":[{"check":"reentrancy-eth","impact":"High","confidence":"High","description":"Reentrancy in withdraw()","elements":[{"name":"withdraw","type":"function","source_mapping":{"filename":"/repo/Vault.sol","lines":[10,11,12]}}]}]}}`
	r := categorizeSlitherResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", issue["severity"])
	}
	if issue["check_id"] != "reentrancy-eth" {
		t.Errorf("unexpected check_id: %v", issue["check_id"])
	}
}

func TestCategorizeSlitherResults_ImpactMapping(t *testing.T) {
	tests := []struct {
		impact   string
		expected string
	}{
		{"High", "HIGH"},
		{"Medium", "MEDIUM"},
		{"Low", "LOW"},
		{"Informational", "INFO"},
		{"Optimization", "INFO"},
	}

	for _, tc := range tests {
		raw := `{"success":true,"results":{"detectors":[{"check":"test","impact":"` + tc.impact + `","confidence":"High","description":"test","elements":[]}]}}`
		r := categorizeSlitherResults(raw, "/repo")
		if len(r[SECURITY_ISSUES]) != 1 {
			t.Fatalf("impact %s: expected 1 issue, got %d", tc.impact, len(r[SECURITY_ISSUES]))
		}
		issue := r[SECURITY_ISSUES][0].(map[string]interface{})
		if issue["severity"] != tc.expected {
			t.Errorf("impact %s: expected %s, got %v", tc.impact, tc.expected, issue["severity"])
		}
	}
}

func TestCategorizeSlitherResults_InvalidJSON(t *testing.T) {
	r := categorizeSlitherResults("not json", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Error("expected 0 results on parse error")
	}
}

// --- Mythril ---

func TestRunMythril_EmptyDir(t *testing.T) {
	result, err := RunMythril(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeMythrilResults_Empty(t *testing.T) {
	r := categorizeMythrilResults(`{"success":true,"issues":[]}`, "/repo", "Foo.sol")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeMythrilResults_WithIssue(t *testing.T) {
	raw := `{"success":true,"issues":[{"title":"Reentrancy","description":"External call followed by state change","severity":"High","swcID":"SWC-107","swcURL":"https://swcregistry.io/docs/SWC-107","locations":[{"sourceMap":"100:50:0"}]}]}`
	r := categorizeMythrilResults(raw, "/repo", "Vault.sol")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", issue["severity"])
	}
	if issue["check_id"] != "SWC-107" {
		t.Errorf("unexpected check_id: %v", issue["check_id"])
	}
}

func TestCategorizeMythrilResults_InvalidJSON(t *testing.T) {
	r := categorizeMythrilResults("not json", "/repo", "Foo.sol")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Error("expected 0 results on parse error")
	}
}
