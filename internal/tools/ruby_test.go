package internal

import (
	"testing"
)

// --- Brakeman ---

func TestRunBrakeman_EmptyDir(t *testing.T) {
	result, err := RunBrakeman(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeBrakemanResults_Empty(t *testing.T) {
	r := categorizeBrakemanResults(`{"warnings":[]}`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeBrakemanResults_WithWarning(t *testing.T) {
	raw := `{"warnings":[{"warning_type":"SQL Injection","file":"/repo/app/models/user.rb","line":42,"message":"Possible SQL injection","confidence":"High","code":"User.where(\"id = #{params[:id]}\")","cvss_score":8.8}]}`
	r := categorizeBrakemanResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", issue["severity"])
	}
	if issue["check_id"] != "SQL Injection" {
		t.Errorf("unexpected check_id: %v", issue["check_id"])
	}
}

func TestCategorizeBrakemanResults_InvalidJSON(t *testing.T) {
	r := categorizeBrakemanResults("not json", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues on parse error, got %d", len(r[SECURITY_ISSUES]))
	}
}

// --- Bundler Audit ---

func TestRunBundlerAudit_EmptyDir(t *testing.T) {
	result, err := RunBundlerAudit(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeBundlerAuditResults_NoVulns(t *testing.T) {
	r := categorizeBundlerAuditResults("No vulnerabilities found\n")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeBundlerAuditResults_WithVuln(t *testing.T) {
	raw := `Name: rails
Version: 5.2.4
Advisory: CVE-2020-8164
Criticality: High
Title: Possible Strong Parameters Bypass in ActionPack
Solution: upgrade to ~> 5.2.4.3, >= 6.0.3.1

Vulnerabilities found!`
	r := categorizeBundlerAuditResults(raw)
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", issue["severity"])
	}
	if issue["check_id"] != "CVE-2020-8164" {
		t.Errorf("unexpected check_id: %v", issue["check_id"])
	}
}

func TestExtractField(t *testing.T) {
	block := "Name: rack\nVersion: 2.1.0\nAdvisory: GHSA-abc"
	if got := extractField(block, "Name:"); got != "rack" {
		t.Errorf("expected 'rack', got %q", got)
	}
	if got := extractField(block, "Missing:"); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
