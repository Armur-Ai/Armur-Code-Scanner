package models

import (
	"testing"
)

func TestComputeID(t *testing.T) {
	f := Finding{
		Tool:    "gosec",
		File:    "main.go",
		Line:    42,
		RuleID:  "G201",
		Message: "SQL string formatting",
	}
	f.ComputeID()

	if f.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if len(f.ID) != 32 {
		t.Fatalf("expected 32-char hex ID, got %d chars: %s", len(f.ID), f.ID)
	}

	// Same input = same ID
	f2 := Finding{
		Tool:    "gosec",
		File:    "main.go",
		Line:    42,
		RuleID:  "G201",
		Message: "SQL string formatting",
	}
	f2.ComputeID()
	if f.ID != f2.ID {
		t.Fatalf("same input should produce same ID: %s != %s", f.ID, f2.ID)
	}

	// Different input = different ID
	f3 := Finding{
		Tool:    "semgrep",
		File:    "main.go",
		Line:    42,
		RuleID:  "sql-injection",
		Message: "SQL string formatting",
	}
	f3.ComputeID()
	if f.ID == f3.ID {
		t.Fatal("different tool should produce different ID")
	}
}

func TestSeverityOrder(t *testing.T) {
	if SeverityOrder(SeverityCritical) <= SeverityOrder(SeverityHigh) {
		t.Fatal("CRITICAL should be higher than HIGH")
	}
	if SeverityOrder(SeverityHigh) <= SeverityOrder(SeverityMedium) {
		t.Fatal("HIGH should be higher than MEDIUM")
	}
	if SeverityOrder(SeverityMedium) <= SeverityOrder(SeverityLow) {
		t.Fatal("MEDIUM should be higher than LOW")
	}
	if SeverityOrder(SeverityLow) <= SeverityOrder(SeverityInfo) {
		t.Fatal("LOW should be higher than INFO")
	}
}

func TestDeduplicate(t *testing.T) {
	findings := []Finding{
		{Tool: "gosec", File: "main.go", Line: 42, CWE: "CWE-89", Severity: SeverityHigh, Message: "SQL injection"},
		{Tool: "semgrep", File: "main.go", Line: 42, CWE: "CWE-89", Severity: SeverityHigh, Message: "SQL injection", Remediation: "Use parameterized queries"},
		{Tool: "gosec", File: "main.go", Line: 100, CWE: "CWE-327", Severity: SeverityMedium, Message: "Weak crypto"},
	}

	deduped, meta := Deduplicate(findings)

	if meta.RawCount != 3 {
		t.Fatalf("expected raw count 3, got %d", meta.RawCount)
	}
	if meta.AfterDedup != 2 {
		t.Fatalf("expected 2 after dedup, got %d", meta.AfterDedup)
	}
	if meta.DupesRemoved != 1 {
		t.Fatalf("expected 1 dupe removed, got %d", meta.DupesRemoved)
	}

	// The finding with remediation should be kept (higher field score)
	for _, f := range deduped {
		if f.File == "main.go" && f.Line == 42 {
			if f.Remediation == "" {
				t.Fatal("expected the finding with remediation to be kept")
			}
			if len(f.DuplicateOf) != 1 {
				t.Fatalf("expected 1 duplicate reference, got %d", len(f.DuplicateOf))
			}
		}
	}

	// Results should be sorted by severity desc
	if deduped[0].Severity != SeverityHigh {
		t.Fatalf("expected first finding to be HIGH, got %s", deduped[0].Severity)
	}
}

func TestDeduplicateNoDuplicates(t *testing.T) {
	findings := []Finding{
		{Tool: "gosec", File: "a.go", Line: 1, CWE: "CWE-89", Severity: SeverityHigh, Message: "issue 1"},
		{Tool: "gosec", File: "b.go", Line: 2, CWE: "CWE-79", Severity: SeverityMedium, Message: "issue 2"},
	}

	deduped, meta := Deduplicate(findings)

	if meta.DupesRemoved != 0 {
		t.Fatalf("expected 0 dupes removed, got %d", meta.DupesRemoved)
	}
	if len(deduped) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(deduped))
	}
}

func TestConvertFromLegacy(t *testing.T) {
	legacy := map[string]interface{}{
		"security_issues": []interface{}{
			map[string]interface{}{
				"path":     "main.go",
				"line":     float64(42),
				"severity": "HIGH",
				"message":  "SQL injection found",
				"cwe":      "CWE-89",
				"tool":     "gosec",
			},
		},
		"complex_functions": []interface{}{
			map[string]interface{}{
				"path":     "handler.go",
				"line":     float64(10),
				"severity": "MEDIUM",
				"message":  "High complexity",
				"tool":     "gocyclo",
			},
		},
	}

	findings := ConvertFromLegacy(legacy)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding
	found := false
	for _, f := range findings {
		if f.Category == "security_issues" && f.File == "main.go" {
			found = true
			if f.Line != 42 {
				t.Fatalf("expected line 42, got %d", f.Line)
			}
			if f.Severity != SeverityHigh {
				t.Fatalf("expected HIGH severity, got %s", f.Severity)
			}
			if f.CWE != "CWE-89" {
				t.Fatalf("expected CWE-89, got %s", f.CWE)
			}
			if f.ID == "" {
				t.Fatal("expected non-empty ID after conversion")
			}
		}
	}
	if !found {
		t.Fatal("expected to find security_issues finding")
	}
}

func TestConvertToLegacy(t *testing.T) {
	findings := []Finding{
		{ID: "abc", Tool: "gosec", Category: "security_issues", File: "main.go", Line: 42, Severity: SeverityHigh, Message: "SQL injection", CWE: "CWE-89"},
	}

	legacy := ConvertToLegacy(findings)
	issues, ok := legacy["security_issues"].([]interface{})
	if !ok {
		t.Fatal("expected security_issues key")
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}

	m := issues[0].(map[string]interface{})
	if m["path"] != "main.go" {
		t.Fatalf("expected main.go, got %v", m["path"])
	}
}
