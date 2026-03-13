package sarif

import (
	"encoding/json"
	"testing"
)

func TestFromScanResults_Empty(t *testing.T) {
	log := FromScanResults(map[string]interface{}{}, "1.0.0")
	if log == nil {
		t.Fatal("expected non-nil SARIF log")
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results for empty input, got %d", len(log.Runs[0].Results))
	}
}

func TestFromScanResults_WithSecurityIssues(t *testing.T) {
	results := map[string]interface{}{
		"security_issues": []interface{}{
			map[string]interface{}{
				"cwe": "CWE-89",
				"files": []interface{}{
					map[string]interface{}{
						"path": "main.go",
						"issues": []interface{}{
							map[string]interface{}{
								"line":     float64(42),
								"column":   float64(10),
								"message":  "SQL injection vulnerability",
								"severity": "HIGH",
							},
						},
					},
				},
			},
		},
	}

	log := FromScanResults(results, "1.0.0")
	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(log.Runs[0].Results))
	}

	r := log.Runs[0].Results[0]
	if r.RuleID != "CWE-89" {
		t.Errorf("expected ruleId CWE-89, got %q", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level 'error' for HIGH severity, got %q", r.Level)
	}
	if r.Message.Text != "SQL injection vulnerability" {
		t.Errorf("unexpected message: %q", r.Message.Text)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	loc := r.Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != "main.go" {
		t.Errorf("unexpected URI: %q", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if loc.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("unexpected StartLine: %d", loc.PhysicalLocation.Region.StartLine)
	}
}

func TestFromScanResults_RuleDeduplication(t *testing.T) {
	results := map[string]interface{}{
		"security_issues": []interface{}{
			map[string]interface{}{
				"cwe": "CWE-89",
				"files": []interface{}{
					map[string]interface{}{
						"path": "a.go",
						"issues": []interface{}{
							map[string]interface{}{"message": "issue1", "severity": "high"},
						},
					},
				},
			},
			map[string]interface{}{
				"cwe": "CWE-89",
				"files": []interface{}{
					map[string]interface{}{
						"path": "b.go",
						"issues": []interface{}{
							map[string]interface{}{"message": "issue2", "severity": "high"},
						},
					},
				},
			},
		},
	}

	log := FromScanResults(results, "1.0.0")
	// Two results but only one unique rule.
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("expected 1 unique rule, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct{ in, want string }{
		{"CRITICAL", "error"},
		{"HIGH", "error"},
		{"MEDIUM", "warning"},
		{"LOW", "note"},
		{"INFO", "note"},
		{"", "warning"},
		{"unknown-sev", "warning"},
	}
	for _, tt := range tests {
		got := severityToLevel(tt.in)
		if got != tt.want {
			t.Errorf("severityToLevel(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMarshal_ValidJSON(t *testing.T) {
	log := FromScanResults(map[string]interface{}{}, "1.0.0")
	data, err := log.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0 in JSON, got %v", decoded["version"])
	}
}
