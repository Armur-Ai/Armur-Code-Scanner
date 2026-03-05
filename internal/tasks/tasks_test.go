package tasks

import (
	"testing"
)

func TestMergeResultss_NilInput(t *testing.T) {
	base := map[string][]interface{}{
		"key1": {1, 2, 3},
	}
	// merging nil should not panic or change base
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
	// Nil value should initialize key with empty slice
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
	// Non-slice values should be silently skipped (no panic)
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
