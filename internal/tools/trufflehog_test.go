package internal

import (
	"testing"

	utils "armur-codescanner/pkg"
)

func TestCategorizeTrufflehogResults_Empty(t *testing.T) {
	result := categorizeTrufflehogResults("", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for empty input")
	}
	if len(result[utils.SECRET_DETECTION]) != 0 {
		t.Errorf("expected 0 secret detections for empty input, got %d", len(result[utils.SECRET_DETECTION]))
	}
}

func TestCategorizeTrufflehogResults_InvalidJSON(t *testing.T) {
	result := categorizeTrufflehogResults("{bad json}", "/tmp/test")
	if result == nil {
		t.Fatal("expected non-nil result for invalid JSON")
	}
	if len(result[utils.SECRET_DETECTION]) != 0 {
		t.Errorf("expected 0 secret detections for invalid JSON, got %d", len(result[utils.SECRET_DETECTION]))
	}
}

func TestCategorizeTrufflehogResults_WithSecret(t *testing.T) {
	input := `[
		{
			"path": "/tmp/test/config.py",
			"line": 15,
			"rule": {
				"message": "AWS Access Key",
				"severity": "HIGH"
			},
			"secret": "AKIAIOSFODNN7EXAMPLE"
		}
	]`
	result := categorizeTrufflehogResults(input, "/tmp/test")
	if len(result[utils.SECRET_DETECTION]) != 1 {
		t.Errorf("expected 1 secret detection, got %d", len(result[utils.SECRET_DETECTION]))
	}
	entry := result[utils.SECRET_DETECTION][0].(map[string]interface{})
	if entry["message"] != "AWS Access Key" {
		t.Errorf("expected message 'AWS Access Key', got %v", entry["message"])
	}
}

func TestCategorizeTrufflehogResults_MultipleSecrets(t *testing.T) {
	input := `[
		{
			"path": "/tmp/test/a.py",
			"line": 1,
			"rule": {"message": "API Key", "severity": "HIGH"},
			"secret": "secret1"
		},
		{
			"path": "/tmp/test/b.py",
			"line": 5,
			"rule": {"message": "Private Key", "severity": "CRITICAL"},
			"secret": "secret2"
		}
	]`
	result := categorizeTrufflehogResults(input, "/tmp/test")
	if len(result[utils.SECRET_DETECTION]) != 2 {
		t.Errorf("expected 2 secret detections, got %d", len(result[utils.SECRET_DETECTION]))
	}
}

func TestFormatSecretIssue(t *testing.T) {
	secret := Secret{
		Path: "/tmp/test/config.py",
		Line: 10,
		Rule: struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
		}{
			Message:  "API Token",
			Severity: "HIGH",
		},
		Secret: "tok-xxxxx",
	}
	result := formatSecretIssue(secret, "/tmp/test")
	if result["message"] != "API Token" {
		t.Errorf("expected message 'API Token', got %v", result["message"])
	}
	if result["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", result["severity"])
	}
	if result["secret"] != "tok-xxxxx" {
		t.Errorf("expected secret value, got %v", result["secret"])
	}
}
