package internal

import (
	"testing"
)

// --- hadolint ---

func TestRunHadolint_EmptyDir(t *testing.T) {
	result, err := RunHadolint(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeHadolintResults_Empty(t *testing.T) {
	r := categorizeHadolintResults("[]", "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

func TestCategorizeHadolintResults_WithFinding(t *testing.T) {
	raw := `[{"file":"/repo/Dockerfile","line":3,"code":"DL3008","level":"warning","message":"Pin versions in apt get install"}]`
	r := categorizeHadolintResults(raw, "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 1 {
		t.Fatalf("expected 1 bug, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
	bug := r[ANTIPATTERNS_BUGS][0].(map[string]interface{})
	if bug["check_id"] != "DL3008" {
		t.Errorf("unexpected check_id: %v", bug["check_id"])
	}
	if bug["severity"] != "MEDIUM" {
		t.Errorf("expected MEDIUM severity for warning, got %v", bug["severity"])
	}
}

func TestCategorizeHadolintResults_InvalidJSON(t *testing.T) {
	r := categorizeHadolintResults("not json", "/repo")
	if len(r[ANTIPATTERNS_BUGS]) != 0 {
		t.Errorf("expected 0 bugs on parse error, got %d", len(r[ANTIPATTERNS_BUGS]))
	}
}

// --- tfsec ---

func TestRunTfsec_EmptyDir(t *testing.T) {
	result, err := RunTfsec(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeTfsecResults_Empty(t *testing.T) {
	r := categorizeTfsecResults(`{"results":[]}`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeTfsecResults_WithFinding(t *testing.T) {
	raw := `{"results":[{"rule_id":"aws-s3-enable-bucket-encryption","description":"S3 bucket not encrypted","severity":"HIGH","location":{"filename":"/repo/main.tf","start_line":5,"end_line":10},"links":["https://cwe.mitre.org/data/definitions/311.html"]}]}`
	r := categorizeTfsecResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH, got %v", issue["severity"])
	}
}

// --- KICS ---

func TestRunKICS_EmptyDir(t *testing.T) {
	result, err := RunKICS(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeKICSResults_Empty(t *testing.T) {
	r := categorizeKICSResults(`{"queries":[]}`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeKICSResults_WithFinding(t *testing.T) {
	raw := `{"queries":[{"query_name":"Container Is Privileged","severity":"HIGH","platform":"Kubernetes","files":[{"file_name":"/repo/deploy.yaml","line":15,"issue_type":"IncorrectValue","search_key":"privileged","expected_value":"false","actual_value":"true","similarity_id":"abc"}]}]}`
	r := categorizeKICSResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
}

// --- kube-linter ---

func TestRunKubeLinter_EmptyDir(t *testing.T) {
	result, err := RunKubeLinter(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeKubeLinterResults_Empty(t *testing.T) {
	r := categorizeKubeLinterResults(`{"reports":[]}`, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeKubeLinterResults_WithFinding(t *testing.T) {
	raw := `{"reports":[{"check":"no-read-only-root-fs","remediation":"Set readOnlyRootFilesystem to true","object":{"k8sObject":{"groupVersionKind":{"Kind":"Deployment"},"name":"my-app","namespace":"default"},"metadata":{"filePath":"/repo/deploy.yaml"}},"diagnostic":{"message":"Container has no read-only root filesystem"}}]}`
	r := categorizeKubeLinterResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
}

// --- kube-score ---

func TestRunKubeScore_EmptyDir(t *testing.T) {
	result, err := RunKubeScore(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestCategorizeKubeScoreResults_Empty(t *testing.T) {
	r := categorizeKubeScoreResults("[]", "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeKubeScoreResults_PassingCheck(t *testing.T) {
	raw := `[{"object_name":"my-app","file_name":"/repo/deploy.yaml","checks":[{"check":{"name":"Container Security Context"},"grade":10,"comments":[]}]}]`
	r := categorizeKubeScoreResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 0 {
		t.Errorf("expected 0 issues for passing check, got %d", len(r[SECURITY_ISSUES]))
	}
}

func TestCategorizeKubeScoreResults_FailingCheck(t *testing.T) {
	raw := `[{"object_name":"my-app","file_name":"/repo/deploy.yaml","checks":[{"check":{"name":"Container Resources"},"grade":1,"comments":[{"path":"spec.containers[0].resources","summary":"CPU limit not set","description":"Set a CPU limit to prevent resource exhaustion"}]}]}]`
	r := categorizeKubeScoreResults(raw, "/repo")
	if len(r[SECURITY_ISSUES]) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(r[SECURITY_ISSUES]))
	}
	issue := r[SECURITY_ISSUES][0].(map[string]interface{})
	if issue["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity for grade 1, got %v", issue["severity"])
	}
}
