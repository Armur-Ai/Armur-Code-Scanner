package internal

import (
	"fmt"
	"strings"
	"text/template"
	"bytes"
)

// SecurityTest represents a generated security test.
type SecurityTest struct {
	FindingID   string `json:"finding_id"`
	Language    string `json:"language"`
	TestName    string `json:"test_name"`
	TestCode    string `json:"test_code"`
	Description string `json:"description"`
}

// GenerateSecurityTests creates failing security tests from findings.
func GenerateSecurityTests(findings []map[string]string, language string) []SecurityTest {
	var tests []SecurityTest

	for _, f := range findings {
		cwe := f["cwe"]
		file := f["file"]
		message := f["message"]

		test := generateTestForCWE(cwe, language, file, message)
		if test != nil {
			tests = append(tests, *test)
		}
	}

	return tests
}

func generateTestForCWE(cwe, language, file, message string) *SecurityTest {
	switch cwe {
	case "CWE-89":
		return generateSQLiTest(language, file, message)
	case "CWE-79":
		return generateXSSTest(language, file, message)
	case "CWE-78":
		return generateCmdInjectionTest(language, file, message)
	case "CWE-22":
		return generatePathTraversalTest(language, file, message)
	default:
		return nil
	}
}

func generateSQLiTest(language, file, message string) *SecurityTest {
	switch language {
	case "go":
		return &SecurityTest{
			Language:    "go",
			TestName:    "TestSQLInjectionPrevention",
			Description: fmt.Sprintf("Regression test for SQL injection in %s", file),
			TestCode: renderTemplate(`func TestSQLInjectionPrevention(t *testing.T) {
	// This test verifies that SQL injection is not possible.
	// Finding: {{.Message}}
	// File: {{.File}}
	maliciousInputs := []string{
		"' OR '1'='1",
		"'; DROP TABLE users; --",
		"1 UNION SELECT * FROM passwords",
	}

	for _, input := range maliciousInputs {
		// TODO: Replace with actual function call from {{.File}}
		// result, err := QueryUser(input)
		// assert.NoError(t, err)
		// assert.NotContains(t, result, "admin")
		_ = input
	}
}`, map[string]string{"File": file, "Message": message}),
		}
	case "py":
		return &SecurityTest{
			Language:    "python",
			TestName:    "test_sql_injection_prevention",
			Description: fmt.Sprintf("Regression test for SQL injection in %s", file),
			TestCode: renderTemplate(`def test_sql_injection_prevention():
    """Regression test: {{.Message}} ({{.File}})"""
    malicious_inputs = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM passwords",
    ]
    for payload in malicious_inputs:
        # TODO: Replace with actual function call from {{.File}}
        # result = query_user(payload)
        # assert "admin" not in result
        pass
`, map[string]string{"File": file, "Message": message}),
		}
	default:
		return nil
	}
}

func generateXSSTest(language, file, message string) *SecurityTest {
	switch language {
	case "go":
		return &SecurityTest{
			Language:    "go",
			TestName:    "TestXSSPrevention",
			Description: fmt.Sprintf("Regression test for XSS in %s", file),
			TestCode: renderTemplate(`func TestXSSPrevention(t *testing.T) {
	// Finding: {{.Message}}
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
	}

	for _, payload := range xssPayloads {
		// TODO: Replace with actual render/handler call from {{.File}}
		// output := RenderUserInput(payload)
		// assert.NotContains(t, output, "<script>")
		_ = payload
	}
}`, map[string]string{"File": file, "Message": message}),
		}
	default:
		return nil
	}
}

func generateCmdInjectionTest(language, file, message string) *SecurityTest {
	return &SecurityTest{
		Language:    language,
		TestName:    "TestCommandInjectionPrevention",
		Description: fmt.Sprintf("Regression test for command injection in %s", file),
		TestCode: fmt.Sprintf("// TODO: Test that command injection payloads (;id, |whoami, $(cat /etc/passwd)) are rejected in %s", file),
	}
}

func generatePathTraversalTest(language, file, message string) *SecurityTest {
	return &SecurityTest{
		Language:    language,
		TestName:    "TestPathTraversalPrevention",
		Description: fmt.Sprintf("Regression test for path traversal in %s", file),
		TestCode: fmt.Sprintf("// TODO: Test that path traversal payloads (../../etc/passwd) are rejected in %s", file),
	}
}

func renderTemplate(tmplStr string, data map[string]string) string {
	tmpl, err := template.New("test").Parse(tmplStr)
	if err != nil {
		return tmplStr
	}
	var buf bytes.Buffer
	tmpl.Execute(&buf, data)
	result := buf.String()
	_ = strings.TrimSpace(result)
	return result
}
