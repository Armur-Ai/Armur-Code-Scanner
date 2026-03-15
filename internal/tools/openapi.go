package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RunOpenAPIScan scans an OpenAPI/Swagger specification for security issues.
func RunOpenAPIScan(dirPath string) (map[string]interface{}, error) {
	// Find OpenAPI spec files
	specFiles := []string{
		"openapi.yaml", "openapi.yml", "openapi.json",
		"swagger.yaml", "swagger.yml", "swagger.json",
		"api-docs.json",
	}

	var specPath string
	for _, name := range specFiles {
		candidate := filepath.Join(dirPath, name)
		if _, err := os.Stat(candidate); err == nil {
			specPath = candidate
			break
		}
	}

	if specPath == "" {
		return map[string]interface{}{"api_security": []interface{}{}}, nil
	}

	data, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAPI spec: %w", err)
	}

	// Parse as JSON (simplified — a full implementation would also handle YAML)
	var spec map[string]interface{}
	if err := json.Unmarshal(data, &spec); err != nil {
		// Try treating as YAML-like (just check for key patterns in text)
		return checkOpenAPIText(string(data), specPath)
	}

	return checkOpenAPIJSON(spec, specPath)
}

func checkOpenAPIJSON(spec map[string]interface{}, specPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	// Check for missing global security schemes
	if _, ok := spec["components"].(map[string]interface{}); ok {
		components := spec["components"].(map[string]interface{})
		if _, ok := components["securitySchemes"]; !ok {
			findings = append(findings, map[string]interface{}{
				"path":     specPath,
				"line":     0,
				"severity": "HIGH",
				"message":  "No securitySchemes defined — API may lack authentication",
				"tool":     "openapi-scan",
				"cwe":      "CWE-306",
			})
		}
	}

	// Check servers for HTTP instead of HTTPS
	if servers, ok := spec["servers"].([]interface{}); ok {
		for _, s := range servers {
			if sm, ok := s.(map[string]interface{}); ok {
				if url, ok := sm["url"].(string); ok {
					if strings.HasPrefix(url, "http://") && !strings.Contains(url, "localhost") {
						findings = append(findings, map[string]interface{}{
							"path":     specPath,
							"line":     0,
							"severity": "HIGH",
							"message":  fmt.Sprintf("Server URL uses HTTP instead of HTTPS: %s", url),
							"tool":     "openapi-scan",
							"cwe":      "CWE-319",
						})
					}
				}
			}
		}
	}

	// Check paths for missing security
	if paths, ok := spec["paths"].(map[string]interface{}); ok {
		for path, methods := range paths {
			if methodMap, ok := methods.(map[string]interface{}); ok {
				for method, operation := range methodMap {
					if opMap, ok := operation.(map[string]interface{}); ok {
						if _, hasSecurity := opMap["security"]; !hasSecurity {
							// Check global security
							if _, hasGlobal := spec["security"]; !hasGlobal {
								findings = append(findings, map[string]interface{}{
									"path":     specPath,
									"line":     0,
									"severity": "MEDIUM",
									"message":  fmt.Sprintf("No security defined for %s %s", strings.ToUpper(method), path),
									"tool":     "openapi-scan",
									"cwe":      "CWE-306",
								})
							}
						}
					}
				}
			}
		}
	}

	return map[string]interface{}{"api_security": findings}, nil
}

func checkOpenAPIText(content, specPath string) (map[string]interface{}, error) {
	findings := []interface{}{}

	if !strings.Contains(content, "securitySchemes") && !strings.Contains(content, "security_schemes") {
		findings = append(findings, map[string]interface{}{
			"path":     specPath,
			"line":     0,
			"severity": "HIGH",
			"message":  "No securitySchemes defined in OpenAPI spec",
			"tool":     "openapi-scan",
			"cwe":      "CWE-306",
		})
	}

	if strings.Contains(content, "http://") && !strings.Contains(content, "localhost") {
		findings = append(findings, map[string]interface{}{
			"path":     specPath,
			"line":     0,
			"severity": "MEDIUM",
			"message":  "HTTP URLs detected in OpenAPI spec (should use HTTPS)",
			"tool":     "openapi-scan",
			"cwe":      "CWE-319",
		})
	}

	return map[string]interface{}{"api_security": findings}, nil
}
