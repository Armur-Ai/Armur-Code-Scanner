package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DetectPackageEcosystem identifies which package ecosystems are present in a directory.
func DetectPackageEcosystem(dirPath string) []string {
	var ecosystems []string

	manifests := map[string]string{
		"package.json":     "npm",
		"package-lock.json": "npm",
		"yarn.lock":        "npm",
		"pnpm-lock.yaml":   "npm",
		"requirements.txt": "pip",
		"Pipfile.lock":     "pip",
		"poetry.lock":      "pip",
		"pyproject.toml":   "pip",
		"go.mod":           "go",
		"Cargo.lock":       "cargo",
		"Cargo.toml":       "cargo",
		"pom.xml":          "maven",
		"build.gradle":     "maven",
		"Gemfile.lock":     "rubygems",
		"composer.lock":    "composer",
		"pubspec.lock":     "pub",
		"mix.lock":         "hex",
	}

	seen := map[string]bool{}
	for file, eco := range manifests {
		if _, err := os.Stat(filepath.Join(dirPath, file)); err == nil {
			if !seen[eco] {
				ecosystems = append(ecosystems, eco)
				seen[eco] = true
			}
		}
	}

	return ecosystems
}

// RunNpmAudit runs npm audit and returns parsed findings.
func RunNpmAudit(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("npm", "audit", "--json")
	cmd.Dir = dirPath
	out, _ := cmd.Output() // npm audit exits non-zero when vulns found

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("npm audit parse error: %w", err)
	}

	return formatNpmAudit(result), nil
}

func formatNpmAudit(raw map[string]interface{}) map[string]interface{} {
	findings := []interface{}{}

	vulns, ok := raw["vulnerabilities"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{"sca": findings}
	}

	for pkg, data := range vulns {
		v, ok := data.(map[string]interface{})
		if !ok {
			continue
		}
		severity := "MEDIUM"
		if s, ok := v["severity"].(string); ok {
			severity = strings.ToUpper(s)
		}

		finding := map[string]interface{}{
			"path":     fmt.Sprintf("package.json → %s", pkg),
			"line":     0,
			"severity": severity,
			"message":  fmt.Sprintf("Vulnerable dependency: %s", pkg),
			"tool":     "npm-audit",
		}
		if via, ok := v["via"].([]interface{}); ok && len(via) > 0 {
			if viaMap, ok := via[0].(map[string]interface{}); ok {
				if title, ok := viaMap["title"].(string); ok {
					finding["message"] = fmt.Sprintf("%s: %s", pkg, title)
				}
				if url, ok := viaMap["url"].(string); ok {
					finding["cwe"] = url
				}
			}
		}
		findings = append(findings, finding)
	}

	return map[string]interface{}{"sca": findings}
}

// RunPipAudit runs pip-audit for Python dependency checking.
func RunPipAudit(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("pip-audit", "--format", "json", "--desc")
	cmd.Dir = dirPath
	out, err := cmd.Output()
	if err != nil {
		// pip-audit may not be installed
		return nil, fmt.Errorf("pip-audit not available: %w", err)
	}

	var vulns []map[string]interface{}
	if err := json.Unmarshal(out, &vulns); err != nil {
		return nil, fmt.Errorf("pip-audit parse error: %w", err)
	}

	findings := []interface{}{}
	for _, v := range vulns {
		name, _ := v["name"].(string)
		version, _ := v["version"].(string)
		vulnID, _ := v["id"].(string)
		desc, _ := v["description"].(string)
		fix, _ := v["fix_versions"].([]interface{})

		fixVer := ""
		if len(fix) > 0 {
			fixVer = fmt.Sprintf(" (fix: %v)", fix[0])
		}

		findings = append(findings, map[string]interface{}{
			"path":     fmt.Sprintf("requirements.txt → %s@%s", name, version),
			"line":     0,
			"severity": "HIGH",
			"message":  fmt.Sprintf("%s %s: %s%s", vulnID, name, truncate(desc, 80), fixVer),
			"cwe":      vulnID,
			"tool":     "pip-audit",
		})
	}

	return map[string]interface{}{"sca": findings}, nil
}

// RunCargoAuditSCA runs cargo-audit specifically for SCA (already exists as RunCargoAudit, this wraps it for SCA context).
func RunCargoAuditSCA(dirPath string) (map[string]interface{}, error) {
	return RunCargoAudit(dirPath)
}

// RunBundleAuditSCA runs bundle-audit for Ruby dependency checking.
func RunBundleAuditSCA(dirPath string) (map[string]interface{}, error) {
	return RunBundlerAudit(dirPath)
}

// RunComposerAudit runs the PHP security checker for Composer dependencies.
func RunComposerAudit(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("local-php-security-checker", "--format=json")
	cmd.Dir = dirPath
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("php security checker error: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, err
	}

	findings := []interface{}{}
	for pkg, data := range result {
		pkgData, ok := data.(map[string]interface{})
		if !ok {
			continue
		}
		advisories, ok := pkgData["advisories"].([]interface{})
		if !ok {
			continue
		}
		for _, adv := range advisories {
			advMap, ok := adv.(map[string]interface{})
			if !ok {
				continue
			}
			findings = append(findings, map[string]interface{}{
				"path":     fmt.Sprintf("composer.lock → %s", pkg),
				"line":     0,
				"severity": "HIGH",
				"message":  fmt.Sprintf("%s: %s", pkg, getString(advMap, "title")),
				"cwe":      getString(advMap, "cve"),
				"tool":     "composer-audit",
			})
		}
	}

	return map[string]interface{}{"sca": findings}, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
