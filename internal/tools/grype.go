package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// RunGrype runs Grype vulnerability scanner on a container image or directory.
func RunGrype(target string) (map[string]interface{}, error) {
	cmd := exec.Command("grype", target, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// Grype exits 1 when vulns found
		} else {
			return nil, fmt.Errorf("grype error: %w", err)
		}
	}

	return parseGrypeOutput(output)
}

// RunTrivyImage runs Trivy on a container image.
func RunTrivyImage(imageRef string) (map[string]interface{}, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", imageRef)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy image error: %w", err)
	}

	return parseTrivyImageOutput(output)
}

func parseGrypeOutput(output []byte) (map[string]interface{}, error) {
	var result struct {
		Matches []struct {
			Vulnerability struct {
				ID          string   `json:"id"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				Fix         struct {
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
				PURL    string `json:"purl"`
			} `json:"artifact"`
		} `json:"matches"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return map[string]interface{}{"sca": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, m := range result.Matches {
		fixVer := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixVer = fmt.Sprintf(" → Fix: %s", m.Vulnerability.Fix.Versions[0])
		}

		desc := m.Vulnerability.Description
		if len(desc) > 120 {
			desc = desc[:117] + "..."
		}

		findings = append(findings, map[string]interface{}{
			"path":     fmt.Sprintf("%s@%s", m.Artifact.Name, m.Artifact.Version),
			"line":     0,
			"severity": strings.ToUpper(m.Vulnerability.Severity),
			"message":  fmt.Sprintf("%s: %s%s", m.Vulnerability.ID, desc, fixVer),
			"cwe":      m.Vulnerability.ID,
			"tool":     "grype",
		})
	}

	return map[string]interface{}{"sca": findings}, nil
}

func parseTrivyImageOutput(output []byte) (map[string]interface{}, error) {
	var result struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				PkgName         string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion    string `json:"FixedVersion"`
				Severity        string `json:"Severity"`
				Title           string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return map[string]interface{}{"sca": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			fixInfo := ""
			if v.FixedVersion != "" {
				fixInfo = fmt.Sprintf(" → Fix: %s", v.FixedVersion)
			}

			findings = append(findings, map[string]interface{}{
				"path":     fmt.Sprintf("%s (%s@%s)", r.Target, v.PkgName, v.InstalledVersion),
				"line":     0,
				"severity": strings.ToUpper(v.Severity),
				"message":  fmt.Sprintf("%s: %s%s", v.VulnerabilityID, v.Title, fixInfo),
				"cwe":      v.VulnerabilityID,
				"tool":     "trivy-image",
			})
		}
	}

	return map[string]interface{}{"sca": findings}, nil
}
