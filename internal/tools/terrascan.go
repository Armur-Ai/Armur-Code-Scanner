package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// RunTerrascan runs the multi-cloud IaC security scanner.
func RunTerrascan(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("terrascan", "scan", "-i", "terraform", "-d", dirPath, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() <= 4 {
				// Terrascan exits non-zero when violations found
			} else {
				return nil, fmt.Errorf("terrascan error: %w", err)
			}
		}
	}

	return parseTerrascanOutput(output)
}

func parseTerrascanOutput(output []byte) (map[string]interface{}, error) {
	var result struct {
		Results struct {
			Violations []struct {
				RuleName    string `json:"rule_name"`
				Description string `json:"description"`
				RuleID      string `json:"rule_id"`
				Severity    string `json:"severity"`
				Category    string `json:"category"`
				File        string `json:"file"`
				Line        int    `json:"line"`
			} `json:"violations"`
		} `json:"results"`
	}

	if err := json.Unmarshal(output, &result); err != nil {
		return map[string]interface{}{"infra_security": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, v := range result.Results.Violations {
		findings = append(findings, map[string]interface{}{
			"path":     v.File,
			"line":     v.Line,
			"severity": mapTerrascanSeverity(v.Severity),
			"message":  fmt.Sprintf("[%s] %s: %s", v.Category, v.RuleName, v.Description),
			"rule_id":  v.RuleID,
			"tool":     "terrascan",
		})
	}

	return map[string]interface{}{"infra_security": findings}, nil
}

func mapTerrascanSeverity(sev string) string {
	switch sev {
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// RunKubesec runs kubesec risk scoring on Kubernetes manifests.
func RunKubesec(filePath string) (map[string]interface{}, error) {
	cmd := exec.Command("kubesec", "scan", filePath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("kubesec error: %w", err)
	}

	var results []struct {
		Scoring struct {
			Critical []struct {
				ID       string `json:"id"`
				Selector string `json:"selector"`
				Reason   string `json:"reason"`
			} `json:"critical"`
			Advise []struct {
				ID       string `json:"id"`
				Selector string `json:"selector"`
				Reason   string `json:"reason"`
			} `json:"advise"`
		} `json:"scoring"`
	}

	if err := json.Unmarshal(output, &results); err != nil {
		return map[string]interface{}{"infra_security": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, r := range results {
		for _, c := range r.Scoring.Critical {
			findings = append(findings, map[string]interface{}{
				"path":     filePath,
				"line":     0,
				"severity": "CRITICAL",
				"message":  fmt.Sprintf("[%s] %s", c.ID, c.Reason),
				"rule_id":  c.ID,
				"tool":     "kubesec",
			})
		}
		for _, a := range r.Scoring.Advise {
			findings = append(findings, map[string]interface{}{
				"path":     filePath,
				"line":     0,
				"severity": "MEDIUM",
				"message":  fmt.Sprintf("[%s] %s", a.ID, a.Reason),
				"rule_id":  a.ID,
				"tool":     "kubesec",
			})
		}
	}

	return map[string]interface{}{"infra_security": findings}, nil
}
