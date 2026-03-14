package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunKubeLinter runs kube-linter on a directory containing Kubernetes manifests.
func RunKubeLinter(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "kube-linter").Str("dir", directory).Msg("running")

	cmd := exec.Command("kube-linter", "lint", "--format", "json", directory)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "kube-linter").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeKubeLinterResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

func categorizeKubeLinterResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report struct {
		Reports []struct {
			Check    string `json:"check"`
			Remediation string `json:"remediation"`
			Object   struct {
				K8sObject struct {
					GroupVersionKind struct {
						Kind string `json:"Kind"`
					} `json:"groupVersionKind"`
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"k8sObject"`
				Metadata struct {
					FilePath string `json:"filePath"`
				} `json:"metadata"`
			} `json:"object"`
			Diagnostic struct {
				Message string `json:"message"`
			} `json:"diagnostic"`
		} `json:"reports"`
	}

	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "kube-linter").Err(err).Msg("failed to parse JSON output")
		return categorized
	}

	for _, r := range report.Reports {
		filePath := strings.TrimPrefix(r.Object.Metadata.FilePath, directory)
		msg := r.Diagnostic.Message
		if r.Remediation != "" {
			msg += " | Remediation: " + r.Remediation
		}
		finding := map[string]interface{}{
			"path":       filePath,
			"line":       0,
			"message":    msg,
			"severity":   "MEDIUM",
			"check_id":   r.Check,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    0,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
