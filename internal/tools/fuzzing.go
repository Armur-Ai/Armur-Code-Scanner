package internal

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunGoFuzz runs Go's native fuzzing for a specified duration.
func RunGoFuzz(dirPath string, timeout time.Duration) (map[string]interface{}, error) {
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	cmd := exec.Command("go", "test", "-fuzz=Fuzz", fmt.Sprintf("-fuzztime=%s", timeout), "./...")
	cmd.Dir = dirPath

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	findings := []interface{}{}

	// Parse crashes from output
	if err != nil {
		scanner := bufio.NewScanner(strings.NewReader(outputStr))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "panic:") || strings.Contains(line, "FAIL") {
				findings = append(findings, map[string]interface{}{
					"path":     dirPath,
					"line":     0,
					"severity": "CRITICAL",
					"message":  fmt.Sprintf("Fuzz crash: %s", strings.TrimSpace(line)),
					"tool":     "go-fuzz",
				})
			}
		}
	}

	// Check for crash artifacts
	crashDir := filepath.Join(dirPath, "testdata", "fuzz")
	crashes, _ := filepath.Glob(filepath.Join(crashDir, "*", "*"))
	for _, crash := range crashes {
		if strings.Contains(crash, "corpus") {
			continue // Skip corpus, only report crashes
		}
		findings = append(findings, map[string]interface{}{
			"path":     crash,
			"line":     0,
			"severity": "CRITICAL",
			"message":  fmt.Sprintf("Fuzz crash artifact: %s", filepath.Base(crash)),
			"tool":     "go-fuzz",
		})
	}

	return map[string]interface{}{"fuzzing": findings}, nil
}

// RunAtheris runs Python Atheris fuzzer.
func RunAtheris(dirPath string, timeout time.Duration) (map[string]interface{}, error) {
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	// Look for existing fuzz targets
	targets, _ := filepath.Glob(filepath.Join(dirPath, "*fuzz*.py"))
	if len(targets) == 0 {
		return map[string]interface{}{"fuzzing": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, target := range targets {
		cmd := exec.Command("python3", "-m", "atheris",
			fmt.Sprintf("-runs=%d", int(timeout.Seconds())*100),
			target,
		)
		cmd.Dir = dirPath

		output, err := cmd.CombinedOutput()
		if err != nil {
			outputStr := string(output)
			if strings.Contains(outputStr, "Exception") || strings.Contains(outputStr, "Traceback") {
				findings = append(findings, map[string]interface{}{
					"path":     target,
					"line":     0,
					"severity": "HIGH",
					"message":  fmt.Sprintf("Python fuzz crash in %s", filepath.Base(target)),
					"tool":     "atheris",
				})
			}
		}
	}

	return map[string]interface{}{"fuzzing": findings}, nil
}

// RunJSFuzz runs JavaScript jsfuzz fuzzer.
func RunJSFuzz(dirPath string, timeout time.Duration) (map[string]interface{}, error) {
	targets, _ := filepath.Glob(filepath.Join(dirPath, "*fuzz*.js"))
	if len(targets) == 0 {
		return map[string]interface{}{"fuzzing": []interface{}{}}, nil
	}

	findings := []interface{}{}
	for _, target := range targets {
		cmd := exec.Command("jsfuzz", target, "--runs", "5000")
		cmd.Dir = dirPath

		output, err := cmd.CombinedOutput()
		if err != nil {
			outputStr := string(output)
			if strings.Contains(outputStr, "crash") || strings.Contains(outputStr, "Error") {
				findings = append(findings, map[string]interface{}{
					"path":     target,
					"line":     0,
					"severity": "HIGH",
					"message":  fmt.Sprintf("JS fuzz crash in %s", filepath.Base(target)),
					"tool":     "jsfuzz",
				})
			}
		}
	}

	return map[string]interface{}{"fuzzing": findings}, nil
}
