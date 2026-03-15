package internal

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

// RunGovulncheck runs the official Go vulnerability checker with call graph analysis.
func RunGovulncheck(dirPath string) (map[string]interface{}, error) {
	cmd := exec.Command("govulncheck", "-json", "./...")
	cmd.Dir = dirPath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("govulncheck error: %w", err)
	}

	return parseGovulncheckOutput(output)
}

func parseGovulncheckOutput(output []byte) (map[string]interface{}, error) {
	findings := []interface{}{}

	// govulncheck outputs newline-delimited JSON messages
	decoder := json.NewDecoder(jsonReader(output))
	for decoder.More() {
		var msg map[string]interface{}
		if err := decoder.Decode(&msg); err != nil {
			break
		}

		// Look for "finding" messages
		if finding, ok := msg["finding"].(map[string]interface{}); ok {
			osv, _ := finding["osv"].(string)

			// Check if the vulnerability is reachable (has trace)
			reachable := false
			if trace, ok := finding["trace"].([]interface{}); ok && len(trace) > 0 {
				reachable = true
			}

			severity := "HIGH"
			if reachable {
				severity = "CRITICAL"
			}

			reachableStr := "unknown"
			if reachable {
				reachableStr = "yes (reachable in call graph)"
			} else {
				reachableStr = "no (not called)"
			}

			findings = append(findings, map[string]interface{}{
				"path":     "go.mod",
				"line":     0,
				"severity": severity,
				"message":  fmt.Sprintf("%s — reachable: %s", osv, reachableStr),
				"cwe":      osv,
				"tool":     "govulncheck",
			})
		}
	}

	return map[string]interface{}{"sca": findings}, nil
}

// jsonReader creates a bytes reader from output that handles NDJSON.
type ndjsonReader struct {
	data []byte
	pos  int
}

func jsonReader(data []byte) *ndjsonReader {
	return &ndjsonReader{data: data}
}

func (r *ndjsonReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
