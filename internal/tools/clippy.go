package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

// RunClippy runs cargo clippy (Rust linter) and returns findings.
func RunClippy(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "clippy").Str("dir", directory).Msg("running")

	// --message-format=json emits one JSON object per line
	cmd := exec.Command("cargo", "clippy", "--message-format=json", "--", "-D", "warnings")
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "clippy").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeClippyResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

type clippyMessage struct {
	Reason  string `json:"reason"`
	Message *struct {
		Message  string `json:"message"`
		Level    string `json:"level"`
		Code     *struct{ Code string `json:"code"` } `json:"code"`
		Spans    []struct {
			FileName string `json:"file_name"`
			LineStart int    `json:"line_start"`
			LineEnd   int    `json:"line_end"`
		} `json:"spans"`
	} `json:"message"`
}

func categorizeClippyResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var msg clippyMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg.Reason != "compiler-message" || msg.Message == nil {
			continue
		}
		if msg.Message.Level != "warning" && msg.Message.Level != "error" {
			continue
		}

		filePath := ""
		lineNum := 0
		endLine := 0
		if len(msg.Message.Spans) > 0 {
			filePath = strings.TrimPrefix(msg.Message.Spans[0].FileName, directory)
			lineNum = msg.Message.Spans[0].LineStart
			endLine = msg.Message.Spans[0].LineEnd
		}

		checkID := "CLIPPY"
		if msg.Message.Code != nil {
			checkID = msg.Message.Code.Code
		}

		severity := "LOW"
		if msg.Message.Level == "error" {
			severity = "HIGH"
		}

		finding := map[string]interface{}{
			"path":       filePath,
			"line":       lineNum,
			"message":    msg.Message.Message,
			"severity":   severity,
			"check_id":   checkID,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    endLine,
		}
		categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
	}

	return categorized
}
