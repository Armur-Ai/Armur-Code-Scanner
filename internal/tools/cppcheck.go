package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/xml"
	"os/exec"
	"strings"
)

// RunCppcheck runs cppcheck on a C/C++ project directory.
func RunCppcheck(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "cppcheck").Str("dir", directory).Msg("running")

	cmd := exec.Command("cppcheck",
		"--enable=all",
		"--xml",
		"--xml-version=2",
		"--quiet",
		directory,
	)
	// cppcheck writes XML to stderr by default
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stderr.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "cppcheck").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeCppcheckResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

type cppcheckXML struct {
	Errors []struct {
		ID       string `xml:"id,attr"`
		Severity string `xml:"severity,attr"`
		Msg      string `xml:"msg,attr"`
		Verbose  string `xml:"verbose,attr"`
		Location []struct {
			File   string `xml:"file,attr"`
			Line   int    `xml:"line,attr"`
			Column int    `xml:"column,attr"`
		} `xml:"location"`
	} `xml:"errors>error"`
}

func categorizeCppcheckResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var report cppcheckXML
	if err := xml.Unmarshal([]byte(raw), &report); err != nil {
		logger.Error().Str("tool", "cppcheck").Err(err).Msg("failed to parse XML output")
		return categorized
	}

	severityMap := map[string]string{
		"error":   "HIGH",
		"warning": "MEDIUM",
		"style":   "LOW",
		"performance": "LOW",
		"portability": "LOW",
		"information": "INFO",
	}

	for _, e := range report.Errors {
		if e.ID == "missingInclude" || e.ID == "noExplicitConstructor" {
			continue // skip noise
		}

		filePath := ""
		lineNum := 0
		if len(e.Location) > 0 {
			filePath = strings.TrimPrefix(e.Location[0].File, directory)
			lineNum = e.Location[0].Line
		}

		severity := severityMap[e.Severity]
		if severity == "" {
			severity = "LOW"
		}

		msg := e.Verbose
		if msg == "" {
			msg = e.Msg
		}

		finding := map[string]interface{}{
			"path":       filePath,
			"line":       lineNum,
			"message":    msg,
			"severity":   severity,
			"check_id":   e.ID,
			"confidence": "HIGH",
			"likelihood": "MEDIUM",
			"cwe":        []string{},
			"owasp":      []string{},
			"endLine":    lineNum,
		}

		if e.Severity == "error" {
			categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
		} else {
			categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], finding)
		}
	}

	return categorized
}
