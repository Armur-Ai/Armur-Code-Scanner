package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
)

// RunSpotBugs runs SpotBugs on a compiled Java project and returns findings.
// It expects the project to have a build output at target/ or build/classes/.
func RunSpotBugs(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "spotbugs").Str("dir", directory).Msg("running")

	cmd := exec.Command("spotbugs", "-textui", "-xml", directory)
	cmd.Dir = directory

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Run()

	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		logger.Debug().Str("tool", "spotbugs").Msg("no output")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), nil
	}

	categorized := categorizeSpotBugsResults(output, directory)
	return utils.ConvertCategorizedResults(categorized), nil
}

// spotBugsXML mirrors the SpotBugs XML output structure.
type spotBugsXML struct {
	BugInstances []struct {
		Type     string `xml:"type,attr"`
		Priority int    `xml:"priority,attr"`
		Category string `xml:"category,attr"`
		Class    []struct {
			SourceLine *struct {
				SourcePath string `xml:"sourcepath,attr"`
				Start      int    `xml:"start,attr"`
				End        int    `xml:"end,attr"`
			} `xml:"SourceLine"`
		} `xml:"Class"`
		ShortMessage string `xml:"ShortMessage"`
		LongMessage  string `xml:"LongMessage"`
	} `xml:"BugInstance"`
}

func categorizeSpotBugsResults(raw, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	var result spotBugsXML
	if err := xml.Unmarshal([]byte(raw), &result); err != nil {
		logger.Error().Str("tool", "spotbugs").Err(err).Msg("failed to parse XML output")
		return categorized
	}

	priorityToSeverity := map[int]string{
		1: "HIGH",
		2: "MEDIUM",
		3: "LOW",
	}

	for _, bug := range result.BugInstances {
		filePath := ""
		lineNum := 0
		endLine := 0
		if len(bug.Class) > 0 && bug.Class[0].SourceLine != nil {
			filePath = strings.TrimPrefix(bug.Class[0].SourceLine.SourcePath, directory)
			lineNum = bug.Class[0].SourceLine.Start
			endLine = bug.Class[0].SourceLine.End
		}

		severity := priorityToSeverity[bug.Priority]
		if severity == "" {
			severity = "LOW"
		}

		msg := bug.LongMessage
		if msg == "" {
			msg = bug.ShortMessage
		}

		finding := map[string]interface{}{
			"path":       filePath,
			"line":       lineNum,
			"message":    msg,
			"severity":   severity,
			"check_id":   bug.Type,
			"confidence": "MEDIUM",
			"likelihood": "MEDIUM",
			"cwe":        []string{fmt.Sprintf("CWE-SpotBugs-%s", bug.Category)},
			"owasp":      []string{},
			"endLine":    endLine,
		}
		categorized[SECURITY_ISSUES] = append(categorized[SECURITY_ISSUES], finding)
	}

	return categorized
}
