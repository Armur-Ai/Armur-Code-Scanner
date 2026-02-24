package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func RunStaticCheck(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "staticcheck").Str("dir", directory).Msg("running")
	staticcheckResults, err := RunStaticcheckOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "staticcheck").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitCategorizedResults()), err
	}
	newcategorisedresult := CategorizeStaticcheckResults(staticcheckResults, directory)
	return utils.ConvertCategorizedResults(newcategorisedresult), nil
}

func RunStaticcheckOnRepo(directory string) (string, error) {
	var cmd *exec.Cmd

	if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
		cmd = exec.Command("staticcheck", "-f", "json", "./...")
		cmd.Dir = directory
	} else {
		files := []string{}
		err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(info.Name(), ".go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		cmd = exec.Command("staticcheck", "-f", "json")
		cmd.Args = append(cmd.Args, files...)
		cmd.Dir = directory
	}

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	cmd.Run()
	return strings.TrimSpace(out.String()), nil
}

func CategorizeStaticcheckResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitCategorizedResults()

	if results == "" {
		logger.Debug().Str("tool", "staticcheck").Msg("no results found")
		return categorizedResults
	}

	issues := strings.Split(results, "\n")
	for _, issue := range issues {
		issue = strings.TrimSpace(issue)
		if issue == "" {
			continue
		}

		var jsonIssue map[string]interface{}
		err := json.Unmarshal([]byte(issue), &jsonIssue)
		if err != nil {
			logger.Debug().Str("tool", "staticcheck").Err(err).Msg("failed to parse issue JSON, skipping")
			continue
		}

		code, ok := jsonIssue["code"].(string)
		if !ok {
			logger.Debug().Str("tool", "staticcheck").Msgf("invalid issue code: %+v", jsonIssue)
			continue
		}
		if strings.HasPrefix(code, "ST") {
			categorizedResults[utils.DOCKSTRING_ABSENT] = append(categorizedResults[utils.DOCKSTRING_ABSENT], FormatIssueForStatic(jsonIssue, directory))
		} else if strings.HasPrefix(code, "SA2") || strings.HasPrefix(code, "SA1") {
			categorizedResults[utils.COMPLEX_FUNCTIONS] = append(categorizedResults[utils.COMPLEX_FUNCTIONS], FormatIssueForStatic(jsonIssue, directory))
		} else {
			logger.Debug().Str("tool", "staticcheck").Msgf("unmatched issue code: %s", code)
		}
	}

	return categorizedResults
}

func FormatIssueForStatic(issue map[string]interface{}, directory string) map[string]interface{} {
	location, ok := issue["location"].(map[string]interface{})
	if !ok {
		logger.Debug().Str("tool", "staticcheck").Msgf("invalid issue location: %+v", issue)
		return nil
	}

	filePath, _ := location["file"].(string)
	line, _ := location["line"].(float64)
	column, _ := location["column"].(float64)
	message, _ := issue["message"].(string)

	filePath = strings.Replace(filePath, directory, "", 1)

	return map[string]interface{}{
		"path":    filePath,
		"line":    int(line),
		"column":  int(column),
		"message": message,
	}
}
