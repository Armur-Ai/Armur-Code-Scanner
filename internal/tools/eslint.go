package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
)

type Issue struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Message string `json:"message"`
	RuleID  string `json:"ruleId,omitempty"`
}

func RunESLintAdvanced(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "eslint-advanced").Str("dir", directory).Msg("running")
	results, err := RunESLintAdvancedOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "eslint-advanced").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	return utils.ConvertCategorizedResults(results), nil
}

func RunESLintOnRepo(repoPath string) (map[string]interface{}, error) {
	categorizedResults := utils.InitCategorizedResults()

	logger.Info().Str("tool", "eslint-jsdoc").Str("dir", repoPath).Msg("running")
	docResults, err := RunESLint(repoPath, "eslint_jsdoc.config.js")
	if err != nil {
		logger.Warn().Str("tool", "eslint-jsdoc").Err(err).Msg("jsdoc check failed")
	} else {
		categorizedResults[DOCKSTRING_ABSENT] = FormatIssues(docResults, repoPath)
	}

	logger.Info().Str("tool", "eslint-security").Str("dir", repoPath).Msg("running")
	securityResults, err := RunESLint(repoPath, "eslint_security.config.js")
	if err != nil {
		logger.Warn().Str("tool", "eslint-security").Err(err).Msg("security check failed")
	} else {
		categorizedResults[SECURITY_ISSUES] = FormatIssues(securityResults, repoPath)
	}

	logger.Info().Str("tool", "eslint-complexity").Str("dir", repoPath).Msg("running")
	complexResults, err := RunESLint(repoPath, "eslint.config.js")
	if err != nil {
		logger.Warn().Str("tool", "eslint-complexity").Err(err).Msg("complexity check failed")
	} else {
		categorizedComplex := CategorizeESLintResults(complexResults, repoPath)
		categorizedResults[COMPLEX_FUNCTIONS] = categorizedComplex[COMPLEX_FUNCTIONS]
		categorizedResults[ANTIPATTERNS_BUGS] = categorizedComplex[ANTIPATTERNS_BUGS]
	}

	return utils.ConvertCategorizedResults(categorizedResults), nil
}

func RunESLintAdvancedOnRepo(repoPath string) (map[string][]interface{}, error) {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	cmd := exec.Command("eslint", "--format", "json", "--config", "eslint_deadcode.config.js", repoPath)
	output, err := cmd.Output()
	if err != nil {
		logger.Debug().Str("tool", "eslint-deadcode").Err(err).Msg("non-zero exit (may still have results)")
	}

	var eslintOutput []map[string]interface{}
	if err := json.Unmarshal(output, &eslintOutput); err != nil {
		return nil, err
	}

	categorized := CategorizeESLintAdvancedResults(eslintOutput, repoPath)
	categorizedResults[utils.DEAD_CODE] = categorized[utils.DEAD_CODE]

	return categorizedResults, nil
}

func CategorizeESLintAdvancedResults(eslintResults []map[string]interface{}, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	deadCodeESLintRuleIDs := []string{
		"no-unused-vars",
		"no-unreachable",
		"no-constant-condition",
		"no-unused-expressions",
		"no-unused-private-class-members",
		"no-useless-assignment",
	}

	if eslintResults != nil {
		for _, fileResult := range eslintResults {
			for _, message := range fileResult["messages"].([]interface{}) {
				msg := message.(map[string]interface{})
				if checkID, ok := msg["ruleId"].(string); ok {
					msg["check_id"] = checkID
					delete(msg, "ruleId")
					msg["file"] = strings.ReplaceAll(fileResult["filePath"].(string), directory, "")

					if contains(deadCodeESLintRuleIDs, checkID) {
						categorizedResults[utils.DEAD_CODE] = append(categorizedResults[utils.DEAD_CODE], msg)
					}
				}
			}
		}
	}
	return categorizedResults
}

func contains(slice []string, item string) bool {
	for _, val := range slice {
		if val == item {
			return true
		}
	}
	return false
}

func RunESLint(directory, configFile string) ([]map[string]interface{}, error) {
	cmd := exec.Command("eslint", "--format", "json", "--config", configFile, directory)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// ESLint exits non-zero when it finds issues; that's expected
		logger.Debug().Str("tool", "eslint").Str("config", configFile).Err(err).Msg("non-zero exit (may still have results)")
	}
	var results []map[string]interface{}
	err = json.Unmarshal(stdout.Bytes(), &results)
	if err != nil {
		logger.Error().Str("tool", "eslint").Str("config", configFile).Err(err).Msg("failed to parse results")
		return nil, err
	}

	return results, nil
}

func FormatIssues(issues []map[string]interface{}, directory string) []interface{} {
	var formattedIssues []interface{}
	for _, issue := range issues {
		filePath := strings.ReplaceAll(issue["filePath"].(string), directory, "")
		messages := issue["messages"].([]interface{})

		for _, msg := range messages {
			message := msg.(map[string]interface{})
			formattedIssues = append(formattedIssues, map[string]interface{}{
				"path":    filePath,
				"line":    int(message["line"].(float64)),
				"column":  int(message["column"].(float64)),
				"message": message["message"].(string),
				"ruleId":  message["ruleId"],
			})
		}
	}
	return formattedIssues
}

func CategorizeESLintResults(results []map[string]interface{}, directory string) map[string][]interface{} {
	categorized := utils.InitCategorizedResults()

	antipatternsRuleIDs := map[string]bool{
		"no-console":           true,
		"strict":               true,
		"no-magic-numbers":     true,
		"consistent-return":    true,
		"no-else-return":       true,
		"no-use-before-define": true,
		"prefer-const":         true,
		"no-restricted-syntax": true,
		"eqeqeq":               true,
		"complexity":           true,
	}

	for _, fileResult := range results {
		filePath := strings.ReplaceAll(fileResult["filePath"].(string), directory, "")
		messages := fileResult["messages"].([]interface{})

		for _, msg := range messages {
			message := msg.(map[string]interface{})
			ruleID, ok := message["ruleId"].(string)
			if !ok {
				continue
			}

			issue := map[string]interface{}{
				"path":    filePath,
				"line":    int(message["line"].(float64)),
				"message": message["message"].(string),
				"ruleId":  ruleID,
			}

			if antipatternsRuleIDs[ruleID] {
				categorized[ANTIPATTERNS_BUGS] = append(categorized[ANTIPATTERNS_BUGS], issue)
			} else if ruleID == "complexity" {
				categorized[COMPLEX_FUNCTIONS] = append(categorized[COMPLEX_FUNCTIONS], issue)
			}
		}
	}
	return categorized
}
