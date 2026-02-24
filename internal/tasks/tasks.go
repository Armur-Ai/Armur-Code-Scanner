package tasks

import (
	"armur-codescanner/internal/logger"
	tools "armur-codescanner/internal/tools"
	utils "armur-codescanner/pkg"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ScanError captures a tool-level failure that occurred during a scan.
type ScanError struct {
	Tool    string `json:"tool"`
	Message string `json:"message"`
}

func RunScanTask(repositoryURL, language string) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("repo", repositoryURL).Msgf("panic recovered during scan: %v", r)
		}
	}()

	dirPath, err := utils.CloneRepo(repositoryURL)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to clone repository")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}

	if language == "" {
		language = utils.DetectRepoLanguage(dirPath)
		logger.Info().Str("repo", repositoryURL).Str("language", language).Msg("language detected")
	} else {
		if err := utils.RemoveNonRelevantFiles(dirPath, language); err != nil {
			logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to remove non-relevant files")
			return map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		}
	}

	categorizedResults, scanErrors, err := RunSimpleScan(dirPath, language)
	if err != nil {
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

func RunScanTaskLocal(repoPath, language string) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("path", repoPath).Msgf("panic recovered during scan: %v", r)
		}
	}()

	if language == "" {
		language = utils.DetectRepoLanguage(repoPath)
		logger.Info().Str("path", repoPath).Str("language", language).Msg("language detected")
	} else {
		if err := utils.RemoveNonRelevantFiles(repoPath, language); err != nil {
			logger.Error().Str("path", repoPath).Err(err).Msg("failed to remove non-relevant files")
			return map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		}
	}

	categorizedResults, scanErrors, err := RunSimpleScanLocal(repoPath, language)
	if err != nil {
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

func AdvancedScanRepositoryTask(repositoryURL, language string) map[string]interface{} {
	defer func() {
		if r := recover(); r != nil {
			logger.Error().Str("repo", repositoryURL).Msgf("panic recovered during advanced scan: %v", r)
		}
	}()

	dirPath, err := utils.CloneRepo(repositoryURL)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to clone repository")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}

	if language == "" {
		language = utils.DetectRepoLanguage(dirPath)
		logger.Info().Str("repo", repositoryURL).Str("language", language).Msg("language detected")
	} else {
		if err := utils.RemoveNonRelevantFiles(dirPath, language); err != nil {
			logger.Error().Str("repo", repositoryURL).Err(err).Msg("failed to remove non-relevant files")
			return map[string]interface{}{
				"status": "failed",
				"error":  err.Error(),
			}
		}
	}

	categorizedResults, scanErrors, err := RunAdvancedScans(dirPath, language)
	if err != nil {
		logger.Error().Str("repo", repositoryURL).Err(err).Msg("advanced scan failed")
		return map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}
	return categorizedResults
}

// RunSimpleScan runs the standard tool suite and returns results, any per-tool errors, and a fatal error if any.
func RunSimpleScan(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	categorizedResults := utils.InitCategorizedResults()
	var scanErrors []ScanError

	semgrepResult, err := tools.RunSemgrep(dirPath, "--config=auto")
	if err != nil {
		scanErrors = append(scanErrors, ScanError{Tool: "semgrep", Message: err.Error()})
	}
	mergeResultss(categorizedResults, semgrepResult)

	if language == "go" {
		if r, err := tools.RunGosec(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "gosec", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunGolint(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "golint", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunGovet(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "govet", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunStaticCheck(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "staticcheck", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunGocyclo(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "gocyclo", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	} else if language == "py" {
		if r, err := tools.RunBandit(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "bandit", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunPydocstyle(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "pydocstyle", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunRadon(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "radon", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunPylint(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "pylint", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	} else if language == "js" {
		if r, err := tools.RunESLintOnRepo(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "eslint", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	}

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorizedResults)
	finalresult := utils.ReformatScanResults(newCatResult)
	return finalresult, scanErrors, nil
}

// RunSimpleScanLocal is the same as RunSimpleScan but does not delete the directory afterwards.
func RunSimpleScanLocal(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	categorizedResults := utils.InitCategorizedResults()
	var scanErrors []ScanError

	semgrepResult, err := tools.RunSemgrep(dirPath, "--config=auto")
	if err != nil {
		scanErrors = append(scanErrors, ScanError{Tool: "semgrep", Message: err.Error()})
	}
	mergeResultss(categorizedResults, semgrepResult)

	if language == "go" {
		if r, err := tools.RunGosec(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "gosec", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunGolint(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "golint", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunGovet(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "govet", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunStaticCheck(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "staticcheck", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunGocyclo(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "gocyclo", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	} else if language == "py" {
		if r, err := tools.RunBandit(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "bandit", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunPydocstyle(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "pydocstyle", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunRadon(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "radon", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}

		if r, err := tools.RunPylint(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "pylint", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	} else if language == "js" {
		if r, err := tools.RunESLintOnRepo(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "eslint", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	}

	newCatResult := utils.ConvertCategorizedResults(categorizedResults)
	finalresult := utils.ReformatScanResults(newCatResult)
	return finalresult, scanErrors, nil
}

// RunAdvancedScans runs the full advanced tool suite.
func RunAdvancedScans(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	categorizedResults := utils.InitAdvancedCategorizedResults()
	var scanErrors []ScanError

	if r, err := tools.RunJSCPD(dirPath); err != nil {
		scanErrors = append(scanErrors, ScanError{Tool: "jscpd", Message: err.Error()})
	} else {
		mergeResultss(categorizedResults, r)
	}

	if r, err := tools.RunCheckov(dirPath); err != nil {
		scanErrors = append(scanErrors, ScanError{Tool: "checkov", Message: err.Error()})
	} else {
		mergeResultss(categorizedResults, r)
	}

	if r, err := tools.RunTrufflehog(dirPath); err != nil {
		scanErrors = append(scanErrors, ScanError{Tool: "trufflehog", Message: err.Error()})
	} else {
		mergeResultss(categorizedResults, r)
	}

	if r, err := tools.RunTrivy(dirPath); err != nil {
		scanErrors = append(scanErrors, ScanError{Tool: "trivy", Message: err.Error()})
	} else {
		mergeResultss(categorizedResults, r)
	}

	if r, err := tools.RunOSVScanner(dirPath); err != nil {
		logger.Warn().Str("tool", "osv-scanner").Err(err).Msg("tool failed")
		scanErrors = append(scanErrors, ScanError{Tool: "osv-scanner", Message: err.Error()})
	} else {
		mergeResultss(categorizedResults, r)
	}

	if language == "go" {
		if r, err := tools.RunGoDeadcode(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "deadcode", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	} else if language == "py" {
		if r, err := tools.RunVulture(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "vulture", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	} else if language == "js" {
		if r, err := tools.RunESLintAdvanced(dirPath); err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: "eslint-advanced", Message: err.Error()})
		} else {
			mergeResultss(categorizedResults, r)
		}
	}

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorizedResults)
	finalresult := utils.ReformatAdvancedScanResults(newCatResult)
	return finalresult, scanErrors, nil
}

func mergeResultss(categorizedResults map[string][]interface{}, newResults map[string]interface{}) {
	for key, newValue := range newResults {
		if newValue == nil {
			if _, exists := categorizedResults[key]; !exists {
				categorizedResults[key] = []interface{}{}
			}
			continue
		}

		newSlice, ok := newValue.([]interface{})
		if !ok {
			continue
		}

		if len(newSlice) == 0 {
			if _, exists := categorizedResults[key]; !exists {
				categorizedResults[key] = []interface{}{}
			}
			continue
		}

		if existingSlice, exists := categorizedResults[key]; exists {
			categorizedResults[key] = append(existingSlice, newSlice...)
		} else {
			categorizedResults[key] = newSlice
		}
	}
}

func ScanFileTask(filePath string) (map[string]interface{}, error) {
	dirPath := filepath.Dir(filePath)

	defer func() {
		if err := os.RemoveAll(dirPath); err != nil {
			logger.Error().Str("dir", dirPath).Err(err).Msg("failed to clean up scan directory")
		} else {
			logger.Debug().Str("dir", dirPath).Msg("cleaned up scan directory")
		}
	}()

	language := utils.DetectFileLanguage(filePath)
	if language == "" {
		err := errors.New("unable to detect file language")
		logger.Error().Str("file", filePath).Err(err).Msg("language detection failed")
		return map[string]interface{}{"status": "failed", "error": err.Error()}, err
	}

	categorizedResults, scanErrors, err := RunSimpleScan(filePath, language)
	if err != nil {
		logger.Error().Str("file", filePath).Err(err).Msg("scan failed")
		return map[string]interface{}{"status": "failed", "error": err.Error()}, err
	}
	if len(scanErrors) > 0 {
		categorizedResults["scan_errors"] = scanErrors
	}

	return categorizedResults, nil
}
