package tasks

import (
	"armur-codescanner/internal/config"
	"armur-codescanner/internal/logger"
	tools "armur-codescanner/internal/tools"
	utils "armur-codescanner/pkg"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ScanError captures a tool-level failure that occurred during a scan.
type ScanError struct {
	Tool    string `json:"tool"`
	Message string `json:"message"`
}

// toolResult holds the output of a single tool execution.
type toolResult struct {
	name   string
	result map[string]interface{}
	err    error
}

// maxConcurrency returns the configured tool concurrency limit.
func maxConcurrency() int {
	if v := os.Getenv("MAX_TOOL_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 5
}

// toolTimeout returns the per-tool execution timeout.
func toolTimeout() time.Duration {
	if v := os.Getenv("TOOL_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 300 * time.Second
}

// withTimeout wraps a tool runner so that it is cancelled after the configured
// per-tool timeout. If the context expires the runner returns a ScanError.
func withTimeout(name string, run func() toolResult) func() toolResult {
	return func() toolResult {
		ctx, cancel := context.WithTimeout(context.Background(), toolTimeout())
		defer cancel()

		ch := make(chan toolResult, 1)
		go func() { ch <- run() }()

		select {
		case res := <-ch:
			return res
		case <-ctx.Done():
			logger.Warn().Str("tool", name).Dur("timeout", toolTimeout()).Msg("tool timed out")
			return toolResult{name: name, err: fmt.Errorf("tool %s timed out after %v", name, toolTimeout())}
		}
	}
}

// runParallel executes a set of named tool functions concurrently up to the
// configured concurrency limit and returns aggregated results + per-tool errors.
func runParallel(dirPath string, runners []func() toolResult) (map[string][]interface{}, []ScanError) {
	sem := make(chan struct{}, maxConcurrency())
	ch := make(chan toolResult, len(runners))
	var wg sync.WaitGroup

	for _, run := range runners {
		wg.Add(1)
		run := run
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ch <- run()
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	categorized := utils.InitCategorizedResults()
	var scanErrors []ScanError
	for res := range ch {
		if res.err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: res.name, Message: res.err.Error()})
			continue
		}
		mergeResultss(categorized, res.result)
	}
	return categorized, scanErrors
}

// runParallelAdvanced is identical to runParallel but seeds with advanced categories.
func runParallelAdvanced(dirPath string, runners []func() toolResult) (map[string][]interface{}, []ScanError) {
	sem := make(chan struct{}, maxConcurrency())
	ch := make(chan toolResult, len(runners))
	var wg sync.WaitGroup

	for _, run := range runners {
		wg.Add(1)
		run := run
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ch <- run()
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	categorized := utils.InitAdvancedCategorizedResults()
	var scanErrors []ScanError
	for res := range ch {
		if res.err != nil {
			scanErrors = append(scanErrors, ScanError{Tool: res.name, Message: res.err.Error()})
			continue
		}
		mergeResultss(categorized, res.result)
	}
	return categorized, scanErrors
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

// applyProjectConfig filters a set of named runners according to the project
// config's tool allow/block lists, then appends any configured plugins.
func applyProjectConfig(
	dirPath string,
	language string,
	runners []func() toolResult,
	namedRunners []string, // parallel slice of tool names (same order as runners)
	cfg *config.ArmurConfig,
) []func() toolResult {
	if cfg == nil {
		return runners
	}

	// Filter by IsToolEnabled.
	var filtered []func() toolResult
	for i, run := range runners {
		name := ""
		if i < len(namedRunners) {
			name = namedRunners[i]
		}
		if name == "" || cfg.IsToolEnabled(name) {
			filtered = append(filtered, run)
		}
	}

	// Append plugin runners for applicable plugins.
	for _, plugin := range cfg.Plugins {
		plugin := plugin // capture loop var
		if plugin.Language != "" && plugin.Language != language {
			continue
		}
		filtered = append(filtered, withTimeout(plugin.Name, func() toolResult {
			result, err := plugin.RunPlugin(dirPath)
			return toolResult{name: plugin.Name, result: result, err: err}
		}))
	}

	return filtered
}

// RunSimpleScan runs the standard tool suite concurrently and returns results.
func RunSimpleScan(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	runners, names := buildSimpleScanRunnersNamed(dirPath, language)
	if cfg, err := config.LoadProjectConfig(dirPath); err == nil {
		runners = applyProjectConfig(dirPath, language, runners, names, cfg)
	}
	categorized, scanErrors := runParallel(dirPath, runners)

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatScanResults(newCatResult), scanErrors, nil
}

// RunSimpleScanLocal is RunSimpleScan without directory cleanup (for local paths).
func RunSimpleScanLocal(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	runners, names := buildSimpleScanRunnersNamed(dirPath, language)
	if cfg, err := config.LoadProjectConfig(dirPath); err == nil {
		runners = applyProjectConfig(dirPath, language, runners, names, cfg)
	}
	categorized, scanErrors := runParallel(dirPath, runners)

	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatScanResults(newCatResult), scanErrors, nil
}

// buildSimpleScanRunners returns the set of tool runners for a standard scan.
// Each runner is wrapped with a per-tool timeout.
func buildSimpleScanRunners(dirPath, language string) []func() toolResult {
	runners, _ := buildSimpleScanRunnersNamed(dirPath, language)
	return runners
}

// buildSimpleScanRunnersNamed is like buildSimpleScanRunners but also returns the
// tool name for each runner (parallel slices) so callers can apply config filtering.
func buildSimpleScanRunnersNamed(dirPath, language string) ([]func() toolResult, []string) {
	runners := []func() toolResult{
		withTimeout("semgrep", func() toolResult {
			r, err := tools.RunSemgrep(dirPath, "--config=auto")
			return toolResult{"semgrep", r, err}
		}),
	}
	names := []string{"semgrep"}

	switch language {
	case "go":
		runners = append(runners,
			withTimeout("gosec", func() toolResult {
				r, err := tools.RunGosec(dirPath)
				return toolResult{"gosec", r, err}
			}),
			withTimeout("golint", func() toolResult {
				r, err := tools.RunGolint(dirPath)
				return toolResult{"golint", r, err}
			}),
			withTimeout("govet", func() toolResult {
				r, err := tools.RunGovet(dirPath)
				return toolResult{"govet", r, err}
			}),
			withTimeout("staticcheck", func() toolResult {
				r, err := tools.RunStaticCheck(dirPath)
				return toolResult{"staticcheck", r, err}
			}),
			withTimeout("gocyclo", func() toolResult {
				r, err := tools.RunGocyclo(dirPath)
				return toolResult{"gocyclo", r, err}
			}),
		)
		names = append(names, "gosec", "golint", "govet", "staticcheck", "gocyclo")
	case "py":
		runners = append(runners,
			withTimeout("bandit", func() toolResult {
				r, err := tools.RunBandit(dirPath)
				return toolResult{"bandit", r, err}
			}),
			withTimeout("pydocstyle", func() toolResult {
				r, err := tools.RunPydocstyle(dirPath)
				return toolResult{"pydocstyle", r, err}
			}),
			withTimeout("radon", func() toolResult {
				r, err := tools.RunRadon(dirPath)
				return toolResult{"radon", r, err}
			}),
			withTimeout("pylint", func() toolResult {
				r, err := tools.RunPylint(dirPath)
				return toolResult{"pylint", r, err}
			}),
		)
		names = append(names, "bandit", "pydocstyle", "radon", "pylint")
	case "js":
		runners = append(runners,
			withTimeout("eslint", func() toolResult {
				r, err := tools.RunESLintOnRepo(dirPath)
				return toolResult{"eslint", r, err}
			}),
		)
		names = append(names, "eslint")
	case "rust":
		runners = append(runners,
			withTimeout("cargo-audit", func() toolResult {
				r, err := tools.RunCargoAudit(dirPath)
				return toolResult{"cargo-audit", r, err}
			}),
			withTimeout("cargo-geiger", func() toolResult {
				r, err := tools.RunCargoGeiger(dirPath)
				return toolResult{"cargo-geiger", r, err}
			}),
			withTimeout("clippy", func() toolResult {
				r, err := tools.RunClippy(dirPath)
				return toolResult{"clippy", r, err}
			}),
		)
		names = append(names, "cargo-audit", "cargo-geiger", "clippy")
	case "java":
		runners = append(runners,
			withTimeout("spotbugs", func() toolResult {
				r, err := tools.RunSpotBugs(dirPath)
				return toolResult{"spotbugs", r, err}
			}),
			withTimeout("pmd", func() toolResult {
				r, err := tools.RunPMD(dirPath)
				return toolResult{"pmd", r, err}
			}),
			withTimeout("dependency-check", func() toolResult {
				r, err := tools.RunDependencyCheck(dirPath)
				return toolResult{"dependency-check", r, err}
			}),
		)
		names = append(names, "spotbugs", "pmd", "dependency-check")
	case "ruby":
		runners = append(runners,
			withTimeout("brakeman", func() toolResult {
				r, err := tools.RunBrakeman(dirPath)
				return toolResult{"brakeman", r, err}
			}),
			withTimeout("bundler-audit", func() toolResult {
				r, err := tools.RunBundlerAudit(dirPath)
				return toolResult{"bundler-audit", r, err}
			}),
		)
		names = append(names, "brakeman", "bundler-audit")
	case "php":
		runners = append(runners,
			withTimeout("phpcs", func() toolResult {
				r, err := tools.RunPHPCS(dirPath)
				return toolResult{"phpcs", r, err}
			}),
			withTimeout("psalm", func() toolResult {
				r, err := tools.RunPsalm(dirPath)
				return toolResult{"psalm", r, err}
			}),
		)
		names = append(names, "phpcs", "psalm")
	case "c":
		runners = append(runners,
			withTimeout("cppcheck", func() toolResult {
				r, err := tools.RunCppcheck(dirPath)
				return toolResult{"cppcheck", r, err}
			}),
			withTimeout("flawfinder", func() toolResult {
				r, err := tools.RunFlawfinder(dirPath)
				return toolResult{"flawfinder", r, err}
			}),
		)
		names = append(names, "cppcheck", "flawfinder")
	case "iac":
		runners = append(runners,
			withTimeout("hadolint", func() toolResult {
				r, err := tools.RunHadolint(dirPath)
				return toolResult{"hadolint", r, err}
			}),
			withTimeout("tfsec", func() toolResult {
				r, err := tools.RunTfsec(dirPath)
				return toolResult{"tfsec", r, err}
			}),
			withTimeout("kics", func() toolResult {
				r, err := tools.RunKICS(dirPath)
				return toolResult{"kics", r, err}
			}),
			withTimeout("kube-linter", func() toolResult {
				r, err := tools.RunKubeLinter(dirPath)
				return toolResult{"kube-linter", r, err}
			}),
			withTimeout("kube-score", func() toolResult {
				r, err := tools.RunKubeScore(dirPath)
				return toolResult{"kube-score", r, err}
			}),
		)
		names = append(names, "hadolint", "tfsec", "kics", "kube-linter", "kube-score")
	case "sol":
		runners = append(runners,
			withTimeout("slither", func() toolResult {
				r, err := tools.RunSlither(dirPath)
				return toolResult{"slither", r, err}
			}),
			withTimeout("mythril", func() toolResult {
				r, err := tools.RunMythril(dirPath)
				return toolResult{"mythril", r, err}
			}),
		)
		names = append(names, "slither", "mythril")
	}

	return runners, names
}

// RunAdvancedScans runs the full advanced tool suite concurrently.
func RunAdvancedScans(dirPath string, language string) (map[string]interface{}, []ScanError, error) {
	runners := []func() toolResult{
		withTimeout("jscpd", func() toolResult {
			r, err := tools.RunJSCPD(dirPath)
			return toolResult{"jscpd", r, err}
		}),
		withTimeout("checkov", func() toolResult {
			r, err := tools.RunCheckov(dirPath)
			return toolResult{"checkov", r, err}
		}),
		withTimeout("trufflehog", func() toolResult {
			r, err := tools.RunTrufflehog(dirPath)
			return toolResult{"trufflehog", r, err}
		}),
		withTimeout("trivy", func() toolResult {
			r, err := tools.RunTrivy(dirPath)
			return toolResult{"trivy", r, err}
		}),
		withTimeout("osv-scanner", func() toolResult {
			r, err := tools.RunOSVScanner(dirPath)
			return toolResult{"osv-scanner", r, err}
		}),
	}

	switch language {
	case "go":
		runners = append(runners, withTimeout("deadcode", func() toolResult {
			r, err := tools.RunGoDeadcode(dirPath)
			return toolResult{"deadcode", r, err}
		}))
	case "py":
		runners = append(runners, withTimeout("vulture", func() toolResult {
			r, err := tools.RunVulture(dirPath)
			return toolResult{"vulture", r, err}
		}))
	case "js":
		runners = append(runners, withTimeout("eslint-advanced", func() toolResult {
			r, err := tools.RunESLintAdvanced(dirPath)
			return toolResult{"eslint-advanced", r, err}
		}))
	}

	categorized, scanErrors := runParallelAdvanced(dirPath, runners)

	if err := os.RemoveAll(dirPath); err != nil {
		return nil, scanErrors, fmt.Errorf("failed to remove directory: %v", err)
	}
	newCatResult := utils.ConvertCategorizedResults(categorized)
	return utils.ReformatAdvancedScanResults(newCatResult), scanErrors, nil
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
