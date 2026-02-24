package internal

import (
	"armur-codescanner/internal/logger"
	utils "armur-codescanner/pkg"
	"encoding/json"
	"os/exec"
	"strings"
)

func RunOSVScanner(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "osv-scanner").Str("dir", directory).Msg("running")
	result, err := runOSVScannerOnRepo(directory)
	if err != nil {
		logger.Warn().Str("tool", "osv-scanner").Err(err).Msg("tool execution failed, returning partial results")
		return utils.ConvertCategorizedResults(utils.InitAdvancedCategorizedResults()), err
	}
	ans := categorizeOSVResults(result, directory)
	return utils.ConvertCategorizedResults(ans), nil
}

func runOSVScannerOnRepo(directory string) (string, error) {
	cmd := exec.Command("osv-scanner", "--format", "json", directory)
	output, err := cmd.Output()
	if err != nil {
		// osv-scanner exits non-zero when vulnerabilities are found
		logger.Debug().Str("tool", "osv-scanner").Err(err).Msg("non-zero exit (may still have results)")
	}
	return string(output), nil
}

func categorizeOSVResults(results string, directory string) map[string][]interface{} {
	categorizedResults := utils.InitAdvancedCategorizedResults()

	if results == "" {
		return categorizedResults
	}

	var osvResults struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string      `json:"id"`
					Summary  string      `json:"summary"`
					Severity interface{} `json:"severity"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	err := json.Unmarshal([]byte(results), &osvResults)
	if err != nil {
		logger.Error().Str("tool", "osv-scanner").Err(err).Msg("failed to parse output")
		return categorizedResults
	}

	for _, result := range osvResults.Results {
		for _, packageData := range result.Packages {
			for _, vulnerability := range packageData.Vulnerabilities {
				categorizedVuln := map[string]interface{}{
					"path":     strings.Replace(result.Source.Path, directory, "", 1),
					"package":  packageData.Package.Name,
					"version":  packageData.Package.Version,
					"check_id": vulnerability.ID,
					"message":  vulnerability.Summary,
				}

				switch severity := vulnerability.Severity.(type) {
				case string:
					categorizedVuln["severity"] = severity
				case []interface{}:
					severities := make([]string, len(severity))
					for i, v := range severity {
						if s, ok := v.(string); ok {
							severities[i] = s
						}
					}
					categorizedVuln["severity"] = severities
				default:
					categorizedVuln["severity"] = "Unknown"
				}

				categorizedResults[utils.SCA] = append(categorizedResults[utils.SCA], categorizedVuln)
			}
		}
	}

	if len(categorizedResults[utils.SCA]) == 0 {
		categorizedResults[utils.SCA] = []interface{}{}
	}

	return categorizedResults
}
