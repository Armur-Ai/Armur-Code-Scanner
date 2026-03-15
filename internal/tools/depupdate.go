package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DepUpdateResult holds the result of a dependency update check.
type DepUpdateResult struct {
	Package        string `json:"package"`
	Current        string `json:"current_version"`
	Latest         string `json:"latest_version"`
	UpdateType     string `json:"update_type"` // major, minor, patch
	Ecosystem      string `json:"ecosystem"`
	HasVulnerability bool `json:"has_vulnerability"`
}

// CheckOutdatedDeps checks for outdated dependencies across ecosystems.
func CheckOutdatedDeps(dirPath string) ([]DepUpdateResult, error) {
	var results []DepUpdateResult

	// Go
	if fileExistsAt(dirPath, "go.mod") {
		goResults := checkGoOutdated(dirPath)
		results = append(results, goResults...)
	}

	// npm
	if fileExistsAt(dirPath, "package.json") {
		npmResults := checkNpmOutdated(dirPath)
		results = append(results, npmResults...)
	}

	// pip
	if fileExistsAt(dirPath, "requirements.txt") {
		pipResults := checkPipOutdated(dirPath)
		results = append(results, pipResults...)
	}

	return results, nil
}

func checkGoOutdated(dirPath string) []DepUpdateResult {
	cmd := exec.Command("go", "list", "-u", "-m", "-json", "all")
	cmd.Dir = dirPath
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var results []DepUpdateResult
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for decoder.More() {
		var mod struct {
			Path    string `json:"Path"`
			Version string `json:"Version"`
			Update  *struct {
				Path    string `json:"Path"`
				Version string `json:"Version"`
			} `json:"Update"`
			Indirect bool `json:"Indirect"`
		}
		if err := decoder.Decode(&mod); err != nil {
			break
		}
		if mod.Update != nil && !mod.Indirect {
			results = append(results, DepUpdateResult{
				Package:    mod.Path,
				Current:    mod.Version,
				Latest:     mod.Update.Version,
				UpdateType: classifyUpdate(mod.Version, mod.Update.Version),
				Ecosystem:  "go",
			})
		}
	}
	return results
}

func checkNpmOutdated(dirPath string) []DepUpdateResult {
	cmd := exec.Command("npm", "outdated", "--json")
	cmd.Dir = dirPath
	output, _ := cmd.Output() // exits non-zero when outdated packages found

	var outdated map[string]struct {
		Current string `json:"current"`
		Wanted  string `json:"wanted"`
		Latest  string `json:"latest"`
	}
	if err := json.Unmarshal(output, &outdated); err != nil {
		return nil
	}

	var results []DepUpdateResult
	for pkg, info := range outdated {
		results = append(results, DepUpdateResult{
			Package:    pkg,
			Current:    info.Current,
			Latest:     info.Latest,
			UpdateType: classifyUpdate(info.Current, info.Latest),
			Ecosystem:  "npm",
		})
	}
	return results
}

func checkPipOutdated(dirPath string) []DepUpdateResult {
	cmd := exec.Command("pip", "list", "--outdated", "--format=json")
	cmd.Dir = dirPath
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	var outdated []struct {
		Name           string `json:"name"`
		Version        string `json:"version"`
		LatestVersion  string `json:"latest_version"`
	}
	if err := json.Unmarshal(output, &outdated); err != nil {
		return nil
	}

	var results []DepUpdateResult
	for _, pkg := range outdated {
		results = append(results, DepUpdateResult{
			Package:    pkg.Name,
			Current:    pkg.Version,
			Latest:     pkg.LatestVersion,
			UpdateType: classifyUpdate(pkg.Version, pkg.LatestVersion),
			Ecosystem:  "pip",
		})
	}
	return results
}

func classifyUpdate(current, latest string) string {
	curParts := strings.SplitN(strings.TrimPrefix(current, "v"), ".", 3)
	latParts := strings.SplitN(strings.TrimPrefix(latest, "v"), ".", 3)

	if len(curParts) >= 1 && len(latParts) >= 1 && curParts[0] != latParts[0] {
		return "major"
	}
	if len(curParts) >= 2 && len(latParts) >= 2 && curParts[1] != latParts[1] {
		return "minor"
	}
	return "patch"
}

// FormatDepUpdates returns findings from outdated dependencies.
func FormatDepUpdates(updates []DepUpdateResult) map[string]interface{} {
	findings := []interface{}{}
	for _, u := range updates {
		severity := "LOW"
		if u.UpdateType == "major" {
			severity = "MEDIUM"
		}
		if u.HasVulnerability {
			severity = "HIGH"
		}

		findings = append(findings, map[string]interface{}{
			"path":     fmt.Sprintf("%s (%s)", u.Package, u.Ecosystem),
			"line":     0,
			"severity": severity,
			"message":  fmt.Sprintf("Outdated: %s@%s → %s (%s update)", u.Package, u.Current, u.Latest, u.UpdateType),
			"tool":     "dep-update-check",
		})
	}
	return map[string]interface{}{"outdated_dependencies": findings}
}

func fileExistsAt(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}
