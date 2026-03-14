package utils

import (
	pkg "armur-codescanner/pkg/common"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

type CWEData struct {
	CWE                 string            `json:"cwe"`
	GoodPracticeExample map[string]string `json:"good_practice_example"`
	BadPracticeExample  map[string]string `json:"bad_practice_example"`
}

const (
	SimpleScan   = "simple_scan"
	AdvancedScan = "advanced_scan"
	FileScan     = "file_scan"
	LocalScan    = "local_scan"
)

// Constants
const (
	DEAD_CODE         = "dead_code"
	DUPLICATE_CODE    = "duplicate_code"
	SECRET_DETECTION  = "secret_detection"
	INFRA_SECURITY    = "infra_security"
	SCA               = "sca"
	COMPLEX_FUNCTIONS = "complex_functions"
	DOCKSTRING_ABSENT = "dockstring_absent"
	ANTIPATTERNS_BUGS = "antipatterns_bugs"
	SECURITY_ISSUES   = "security_issues"
	UNKNOWN           = "unknown"
)

func LoadCWEData(filePath string) ([]CWEData, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	// Unmarshal the JSON into a slice of CWEData
	var data []CWEData
	err = json.Unmarshal(file, &data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling CWE data: %v", err)
	}

	return data, nil
}

func GetPracticesFromJSON(data []CWEData, language string, cwe string) map[string]string {
	for _, item := range data {
		if item.CWE == cwe {
			goodPractice, goodFound := item.GoodPracticeExample[language]
			badPractice, badFound := item.BadPracticeExample[language]

			if goodFound && badFound {
				return map[string]string{
					"good_practice": goodPractice,
					"bad_practice":  badPractice,
				}
			}
		}
	}
	return map[string]string{}
}

// reposBaseDir returns the directory used for cloned repositories.
// It reads ARMUR_REPOS_DIR env var; falls back to /armur/repos.
func reposBaseDir() string {
	if d := os.Getenv("ARMUR_REPOS_DIR"); d != "" {
		return d
	}
	return "/armur/repos"
}

// CloneRepo clones a repository to a temporary directory
func CloneRepo(repositoryURL string) (string, error) {
	baseDir := reposBaseDir()
	err := os.MkdirAll(baseDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("error creating base directory: %w", err)
	}

	tempDir, err := os.MkdirTemp(baseDir, "repo")
	if err != nil {
		return "", fmt.Errorf("error creating temp directory: %w", err)
	}

	_, err = git.PlainClone(tempDir, false, &git.CloneOptions{
		URL:      repositoryURL,
		Progress: os.Stdout,
	})
	if err != nil {
		return "", fmt.Errorf("error cloning repository: %w", err)
	}

	return tempDir, nil
}

// DetectRepoLanguage detects the primary language of a repository by counting source files.
func DetectRepoLanguage(directory string) string {
	languages := map[string]int{
		"go": 0, "py": 0, "js": 0,
		"rust": 0, "java": 0, "ruby": 0,
		"php": 0, "c": 0, "sol": 0,
	}

	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		name := info.Name()
		switch {
		case strings.HasSuffix(name, ".go"):
			languages["go"]++
		case strings.HasSuffix(name, ".py"):
			languages["py"]++
		case strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts"):
			languages["js"]++
		case strings.HasSuffix(name, ".rs"):
			languages["rust"]++
		case strings.HasSuffix(name, ".java") || strings.HasSuffix(name, ".kt"):
			languages["java"]++
		case strings.HasSuffix(name, ".rb"):
			languages["ruby"]++
		case strings.HasSuffix(name, ".php"):
			languages["php"]++
		case strings.HasSuffix(name, ".c") || strings.HasSuffix(name, ".cpp") || strings.HasSuffix(name, ".h"):
			languages["c"]++
		case strings.HasSuffix(name, ".sol"):
			languages["sol"]++
		}
		return nil
	})

	// Prefer IaC if Dockerfile or Terraform files are present.
	iacCount := 0
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			n := info.Name()
			if n == "Dockerfile" || strings.HasSuffix(n, ".tf") || strings.HasSuffix(n, ".tfvars") {
				iacCount++
			}
		}
		return nil
	})
	if iacCount > 0 {
		languages["iac"] = iacCount
	}

	maxLang := ""
	maxCount := 0
	for lang, count := range languages {
		if count > maxCount {
			maxLang = lang
			maxCount = count
		}
	}

	return maxLang
}

// DetectFileLanguage detects the language of a file by its extension.
func DetectFileLanguage(file string) string {
	switch {
	case strings.HasSuffix(file, ".go"):
		return "go"
	case strings.HasSuffix(file, ".py"):
		return "py"
	case strings.HasSuffix(file, ".js") || strings.HasSuffix(file, ".ts"):
		return "js"
	case strings.HasSuffix(file, ".rs"):
		return "rust"
	case strings.HasSuffix(file, ".java") || strings.HasSuffix(file, ".kt"):
		return "java"
	case strings.HasSuffix(file, ".rb"):
		return "ruby"
	case strings.HasSuffix(file, ".php"):
		return "php"
	case strings.HasSuffix(file, ".c") || strings.HasSuffix(file, ".cpp") || strings.HasSuffix(file, ".h"):
		return "c"
	case strings.HasSuffix(file, ".sol"):
		return "sol"
	default:
		return ""
	}
}

func RemoveNonRelevantFiles(dirPath string, language string) error {
	// Get extensions for the specified language
	extensions, ok := pkg.LanguageFileExtensions[strings.ToLower(language)]
	if !ok {
		extensions = []string{} // Empty slice if language not found
	}

	// Walk through directory
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file should be kept
		shouldKeep := false
		for _, ext := range extensions {
			if strings.HasSuffix(strings.ToLower(info.Name()), ext) {
				shouldKeep = true
				break
			}
		}

		// Remove file if it shouldn't be kept
		if !shouldKeep {
			if err := os.Remove(path); err != nil {
				return err
			}
		}

		return nil
	})
}

// InitCategorizedResults initializes categorized results
func InitCategorizedResults() map[string][]interface{} {
	return map[string][]interface{}{
		DOCKSTRING_ABSENT: {},
		SECURITY_ISSUES:   {},
		COMPLEX_FUNCTIONS: {},
		ANTIPATTERNS_BUGS: {},
	}
}

func ConvertCategorizedResults(input map[string][]interface{}) map[string]interface{} {
	converted := make(map[string]interface{})
	for key, value := range input {
		if value == nil {
			converted[key] = []interface{}{}
		} else {
			converted[key] = value
		}
	}
	return converted
}

// InitAdvancedCategorizedResults initializes advanced categorized results
func InitAdvancedCategorizedResults() map[string][]interface{} {
	return map[string][]interface{}{
		DEAD_CODE:        {},
		DUPLICATE_CODE:   {},
		SECRET_DETECTION: {},
		INFRA_SECURITY:   {},
		SCA:              {},
	}
}
