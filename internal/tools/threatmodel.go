package internal

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RouteInfo represents a detected HTTP endpoint.
type RouteInfo struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Handler string `json:"handler"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Auth    bool   `json:"auth"` // whether auth middleware is applied
}

// ThreatModel represents the threat model generated from code analysis.
type ThreatModel struct {
	Routes       []RouteInfo            `json:"routes"`
	EntryPoints  int                    `json:"entry_points"`
	DataStores   []string               `json:"data_stores"`
	ExternalAPIs []string               `json:"external_apis"`
	Mermaid      string                 `json:"mermaid_dfd"`
}

// Route detection patterns per framework.
var routePatterns = []*regexp.Regexp{
	// Go (Gin)
	regexp.MustCompile(`\.(GET|POST|PUT|DELETE|PATCH)\s*\(\s*"([^"]+)"`),
	// Go (net/http)
	regexp.MustCompile(`http\.HandleFunc\s*\(\s*"([^"]+)"`),
	// Python (Flask/FastAPI)
	regexp.MustCompile(`@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"](.*?)['"]`),
	// JavaScript (Express)
	regexp.MustCompile(`(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"](.*?)['"]`),
	// Java (Spring)
	regexp.MustCompile(`@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(\s*(?:value\s*=\s*)?['"](.*?)['"]`),
}

var dataStorePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:postgresql|postgres|mysql|mongodb|redis|sqlite|dynamodb|cassandra)`),
	regexp.MustCompile(`(?i)(?:database_url|db_host|redis_url|mongo_uri)`),
}

var externalAPIPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://(?:api\.|.*\.com/api/|.*\.io/v\d)`),
	regexp.MustCompile(`(?i)(?:stripe|twilio|sendgrid|aws|gcp|azure).*(?:client|api|sdk)`),
}

// DetectRoutes scans source code for HTTP endpoint definitions.
func DetectRoutes(dirPath string) []RouteInfo {
	var routes []RouteInfo

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isSourceFile(path) {
			return nil
		}

		rel, _ := filepath.Rel(dirPath, path)
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			for _, pattern := range routePatterns {
				matches := pattern.FindStringSubmatch(line)
				if len(matches) >= 3 {
					routes = append(routes, RouteInfo{
						Method: strings.ToUpper(matches[1]),
						Path:   matches[2],
						File:   rel,
						Line:   lineNum,
					})
				} else if len(matches) >= 2 {
					routes = append(routes, RouteInfo{
						Method: "ANY",
						Path:   matches[1],
						File:   rel,
						Line:   lineNum,
					})
				}
			}
		}

		return nil
	})

	return routes
}

// GenerateThreatModel creates a threat model from code analysis.
func GenerateThreatModel(dirPath string) *ThreatModel {
	routes := DetectRoutes(dirPath)
	dataStores := detectPatterns(dirPath, dataStorePatterns)
	externalAPIs := detectPatterns(dirPath, externalAPIPatterns)

	model := &ThreatModel{
		Routes:       routes,
		EntryPoints:  len(routes),
		DataStores:   unique(dataStores),
		ExternalAPIs: unique(externalAPIs),
	}

	model.Mermaid = generateDFD(model)
	return model
}

// generateDFD generates a Mermaid Data Flow Diagram.
func generateDFD(model *ThreatModel) string {
	var b strings.Builder
	b.WriteString("graph LR\n")
	b.WriteString("    User[\"External User\"]\n")
	b.WriteString("    App[\"Application\"]\n")

	// Routes as entry points
	b.WriteString("    User -->|HTTP| App\n")

	// Data stores
	for i, ds := range model.DataStores {
		id := fmt.Sprintf("DB%d", i)
		b.WriteString(fmt.Sprintf("    %s[(\"%s\")]\n", id, ds))
		b.WriteString(fmt.Sprintf("    App --> %s\n", id))
	}

	// External APIs
	for i, api := range model.ExternalAPIs {
		id := fmt.Sprintf("API%d", i)
		b.WriteString(fmt.Sprintf("    %s[\"%s\"]\n", id, api))
		b.WriteString(fmt.Sprintf("    App --> %s\n", id))
	}

	// Style
	b.WriteString("    style User fill:#4488ff\n")
	b.WriteString("    style App fill:#44aa44\n")

	return b.String()
}

func detectPatterns(dirPath string, patterns []*regexp.Regexp) []string {
	var found []string

	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !isSourceFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		for _, p := range patterns {
			matches := p.FindAllString(string(content), -1)
			found = append(found, matches...)
		}
		return nil
	})

	return found
}

func unique(items []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, item := range items {
		lower := strings.ToLower(strings.TrimSpace(item))
		if !seen[lower] && lower != "" {
			seen[lower] = true
			result = append(result, item)
		}
	}
	return result
}
