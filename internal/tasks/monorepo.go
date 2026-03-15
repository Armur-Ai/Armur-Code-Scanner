package tasks

import (
	"os"
	"path/filepath"
	"strings"
)

// Service represents a detected service/module within a monorepo.
type Service struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Language string `json:"language"`
	Manifest string `json:"manifest"` // go.mod, package.json, etc.
}

// DetectMonorepoServices finds independent services/modules within a directory.
func DetectMonorepoServices(rootPath string) []Service {
	var services []Service

	manifestTypes := map[string]string{
		"go.mod":         "go",
		"package.json":   "js",
		"pyproject.toml": "py",
		"requirements.txt": "py",
		"Cargo.toml":     "rust",
		"pom.xml":        "java",
		"build.gradle":   "java",
		"Gemfile":        "ruby",
		"composer.json":  "php",
	}

	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			// Skip hidden dirs and common non-service dirs
			if info != nil && info.IsDir() {
				base := filepath.Base(path)
				if strings.HasPrefix(base, ".") || base == "node_modules" || base == "vendor" || base == "target" || base == "build" || base == "dist" {
					return filepath.SkipDir
				}
			}
			return nil
		}

		name := filepath.Base(path)
		if lang, ok := manifestTypes[name]; ok {
			dir := filepath.Dir(path)
			rel, _ := filepath.Rel(rootPath, dir)

			// Don't count the root as a "service" unless it's the only one
			if rel == "." {
				return nil
			}

			serviceName := filepath.Base(dir)
			if rel != serviceName {
				serviceName = strings.ReplaceAll(rel, string(os.PathSeparator), "-")
			}

			services = append(services, Service{
				Name:     serviceName,
				Path:     rel,
				Language: lang,
				Manifest: name,
			})
		}

		return nil
	})

	// If no sub-services found, treat root as single service
	if len(services) == 0 {
		for _, manifest := range []string{"go.mod", "package.json", "pyproject.toml", "Cargo.toml", "pom.xml"} {
			if _, err := os.Stat(filepath.Join(rootPath, manifest)); err == nil {
				lang := manifestTypes[manifest]
				services = append(services, Service{
					Name:     filepath.Base(rootPath),
					Path:     ".",
					Language: lang,
					Manifest: manifest,
				})
				break
			}
		}
	}

	return services
}

// IsMonorepo returns true if multiple independent services are detected.
func IsMonorepo(rootPath string) bool {
	services := DetectMonorepoServices(rootPath)
	return len(services) > 1
}
