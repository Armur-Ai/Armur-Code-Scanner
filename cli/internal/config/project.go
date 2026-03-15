package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ProjectConfig represents the .armur.yml project configuration.
type ProjectConfig struct {
	Scan struct {
		Depth             string `yaml:"depth"`
		Language          string `yaml:"language"`
		SeverityThreshold string `yaml:"severity-threshold"`
		FailOnFindings    bool   `yaml:"fail-on-findings"`
	} `yaml:"scan"`
	Exclude []string `yaml:"exclude"`
	Tools   struct {
		Enabled  []string `yaml:"enabled"`
		Disabled []string `yaml:"disabled"`
		Timeout  int      `yaml:"timeout"`
	} `yaml:"tools"`
	Output struct {
		Format string `yaml:"format"`
		SaveTo string `yaml:"save-to"`
	} `yaml:"output"`
}

// LoadProjectConfig loads .armur.yml from the given directory (or cwd if empty).
func LoadProjectConfig(dir string) (*ProjectConfig, error) {
	path := ".armur.yml"
	if dir != "" && dir != "." {
		path = dir + "/.armur.yml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
