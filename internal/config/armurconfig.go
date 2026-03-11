// Package config handles loading and applying the per-project .armur.yml
// configuration file that lives in the scanned repository root.
package config

import (
	"armur-codescanner/internal/logger"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ArmurConfig is the schema of the .armur.yml project configuration file.
type ArmurConfig struct {
	// Exclude is a list of glob patterns for files/dirs to skip during scanning.
	Exclude []string `yaml:"exclude"`

	// Tools configures which tools run.
	Tools ToolsConfig `yaml:"tools"`

	// SeverityThreshold is the minimum severity level to report.
	// Valid values: info, low, medium, high, critical (case-insensitive).
	SeverityThreshold string `yaml:"severity-threshold"`

	// FailOnFindings causes the process to exit non-zero if any findings exceed
	// the severity threshold.
	FailOnFindings bool `yaml:"fail-on-findings"`

	// Plugins defines custom tool integrations.
	Plugins []PluginConfig `yaml:"plugins"`
}

// ToolsConfig controls the tool allow/block lists.
type ToolsConfig struct {
	// Enabled is an explicit allowlist of tool names. When non-empty, only
	// these tools will run (all others are skipped).
	Enabled []string `yaml:"enabled"`

	// Disabled is an explicit blocklist of tool names. These tools are skipped
	// even if they would otherwise run.
	Disabled []string `yaml:"disabled"`
}

// PluginConfig defines a custom external tool plugin.
type PluginConfig struct {
	// Name is a human-readable identifier used in scan results.
	Name string `yaml:"name"`

	// Command is the shell command to run. The placeholder {target} is replaced
	// with the path being scanned.
	Command string `yaml:"command"`

	// OutputFormat describes how to parse the plugin output: "json" or "text".
	OutputFormat string `yaml:"output-format"`

	// Language restricts the plugin to repos of this language (go/py/js).
	// Leave empty to run for all languages.
	Language string `yaml:"language"`
}

const configFileName = ".armur.yml"

// LoadProjectConfig reads the .armur.yml file from repoPath, if it exists.
// If the file is absent, a zero-value ArmurConfig is returned without error.
func LoadProjectConfig(repoPath string) (*ArmurConfig, error) {
	cfgPath := filepath.Join(repoPath, configFileName)

	data, err := os.ReadFile(cfgPath)
	if os.IsNotExist(err) {
		logger.Debug().Str("path", cfgPath).Msg(".armur.yml not found; using defaults")
		return &ArmurConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", cfgPath, err)
	}

	var cfg ArmurConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("could not parse %s: %w", cfgPath, err)
	}

	logger.Info().Str("path", cfgPath).Msg(".armur.yml loaded")
	return &cfg, nil
}

// IsToolEnabled returns true if the given tool should run given the config.
func (c *ArmurConfig) IsToolEnabled(toolName string) bool {
	// Explicit blocklist takes precedence.
	for _, d := range c.Tools.Disabled {
		if strings.EqualFold(d, toolName) {
			return false
		}
	}
	// If an allowlist is set, the tool must be in it.
	if len(c.Tools.Enabled) > 0 {
		for _, e := range c.Tools.Enabled {
			if strings.EqualFold(e, toolName) {
				return true
			}
		}
		return false
	}
	return true
}

// RunPlugin executes a custom plugin and returns its output as a generic
// result map under the "custom_tool" key. The {target} placeholder in
// Command is replaced with dirPath.
func (p *PluginConfig) RunPlugin(dirPath string) (map[string]interface{}, error) {
	if p.Command == "" {
		return nil, fmt.Errorf("plugin %q has no command configured", p.Name)
	}

	cmdStr := strings.ReplaceAll(p.Command, "{target}", dirPath)
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return nil, fmt.Errorf("plugin %q has empty command after substitution", p.Name)
	}

	cmd := exec.Command(parts[0], parts[1:]...) //nolint:gosec // plugin cmds are user-configured
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Info().Str("plugin", p.Name).Str("cmd", cmdStr).Msg("running plugin")
	if err := cmd.Run(); err != nil {
		logger.Warn().Str("plugin", p.Name).Err(err).Str("stderr", stderr.String()).Msg("plugin exited with error")
	}

	return map[string]interface{}{
		"custom_tool": []interface{}{
			map[string]interface{}{
				"plugin":  p.Name,
				"output":  stdout.String(),
				"format":  p.OutputFormat,
				"command": cmdStr,
			},
		},
	}, nil
}
