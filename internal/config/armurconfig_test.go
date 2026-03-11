package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProjectConfig_NoFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadProjectConfig(dir)
	if err != nil {
		t.Fatalf("expected no error when .armur.yml is absent, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config for missing file")
	}
}

func TestLoadProjectConfig_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `
exclude:
  - vendor/**
  - "**/*.pb.go"
tools:
  enabled:
    - gosec
    - semgrep
  disabled:
    - pylint
severity-threshold: medium
fail-on-findings: true
plugins:
  - name: my-tool
    command: echo {target}
    output-format: text
    language: go
`
	if err := os.WriteFile(filepath.Join(dir, ".armur.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadProjectConfig(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Exclude) != 2 {
		t.Errorf("expected 2 exclude patterns, got %d", len(cfg.Exclude))
	}
	if len(cfg.Tools.Enabled) != 2 {
		t.Errorf("expected 2 enabled tools, got %d", len(cfg.Tools.Enabled))
	}
	if len(cfg.Tools.Disabled) != 1 {
		t.Errorf("expected 1 disabled tool, got %d", len(cfg.Tools.Disabled))
	}
	if cfg.SeverityThreshold != "medium" {
		t.Errorf("expected severity-threshold=medium, got %q", cfg.SeverityThreshold)
	}
	if !cfg.FailOnFindings {
		t.Error("expected fail-on-findings=true")
	}
	if len(cfg.Plugins) != 1 {
		t.Errorf("expected 1 plugin, got %d", len(cfg.Plugins))
	}
	if cfg.Plugins[0].Name != "my-tool" {
		t.Errorf("expected plugin name 'my-tool', got %q", cfg.Plugins[0].Name)
	}
}

func TestLoadProjectConfig_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	// Use a YAML mapping key with a tab character which is invalid in YAML.
	content := "tools:\n\tenabled:\n\t\t- gosec\n"
	if err := os.WriteFile(filepath.Join(dir, ".armur.yml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadProjectConfig(dir)
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}

func TestIsToolEnabled_AllowlistEmpty(t *testing.T) {
	cfg := &ArmurConfig{}
	if !cfg.IsToolEnabled("gosec") {
		t.Error("tool should be enabled when allowlist is empty")
	}
}

func TestIsToolEnabled_AllowlistMatchCaseInsensitive(t *testing.T) {
	cfg := &ArmurConfig{
		Tools: ToolsConfig{Enabled: []string{"GoSec", "semgrep"}},
	}
	if !cfg.IsToolEnabled("gosec") {
		t.Error("gosec should match GoSec case-insensitively")
	}
	if cfg.IsToolEnabled("bandit") {
		t.Error("bandit should not be enabled when allowlist is set and doesn't include it")
	}
}

func TestIsToolEnabled_Blocklist(t *testing.T) {
	cfg := &ArmurConfig{
		Tools: ToolsConfig{Disabled: []string{"pylint"}},
	}
	if cfg.IsToolEnabled("pylint") {
		t.Error("pylint should be disabled")
	}
	if !cfg.IsToolEnabled("gosec") {
		t.Error("gosec should be enabled when not in blocklist")
	}
}

func TestIsToolEnabled_BlocklistOverridesAllowlist(t *testing.T) {
	// A tool in both lists should be disabled (blocklist wins).
	cfg := &ArmurConfig{
		Tools: ToolsConfig{
			Enabled:  []string{"gosec"},
			Disabled: []string{"gosec"},
		},
	}
	if cfg.IsToolEnabled("gosec") {
		t.Error("gosec should be disabled when in both enabled and disabled lists")
	}
}

func TestRunPlugin_EmptyCommand(t *testing.T) {
	p := &PluginConfig{Name: "empty"}
	_, err := p.RunPlugin("/tmp")
	if err == nil {
		t.Error("expected error for plugin with empty command")
	}
}

func TestRunPlugin_EchoCommand(t *testing.T) {
	p := &PluginConfig{
		Name:         "echo-test",
		Command:      "echo {target}",
		OutputFormat: "text",
	}
	result, err := p.RunPlugin("/tmp/testdir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	items, ok := result["custom_tool"].([]interface{})
	if !ok || len(items) != 1 {
		t.Errorf("expected 1 custom_tool entry, got %v", result["custom_tool"])
	}
}
