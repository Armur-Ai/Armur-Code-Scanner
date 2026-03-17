package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the CLI configuration.
type Config struct {
	API struct {
		URL string `json:"url"`
	} `json:"api"`
	Redis struct {
		URL string `json:"url"`
	} `json:"redis"`
	APIKey string `json:"api_key"`
}

// configFilePath is the path to the configuration file.
var configFilePath = filepath.Join(os.Getenv("HOME"), ".vibescan", "config.json")

// LoadConfig loads the configuration from the config file.
func LoadConfig() (*Config, error) {
	// Default configuration
	defaultCfg := &Config{}
	defaultCfg.API.URL = "http://localhost:4500"

	// ARMUR_API_KEY env var takes precedence over config file
	if key := os.Getenv("ARMUR_API_KEY"); key != "" {
		defaultCfg.APIKey = key
	}

	// Create config file if it doesn't exist
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		return defaultCfg, nil
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %w", err)
	}

	if cfg.API.URL == "" {
		cfg.API.URL = defaultCfg.API.URL
	}

	// Env var takes precedence over stored key
	if key := os.Getenv("ARMUR_API_KEY"); key != "" {
		cfg.APIKey = key
	}

	return &cfg, nil
}

// SaveConfig saves the configuration to the config file.
func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(configFilePath), 0755); err != nil {
		return fmt.Errorf("error creating config directory: %w", err)
	}

	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
