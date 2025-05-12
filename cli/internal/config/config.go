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
	APIKey struct {
		URL string `json:"url"`
	} `json:"api_key"`
}

// configFilePath is the path to the configuration file.
var configFilePath = filepath.Join(os.Getenv("HOME"), ".armur", "config.json")

// LoadConfig loads the configuration from the config file.
func LoadConfig() (*Config, error) {
	// Default configuration
	defaultCfg := &Config{}
	defaultCfg.API.URL = "http://localhost:4500"

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

	// If config file was empty or API URL was not set, use default
	if cfg.API.URL == "" {
		cfg.API.URL = defaultCfg.API.URL
	}

	return &cfg, nil
}

// SaveConfig saves the configuration to the config file.
func SaveConfig(cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(configFilePath), 0755); err != nil {
		return fmt.Errorf("error creating config directory: %w", err)
	}

	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
