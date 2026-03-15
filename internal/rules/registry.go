package rules

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const registryURL = "https://raw.githubusercontent.com/armur-ai/armur-templates/main/index.json"

// RulePack represents a downloadable rule pack from the registry.
type RulePack struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Type        string   `json:"type"` // rules, exploits, sandboxes, fixes, chains
	Description string   `json:"description"`
	Languages   []string `json:"languages"`
	RuleCount   int      `json:"rule_count"`
	Author      string   `json:"author"`
	Downloads   int      `json:"downloads"`
	URL         string   `json:"url"`
}

// Registry holds the index of available rule packs.
type Registry struct {
	Packs    []RulePack `json:"packs"`
	FetchedAt time.Time `json:"fetched_at"`
}

// FetchRegistry downloads the latest rule pack index.
func FetchRegistry() (*Registry, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(registryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch registry: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var reg Registry
	if err := json.Unmarshal(body, &reg); err != nil {
		return nil, fmt.Errorf("failed to parse registry: %w", err)
	}
	reg.FetchedAt = time.Now()
	return &reg, nil
}

// InstalledDir returns the path where rules are installed locally.
func InstalledDir() string {
	return filepath.Join(os.Getenv("HOME"), ".armur", "templates")
}

// InstallPack downloads and installs a rule pack.
func InstallPack(pack RulePack) error {
	dir := filepath.Join(InstalledDir(), pack.Name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Download the pack archive
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(pack.URL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	// Save to local directory
	outPath := filepath.Join(dir, "rules.tar.gz")
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	// Write metadata
	meta, _ := json.MarshalIndent(pack, "", "  ")
	return os.WriteFile(filepath.Join(dir, "metadata.json"), meta, 0644)
}

// ListInstalled returns all locally installed rule packs.
func ListInstalled() ([]RulePack, error) {
	baseDir := InstalledDir()
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var packs []RulePack
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(baseDir, entry.Name(), "metadata.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var pack RulePack
		if err := json.Unmarshal(data, &pack); err != nil {
			continue
		}
		packs = append(packs, pack)
	}
	return packs, nil
}

// RemovePack removes an installed rule pack.
func RemovePack(name string) error {
	dir := filepath.Join(InstalledDir(), name)
	return os.RemoveAll(dir)
}

// SearchPacks filters packs by keyword in name, description, or languages.
func SearchPacks(packs []RulePack, query string) []RulePack {
	var results []RulePack
	for _, p := range packs {
		if contains(p.Name, query) || contains(p.Description, query) {
			results = append(results, p)
			continue
		}
		for _, lang := range p.Languages {
			if contains(lang, query) {
				results = append(results, p)
				break
			}
		}
	}
	return results
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsLower(s, substr)))
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldSlice(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFoldSlice(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
