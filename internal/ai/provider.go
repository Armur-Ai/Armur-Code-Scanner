package ai

import (
	"context"
	"fmt"
	"os"
)

// AIProvider defines the interface for AI backends (Claude, Ollama, etc.).
type AIProvider interface {
	Complete(ctx context.Context, prompt string, opts CompletionOpts) (string, error)
	Stream(ctx context.Context, prompt string, opts CompletionOpts) (<-chan string, error)
	Name() string
	Available() bool
}

// CompletionOpts controls generation parameters.
type CompletionOpts struct {
	MaxTokens    int
	Temperature  float64
	SystemPrompt string
	Model        string // override default model
}

// DefaultOpts returns sensible defaults for completions.
func DefaultOpts() CompletionOpts {
	return CompletionOpts{
		MaxTokens:   2048,
		Temperature: 0.3,
	}
}

// ProviderConfig stores AI provider configuration.
type ProviderConfig struct {
	Provider     string `json:"provider" yaml:"provider"`           // claude | ollama | auto | none
	ClaudeModel  string `json:"claude_model" yaml:"claude_model"`   // default: claude-sonnet-4-6
	OllamaModel  string `json:"ollama_model" yaml:"ollama_model"`   // default: llama3.1:8b
	OllamaURL    string `json:"ollama_url" yaml:"ollama_url"`       // default: http://localhost:11434
}

// DefaultProviderConfig returns sensible defaults.
func DefaultProviderConfig() ProviderConfig {
	return ProviderConfig{
		Provider:    "auto",
		ClaudeModel: "claude-sonnet-4-6",
		OllamaModel: "llama3.1:8b",
		OllamaURL:   "http://localhost:11434",
	}
}

// GetProvider returns the best available AI provider based on config and availability.
func GetProvider(cfg ProviderConfig) (AIProvider, error) {
	switch cfg.Provider {
	case "claude":
		p := NewClaudeProvider(cfg.ClaudeModel)
		if !p.Available() {
			return nil, fmt.Errorf("Claude API key not configured (set ANTHROPIC_API_KEY)")
		}
		return p, nil

	case "ollama":
		p := NewOllamaProvider(cfg.OllamaURL, cfg.OllamaModel)
		if !p.Available() {
			return nil, fmt.Errorf("Ollama not reachable at %s", cfg.OllamaURL)
		}
		return p, nil

	case "none":
		return nil, fmt.Errorf("AI features disabled (provider: none)")

	default: // "auto"
		// Try Claude first (best quality), then Ollama (free/local)
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			p := NewClaudeProvider(cfg.ClaudeModel)
			if p.Available() {
				return p, nil
			}
		}

		p := NewOllamaProvider(cfg.OllamaURL, cfg.OllamaModel)
		if p.Available() {
			return p, nil
		}

		return nil, fmt.Errorf("no AI provider available; set ANTHROPIC_API_KEY or start Ollama")
	}
}
