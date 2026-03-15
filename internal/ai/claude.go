package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const claudeAPIURL = "https://api.anthropic.com/v1/messages"

// ClaudeProvider implements AIProvider using the Anthropic Claude API.
type ClaudeProvider struct {
	apiKey string
	model  string
}

// NewClaudeProvider creates a new Claude API provider.
func NewClaudeProvider(model string) *ClaudeProvider {
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	return &ClaudeProvider{
		apiKey: os.Getenv("ANTHROPIC_API_KEY"),
		model:  model,
	}
}

func (c *ClaudeProvider) Name() string { return "claude" }

func (c *ClaudeProvider) Available() bool {
	return c.apiKey != ""
}

func (c *ClaudeProvider) Complete(ctx context.Context, prompt string, opts CompletionOpts) (string, error) {
	if !c.Available() {
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	model := c.model
	if opts.Model != "" {
		model = opts.Model
	}
	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2048
	}

	messages := []map[string]string{
		{"role": "user", "content": prompt},
	}

	body := map[string]interface{}{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   messages,
	}

	if opts.SystemPrompt != "" {
		body["system"] = opts.SystemPrompt
	}
	if opts.Temperature > 0 {
		body["temperature"] = opts.Temperature
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", claudeAPIURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Claude API error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response error: %w", err)
	}

	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude")
	}
	return result.Content[0].Text, nil
}

func (c *ClaudeProvider) Stream(ctx context.Context, prompt string, opts CompletionOpts) (<-chan string, error) {
	// For now, use non-streaming and send as single chunk
	ch := make(chan string, 1)
	go func() {
		defer close(ch)
		text, err := c.Complete(ctx, prompt, opts)
		if err != nil {
			ch <- fmt.Sprintf("Error: %v", err)
			return
		}
		ch <- text
	}()
	return ch, nil
}
