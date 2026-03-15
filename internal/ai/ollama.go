package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// OllamaProvider implements AIProvider using a local Ollama instance.
type OllamaProvider struct {
	baseURL string
	model   string
}

// NewOllamaProvider creates a new Ollama provider.
func NewOllamaProvider(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "llama3.1:8b"
	}
	return &OllamaProvider{baseURL: baseURL, model: model}
}

func (o *OllamaProvider) Name() string { return "ollama" }

func (o *OllamaProvider) Available() bool {
	conn, err := net.DialTimeout("tcp", extractHost(o.baseURL), 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (o *OllamaProvider) Complete(ctx context.Context, prompt string, opts CompletionOpts) (string, error) {
	if !o.Available() {
		return "", fmt.Errorf("Ollama not reachable at %s", o.baseURL)
	}

	model := o.model
	if opts.Model != "" {
		model = opts.Model
	}

	body := map[string]interface{}{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}

	if opts.SystemPrompt != "" {
		body["system"] = opts.SystemPrompt
	}
	if opts.Temperature > 0 {
		body["options"] = map[string]interface{}{
			"temperature": opts.Temperature,
		}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/api/generate", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Ollama API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama error %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", err
	}

	return result.Response, nil
}

func (o *OllamaProvider) Stream(ctx context.Context, prompt string, opts CompletionOpts) (<-chan string, error) {
	ch := make(chan string, 1)
	go func() {
		defer close(ch)
		text, err := o.Complete(ctx, prompt, opts)
		if err != nil {
			ch <- fmt.Sprintf("Error: %v", err)
			return
		}
		ch <- text
	}()
	return ch, nil
}

// extractHost parses "http://localhost:11434" → "localhost:11434"
func extractHost(url string) string {
	host := url
	for _, prefix := range []string{"http://", "https://"} {
		if len(host) > len(prefix) && host[:len(prefix)] == prefix {
			host = host[len(prefix):]
		}
	}
	// Remove trailing slash
	if len(host) > 0 && host[len(host)-1] == '/' {
		host = host[:len(host)-1]
	}
	return host
}
