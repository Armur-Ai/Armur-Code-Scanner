package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// APIClient handles communication with the Armur Code Scanner API.
type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewClient creates a new API client.
func NewClient(baseURL string) *APIClient {
	return &APIClient{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{},
	}
}

// ScanRepository initiates a scan of a remote Git repository.
func (c *APIClient) ScanRepository(repoURL, language string, isAdvanced bool) (string, error) {
	var endpoint string
	if isAdvanced {
		endpoint = "/api/v1/advanced-scan/repo"
	} else {
		endpoint = "/api/v1/scan/repo"
	}

	fullURL := strings.TrimRight(c.BaseURL, "/") + endpoint

	requestBody, err := json.Marshal(map[string]string{
		"repository_url": repoURL,
		"language":       language,
	})
	if err != nil {
		return "", fmt.Errorf("error creating request body: %w", err)
	}

	resp, err := c.HTTPClient.Post(fullURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("error making API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding API response: %w", err)
	}

	taskID, ok := result["task_id"]
	if !ok {
		return "", fmt.Errorf("task_id not found in API response")
	}

	return taskID, nil
}

// ScanFile initiates a scan of a local file via multipart upload.
func (c *APIClient) ScanFile(filePath string, isAdvanced bool) (string, error) {
	endpoint := "/api/v1/scan/file"
	fullURL := strings.TrimRight(c.BaseURL, "/") + endpoint

	requestBody, err := json.Marshal(map[string]string{
		"file_path": filePath,
	})
	if err != nil {
		return "", fmt.Errorf("error creating request body: %w", err)
	}

	resp, err := c.HTTPClient.Post(fullURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("error making API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding API response: %w", err)
	}

	taskID, ok := result["task_id"]
	if !ok {
		return "", fmt.Errorf("task_id not found in API response")
	}

	return taskID, nil
}

// GetTaskStatus retrieves the status of a specific scan task.
func (c *APIClient) GetTaskStatus(taskID string) (string, map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/api/v1/status/%s", strings.TrimRight(c.BaseURL, "/"), taskID)

	resp, err := c.HTTPClient.Get(endpoint)
	if err != nil {
		return "", nil, fmt.Errorf("error making API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("error decoding API response: %w", err)
	}

	status, ok := result["status"].(string)
	if !ok {
		return "", nil, fmt.Errorf("status not found in API response")
	}

	var data map[string]interface{}
	if status == "success" {
		data, ok = result["data"].(map[string]interface{})
		if !ok {
			return status, nil, fmt.Errorf("data not found or not a map in API response")
		}
	}

	return status, data, nil
}

// GetOwaspReport retrieves the OWASP report for a completed scan task.
func (c *APIClient) GetOwaspReport(taskID string) (interface{}, error) {
	endpoint := fmt.Sprintf("%s/api/v1/reports/owasp/%s", strings.TrimRight(c.BaseURL, "/"), taskID)

	resp, err := c.HTTPClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error making API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	var report interface{}
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("error decoding API response: %w", err)
	}

	return report, nil
}

// GetSansReport retrieves the SANS report for a completed scan task.
func (c *APIClient) GetSansReport(taskID string) (interface{}, error) {
	endpoint := fmt.Sprintf("%s/api/v1/reports/sans/%s", strings.TrimRight(c.BaseURL, "/"), taskID)

	resp, err := c.HTTPClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error making API request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %w", err)
	}

	var report interface{}
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("error decoding API response: %w", err)
	}

	return report, nil
}
