// Package webhook delivers scan results to a user-configured HTTP endpoint.
// It signs the payload with HMAC-SHA256 and retries on failure with
// exponential back-off.
package webhook

import (
	"armur-codescanner/internal/logger"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	// SignatureHeader is the HTTP header used to transmit the HMAC signature.
	SignatureHeader = "X-Armur-Signature"

	// DefaultMaxRetries is the number of delivery attempts before giving up.
	DefaultMaxRetries = 3

	// DefaultTimeout is the HTTP client timeout per attempt.
	DefaultTimeout = 15 * time.Second
)

// Delivery describes a single webhook delivery.
type Delivery struct {
	// URL is the endpoint to POST the payload to.
	URL string

	// Secret is used to compute the HMAC-SHA256 signature.
	// If empty, no signature header is added.
	Secret string

	// MaxRetries controls how many attempts are made (default: 3).
	MaxRetries int

	// HTTPClient allows test injection. When nil, a default client is used.
	HTTPClient *http.Client
}

// DeliveryResult captures the outcome of a webhook delivery.
type DeliveryResult struct {
	StatusCode int
	Attempts   int
	Err        error
}

// NewDelivery constructs a Delivery with sensible defaults.
func NewDelivery(url, secret string) *Delivery {
	return &Delivery{
		URL:        url,
		Secret:     secret,
		MaxRetries: DefaultMaxRetries,
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
	}
}

// Send POSTs the payload to the configured URL.
// It retries up to MaxRetries times with exponential back-off (1s, 2s, 4s).
func (d *Delivery) Send(taskID string, result interface{}) DeliveryResult {
	payload, err := json.Marshal(map[string]interface{}{
		"task_id": taskID,
		"result":  result,
	})
	if err != nil {
		return DeliveryResult{Err: fmt.Errorf("failed to marshal payload: %w", err)}
	}

	client := d.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}

	maxRetries := d.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}

	var lastErr error
	var lastStatus int
	backoff := time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest(http.MethodPost, d.URL, bytes.NewReader(payload))
		if err != nil {
			return DeliveryResult{Attempts: attempt, Err: fmt.Errorf("failed to build request: %w", err)}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "armur-webhook/1.0")

		if d.Secret != "" {
			req.Header.Set(SignatureHeader, computeHMAC(payload, d.Secret))
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			logger.Warn().
				Str("url", d.URL).
				Str("task_id", taskID).
				Int("attempt", attempt).
				Err(err).
				Msg("webhook delivery failed, will retry")
		} else {
			lastStatus = resp.StatusCode
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				logger.Info().
					Str("url", d.URL).
					Str("task_id", taskID).
					Int("attempt", attempt).
					Int("status", resp.StatusCode).
					Msg("webhook delivered successfully")
				return DeliveryResult{StatusCode: lastStatus, Attempts: attempt}
			}
			lastErr = fmt.Errorf("webhook returned non-2xx status %d", resp.StatusCode)
			logger.Warn().
				Str("url", d.URL).
				Str("task_id", taskID).
				Int("attempt", attempt).
				Int("status", resp.StatusCode).
				Msg("webhook delivery non-2xx, will retry")
		}

		if attempt < maxRetries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	logger.Error().
		Str("url", d.URL).
		Str("task_id", taskID).
		Int("attempts", maxRetries).
		Err(lastErr).
		Msg("webhook delivery failed after all retries")

	return DeliveryResult{StatusCode: lastStatus, Attempts: maxRetries, Err: lastErr}
}

// computeHMAC returns "sha256=<hex>" suitable for the signature header.
func computeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks an inbound HMAC signature header against the expected
// value. Use this in your webhook receiver to authenticate deliveries.
func VerifySignature(payload []byte, secret, sigHeader string) bool {
	expected := computeHMAC(payload, secret)
	return hmac.Equal([]byte(sigHeader), []byte(expected))
}
