package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDelivery_Defaults(t *testing.T) {
	d := NewDelivery("https://example.com/hook", "secret")
	if d.MaxRetries != DefaultMaxRetries {
		t.Errorf("expected MaxRetries=%d, got %d", DefaultMaxRetries, d.MaxRetries)
	}
	if d.HTTPClient == nil {
		t.Error("expected non-nil HTTPClient")
	}
}

func TestSend_Success(t *testing.T) {
	received := false
	var receivedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		json.NewDecoder(r.Body).Decode(&receivedBody) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDelivery(srv.URL, "")
	result := d.Send("test-task-id", map[string]string{"status": "ok"})

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if result.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", result.Attempts)
	}
	if !received {
		t.Error("server did not receive the request")
	}
	if receivedBody["task_id"] != "test-task-id" {
		t.Errorf("unexpected task_id in payload: %v", receivedBody["task_id"])
	}
}

func TestSend_WithHMACSignature(t *testing.T) {
	var sigHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDelivery(srv.URL, "my-secret")
	d.Send("task-1", nil) //nolint:errcheck

	if sigHeader == "" {
		t.Error("expected X-Armur-Signature header to be set")
	}
	if len(sigHeader) <= len("sha256=") {
		t.Errorf("signature header looks too short: %q", sigHeader)
	}
}

func TestSend_RetriesOnFailure(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	d := NewDelivery(srv.URL, "")
	d.MaxRetries = 3
	d.HTTPClient = &http.Client{Timeout: DefaultTimeout}

	result := d.Send("retry-task", nil)
	if result.Err != nil {
		t.Fatalf("expected eventual success, got error: %v", result.Err)
	}
	if callCount != 3 {
		t.Errorf("expected 3 attempts, got %d", callCount)
	}
}

func TestSend_AllRetriesExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	d := NewDelivery(srv.URL, "")
	d.MaxRetries = 2
	d.HTTPClient = &http.Client{Timeout: DefaultTimeout}

	result := d.Send("fail-task", nil)
	if result.Err == nil {
		t.Error("expected error after exhausted retries, got nil")
	}
	if result.Attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", result.Attempts)
	}
}

func TestVerifySignature(t *testing.T) {
	payload := []byte(`{"task_id":"abc"}`)
	secret := "test-secret"
	sig := computeHMAC(payload, secret)

	if !VerifySignature(payload, secret, sig) {
		t.Error("expected valid signature to verify")
	}
	if VerifySignature(payload, secret, "sha256=bad") {
		t.Error("expected invalid signature to fail verification")
	}
	if VerifySignature(payload, "wrong-secret", sig) {
		t.Error("expected wrong secret to fail verification")
	}
}

func TestComputeHMAC_Format(t *testing.T) {
	sig := computeHMAC([]byte("hello"), "secret")
	if len(sig) < 7 || sig[:7] != "sha256=" {
		t.Errorf("expected 'sha256=' prefix, got %q", sig)
	}
}
