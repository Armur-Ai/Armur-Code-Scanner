package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newRouter() *gin.Engine {
	r := gin.New()
	r.POST("/scan/repo", ScanHandler)
	r.POST("/advanced-scan/repo", AdvancedScanResult)
	r.POST("/scan/local", ScanLocalHandler)
	r.GET("/status/:task_id", TaskStatus)
	return r
}

func TestScanHandler_InvalidJSON(t *testing.T) {
	r := newRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/repo", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestScanHandler_InvalidScheme(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"repository_url": "http://github.com/user/repo",
		"language":       "go",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/repo", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for http:// URL, got %d", w.Code)
	}
}

func TestScanHandler_InvalidLanguage(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"repository_url": "https://github.com/user/repo",
		"language":       "cobol",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/repo", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported language, got %d", w.Code)
	}
}

func TestScanHandler_EmptyURL(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"repository_url": "",
		"language":       "go",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/repo", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty URL, got %d", w.Code)
	}
}

func TestAdvancedScanResult_InvalidLanguage(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"repository_url": "https://github.com/user/repo",
		"language":       "cobol",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/advanced-scan/repo", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported language, got %d", w.Code)
	}
}

func TestScanLocalHandler_MissingPath(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"language": "go",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/local", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing local_path, got %d", w.Code)
	}
}

func TestScanLocalHandler_NonExistentPath(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"local_path": "/does/not/exist/12345",
		"language":   "go",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/local", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-existent path, got %d", w.Code)
	}
}

func TestScanLocalHandler_InvalidLanguage(t *testing.T) {
	r := newRouter()
	body, _ := json.Marshal(map[string]string{
		"local_path": "/tmp",
		"language":   "cobol",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan/local", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported language, got %d", w.Code)
	}
}

func TestTaskStatus_InvalidTaskID(t *testing.T) {
	r := newRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status/not-a-valid-uuid", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid task_id, got %d", w.Code)
	}
}

func TestTaskStatus_ValidTaskID_NoRedis(t *testing.T) {
	// With a valid UUID but no Redis, the handler should return pending (200)
	// because GetTaskResult returns an error => pending status
	r := newRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status/550e8400-e29b-41d4-a716-446655440000", nil)
	r.ServeHTTP(w, req)
	// Either 200 (pending) or 500 depending on whether Redis is reachable
	// The important thing is it doesn't panic and doesn't return 400
	if w.Code == http.StatusBadRequest {
		t.Error("valid UUID should not return 400")
	}
}
