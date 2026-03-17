package api

import (
	"armur-codescanner/internal/middleware"
	"armur-codescanner/internal/tasks"
	utils "armur-codescanner/pkg"
	"armur-codescanner/pkg/sarif"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// validLanguages is the set of language codes accepted by the scan API.
var validLanguages = map[string]bool{
	"go": true, "py": true, "js": true,
	"rust": true, "java": true, "ruby": true,
	"php": true, "c": true, "iac": true, "sol": true,
}

// isValidLanguage returns true when lang is a recognised language code.
func isValidLanguage(lang string) bool {
	return validLanguages[lang]
}

// reposBaseDir returns the base directory for temporary scan files.
// Reads ARMUR_REPOS_DIR env var; falls back to /armur/repos.
func reposBaseDir() string {
	if d := os.Getenv("ARMUR_REPOS_DIR"); d != "" {
		return d
	}
	return "/armur/repos"
}

// ScanRequest represents a scan request for a github repository with a specified language
type ScanRequest struct {
	RepositoryURL string `json:"repository_url" example:"https://github.com/Armur-Ai/Armur-Code-Scanner"`
	Language      string `json:"language" example:"go"`
	WebhookURL    string `json:"webhook_url,omitempty" example:"https://hooks.example.com/armur"`
	WebhookSecret string `json:"webhook_secret,omitempty" example:"my-hmac-secret"`
}

// LocalScanRequest represents a scan request for a local repository with a specified language
type LocalScanRequest struct {
	LocalPath        string `json:"local_path" binding:"required" example:"/armur/repo"`
	Language         string `json:"language" example:"go"`
	DiffBaseRef      string `json:"diff_base_ref" example:"HEAD~1"`
	ChangedFilesOnly bool   `json:"changed_files_only" example:"false"`
}

// ScanHandler godoc
// @Summary Trigger a code scan on a repository.
// @Description Enqueues a scan task for a given repository URL and language.
// @Tags scan
// @Accept json
// @Produce json
// @Param request body ScanRequest true "Request body containing repository URL and language"
// @Success 200 {object} map[string]string  "Successfully enqueued task"
// @Failure 400 {object} map[string]string "Invalid request parameters"
// @Failure 500 {object} map[string]string "Failed to enqueue scan task"
// @Router /api/v1/scan/repo [post]
func ScanHandler(c *gin.Context) {
	var request ScanRequest

	// Bind JSON to struct
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := middleware.ValidateGitURL(request.RepositoryURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.Language != "" && !isValidLanguage(request.Language) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid language: must be one of go, py, js, rust, java, ruby, php, c, iac, sol"})
		return
	}

	// Enqueue the scan task
	taskID, err := tasks.EnqueueScanTask(utils.SimpleScan, request.RepositoryURL, request.Language,
		tasks.ScanOptions{WebhookURL: request.WebhookURL, WebhookSecret: request.WebhookSecret})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue scan task", "details": err.Error()})
		return
	}

	// Respond with the Task ID
	c.JSON(http.StatusOK, gin.H{"task_id": taskID})
}

// AdvancedScanResult godoc
// @Summary Trigger a code scan on a repository with advanced scans.
// @Description Enqueues an advanced scan task for a given repository URL and language.
// @Tags scan
// @Accept json
// @Produce json
// @Param request body ScanRequest true "Request body containing repository URL and language"
// @Success 200 {object} map[string]string "Successfully enqueued task"
// @Failure 400 {object} map[string]string "Invalid request parameters"
// @Failure 500 {object} map[string]string "Failed to enqueue scan task"
// @Router /api/v1/advanced-scan/repo [post]
func AdvancedScanResult(c *gin.Context) {
	var request ScanRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := middleware.ValidateGitURL(request.RepositoryURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.Language != "" && !isValidLanguage(request.Language) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid language: must be one of go, py, js, rust, java, ruby, php, c, iac, sol"})
		return
	}

	taskID, err := tasks.EnqueueScanTask(utils.AdvancedScan, request.RepositoryURL, request.Language,
		tasks.ScanOptions{WebhookURL: request.WebhookURL, WebhookSecret: request.WebhookSecret})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue scan task", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"task_id": taskID})
}

// ScanFile godoc
// @Summary Trigger a code scan on file.
// @Description Enqueues a scan task for a given file.
// @Tags scan
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "File to be scanned"
// @Success 202 {object} map[string]string "Successfully enqueued task"
// @Failure 400 {object} map[string]string "No file part or no selected file"
// @Failure 500 {object} map[string]string "Failed to create temp directory or Failed to save file"
// @Router /api/v1/scan/file [post]
func ScanFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil || file.Filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file part or no selected file"})
		return
	}

	baseDir := reposBaseDir()
	if err := os.MkdirAll(baseDir, os.ModePerm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create base directory", "details": err.Error()})
		return
	}

	tempDir, err := os.MkdirTemp(baseDir, "scan")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create temp directory", "details": err.Error()})
		return
	}

	filePath := filepath.Join(tempDir, file.Filename)
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file", "details": err.Error()})
		return
	}

	taskID, err := tasks.EnqueueScanTask(utils.FileScan, filePath, filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue scan task", "details": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"task_id": taskID,
	})
}

// TaskStatus godoc
// @Summary Get task status and results.
// @Description Get the status and results of a scan task by its ID.
//
//	Supports ?format=sarif to return SARIF 2.1.0 output.
//
// @Tags scan
// @Produce json
// @Param task_id path string true "Task ID"
// @Param format query string false "Output format (json, sarif)" Enums(json, sarif)
// @Success 200 {object} map[string]interface{} "Successfully retrieved task result"
// @Router /api/v1/status/{task_id} [get]
func TaskStatus(c *gin.Context) {
	taskID := c.Param("task_id")
	if !middleware.ValidateTaskID(taskID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id format"})
		return
	}

	result, err := tasks.GetTaskResult(taskID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "pending",
			"task_id": taskID,
		})
		return
	}

	// Support SARIF output format via ?format=sarif query param.
	if strings.EqualFold(c.Query("format"), "sarif") {
		scanMap, _ := result.(map[string]interface{})
		sarifLog := sarif.FromScanResults(scanMap, "")
		data, marshalErr := sarifLog.Marshal()
		if marshalErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to marshal SARIF output"})
			return
		}
		c.Data(http.StatusOK, "application/json", data)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"data":    result,
		"task_id": taskID,
	})
}

// TaskOwasp godoc
// @Summary Get OWASP report for a task result.
// @Description Generates OWASP report from a specific task result using task ID.
// @Tags report
// @Produce json
// @Param task_id path string true "Task ID"
// @Success 200 {object} []utils.ReportItem "Successfully generated OWASP report"
// @Failure 404 {object} map[string]string "Task result not found"
// @Failure 500 {object} map[string]string "Failed to fetch task result"
// @Router /api/v1/reports/owasp/{task_id} [get]
func TaskOwasp(c *gin.Context) {
	taskID := c.Param("task_id")
	if !middleware.ValidateTaskID(taskID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id format"})
		return
	}

	// Fetch task result from Redis
	taskResult, err := tasks.GetTaskResult(taskID)
	if err != nil {
		if err.Error() == "task result not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Task result not found. Pls wait"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch task result", "details": err.Error()})
		}
		return
	}

	report, err := utils.GenerateOwaspReport(taskResult)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

// TaskSans godoc
// @Summary Get SANS report for a task result.
// @Description Generates SANS report from a specific task result using task ID.
// @Tags report
// @Produce json
// @Param task_id path string true "Task ID"
// @Success 200 {object} []utils.SANSReportItem "Successfully generated SANS report"
// @Failure 404 {object} map[string]string "Task result not found"
// @Failure 500 {object} map[string]string "Failed to fetch task result"
// @Router /api/v1/reports/sans/{task_id} [get]
func TaskSans(c *gin.Context) {
	taskID := c.Param("task_id")
	if !middleware.ValidateTaskID(taskID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id format"})
		return
	}

	// Fetch task result from Redis
	taskResult, err := tasks.GetTaskResult(taskID)
	if err != nil {
		if err.Error() == "task result not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Task result not found. Pls wait"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch task result", "details": err.Error()})
		}
		return
	}

	report, err := utils.GenerateSANSReports(taskResult)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

// HealthCheck returns the server health status.
func HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "vibescan",
	})
}

// ReadinessCheck returns whether the server is ready to accept requests.
func ReadinessCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
	})
}

// CancelScan cancels an in-progress scan task.
func CancelScan(c *gin.Context) {
	taskID := c.Param("task_id")
	if !middleware.ValidateTaskID(taskID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id format"})
		return
	}

	if err := tasks.CancelTask(taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cancel task", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "cancelled", "task_id": taskID})
}

// TaskProgress streams scan progress via Server-Sent Events (SSE).
// The client connects and receives real-time updates as tools execute.
func TaskProgress(c *gin.Context) {
	taskID := c.Param("task_id")
	if !middleware.ValidateTaskID(taskID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id format"})
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
		return
	}

	ctx := c.Request.Context()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			progress, err := tasks.GetScanProgress(taskID)
			if err != nil {
				// No progress yet — task may be queued
				fmt.Fprintf(c.Writer, "data: {\"status\":\"queued\",\"task_id\":%q}\n\n", taskID)
				flusher.Flush()
				continue
			}

			data, _ := json.Marshal(progress)
			fmt.Fprintf(c.Writer, "data: %s\n\n", data)
			flusher.Flush()

			// Stop streaming when scan is done
			if progress.Status == "completed" || progress.Status == "failed" {
				return
			}
		}
	}
}

// BatchScan enqueues multiple scan tasks at once.
func BatchScan(c *gin.Context) {
	var request BatchScanRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(request.Targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one target required"})
		return
	}

	batchID := fmt.Sprintf("batch-%d", time.Now().UnixNano())
	var taskIDs []string

	for _, target := range request.Targets {
		scanType := "SimpleScan"
		if target.Mode == "advanced" {
			scanType = "AdvancedScan"
		}

		repoOrPath := target.RepoURL
		if repoOrPath == "" {
			repoOrPath = target.LocalPath
		}

		taskID, err := tasks.EnqueueScanTask(scanType, repoOrPath, target.Language)
		if err != nil {
			continue // Skip failed enqueues, don't fail the batch
		}
		taskIDs = append(taskIDs, taskID)
	}

	c.JSON(http.StatusOK, BatchScanResponse{
		BatchID: batchID,
		TaskIDs: taskIDs,
		Count:   len(taskIDs),
	})
}

// ScanLocalHandler godoc
// @Summary Trigger a code scan on a local repository.
// @Description Enqueues a scan task for a given local repository path and language.
// @Tags scan
// @Accept json
// @Produce json
// @Param request body LocalScanRequest true "Request body containing local path and language"
// @Success 200 {object} map[string]string "Successfully enqueued task"
// @Failure 400 {object} map[string]string "Invalid request parameters"
// @Failure 500 {object} map[string]string "Failed to enqueue scan task"
// @Router /api/v1/scan/local [post]
func ScanLocalHandler(c *gin.Context) {
	var request LocalScanRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.LocalPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Local path is required"})
		return
	}

	// Sanitize path to prevent path traversal attacks (CWE-22).
	sanitizedPath, err := middleware.SanitizeLocalPath(request.LocalPath)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if request.Language != "" && !isValidLanguage(request.Language) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid language: must be one of go, py, js, rust, java, ruby, php, c, iac, sol"})
		return
	}

	// Verify the path exists and is a directory
	if info, err := os.Stat(sanitizedPath); os.IsNotExist(err) || !info.IsDir() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or non-existent directory"})
		return
	}

	// Enqueue the scan task with "local" scan type
	taskID, err := tasks.EnqueueScanTask(utils.SimpleScan, sanitizedPath, request.Language)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enqueue scan task", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"task_id": taskID})
}
