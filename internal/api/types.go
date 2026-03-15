package api

import "time"

// ScanSubmitResponse is returned when a scan is successfully enqueued.
type ScanSubmitResponse struct {
	TaskID   string    `json:"task_id"`
	QueuedAt time.Time `json:"queued_at"`
}

// ScanStatusResponse is returned when querying scan status.
type ScanStatusResponse struct {
	TaskID     string      `json:"task_id"`
	Status     string      `json:"status"` // pending, running, success, failed, cancelled
	StartedAt  *time.Time  `json:"started_at,omitempty"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
	Data       interface{} `json:"data,omitempty"`
	Meta       *ScanMeta   `json:"meta,omitempty"`
}

// ScanMeta holds metadata about the scan execution.
type ScanMeta struct {
	Language string   `json:"language,omitempty"`
	Mode     string   `json:"mode,omitempty"`
	ToolsRun []string `json:"tools_run,omitempty"`
	Duration float64  `json:"duration_secs,omitempty"`
}

// BatchScanRequest accepts multiple scan targets.
type BatchScanRequest struct {
	Targets []BatchTarget `json:"targets" binding:"required"`
}

// BatchTarget is a single target in a batch scan.
type BatchTarget struct {
	RepoURL  string `json:"repo_url,omitempty"`
	LocalPath string `json:"local_path,omitempty"`
	Language string `json:"language,omitempty"`
	Mode     string `json:"mode,omitempty"` // simple | advanced
}

// BatchScanResponse is returned when a batch scan is submitted.
type BatchScanResponse struct {
	BatchID string   `json:"batch_id"`
	TaskIDs []string `json:"task_ids"`
	Count   int      `json:"count"`
}

// ErrorResponse is a standard error format.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}
