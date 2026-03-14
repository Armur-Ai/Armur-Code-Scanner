package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"armur-codescanner/internal/redis"
)

// ToolProgress represents the status of an individual tool execution.
type ToolProgress struct {
	Tool      string  `json:"tool"`
	Status    string  `json:"status"` // "running", "completed", "failed", "skipped"
	StartedAt int64   `json:"started_at,omitempty"`
	EndedAt   int64   `json:"ended_at,omitempty"`
	Findings  int     `json:"findings"`
	Error     string  `json:"error,omitempty"`
	Duration  float64 `json:"duration_secs,omitempty"`
}

// ScanProgress represents the overall progress of a scan task.
type ScanProgress struct {
	TaskID     string         `json:"task_id"`
	Status     string         `json:"status"` // "queued", "running", "completed", "failed"
	TotalTools int            `json:"total_tools"`
	Completed  int            `json:"completed"`
	StartedAt  int64          `json:"started_at"`
	Tools      []ToolProgress `json:"tools"`
}

// progressKey returns the Redis key for storing scan progress.
func progressKey(taskID string) string {
	return fmt.Sprintf("progress:%s", taskID)
}

// SaveScanProgress saves the current scan progress to Redis.
func SaveScanProgress(taskID string, progress *ScanProgress) error {
	ctx := context.Background()
	data, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	return redis.RedisClient().Set(ctx, progressKey(taskID), data, 2*time.Hour).Err()
}

// GetScanProgress retrieves the scan progress from Redis.
func GetScanProgress(taskID string) (*ScanProgress, error) {
	ctx := context.Background()
	data, err := redis.RedisClient().Get(ctx, progressKey(taskID)).Result()
	if err != nil {
		return nil, err
	}

	var progress ScanProgress
	if err := json.Unmarshal([]byte(data), &progress); err != nil {
		return nil, err
	}
	return &progress, nil
}

// InitProgress creates initial progress tracking for a scan.
func InitProgress(taskID string, tools []string) *ScanProgress {
	toolProgress := make([]ToolProgress, len(tools))
	for i, t := range tools {
		toolProgress[i] = ToolProgress{Tool: t, Status: "pending"}
	}

	progress := &ScanProgress{
		TaskID:     taskID,
		Status:     "running",
		TotalTools: len(tools),
		Completed:  0,
		StartedAt:  time.Now().Unix(),
		Tools:      toolProgress,
	}

	SaveScanProgress(taskID, progress)
	return progress
}

// UpdateToolStatus updates the status of a specific tool in the progress.
func UpdateToolStatus(progress *ScanProgress, tool, status string, findings int, toolErr string) {
	now := time.Now().Unix()
	for i := range progress.Tools {
		if progress.Tools[i].Tool == tool {
			progress.Tools[i].Status = status
			if status == "running" {
				progress.Tools[i].StartedAt = now
			}
			if status == "completed" || status == "failed" {
				progress.Tools[i].EndedAt = now
				progress.Tools[i].Findings = findings
				progress.Tools[i].Error = toolErr
				if progress.Tools[i].StartedAt > 0 {
					progress.Tools[i].Duration = float64(now - progress.Tools[i].StartedAt)
				}
				progress.Completed++
			}
			break
		}
	}
	SaveScanProgress(progress.TaskID, progress)
}
