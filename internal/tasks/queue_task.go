package tasks

import (
	"armur-codescanner/internal/redis"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

// ScanOptions holds optional parameters for a scan task.
type ScanOptions struct {
	WebhookURL    string
	WebhookSecret string
}

// EnqueueScanTask enqueues a scan task and returns its task ID.
func EnqueueScanTask(scanType, repoURL, language string, opts ...ScanOptions) (string, error) {
	taskID := uuid.New().String()

	payload := map[string]string{
		"repository_url": repoURL,
		"language":       language,
		"scan_type":      scanType,
		"task_id":        taskID,
	}

	// Apply optional webhook settings.
	if len(opts) > 0 {
		if opts[0].WebhookURL != "" {
			payload["webhook_url"] = opts[0].WebhookURL
		}
		if opts[0].WebhookSecret != "" {
			payload["webhook_secret"] = opts[0].WebhookSecret
		}
	}

	taskPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	client := asynq.NewClient(redis.RedisClientOptions())
	defer client.Close()

	task := asynq.NewTask("scan:repo", taskPayload)
	_, err = client.Enqueue(task, asynq.Queue("default"), asynq.MaxRetry(3), asynq.Timeout(30*time.Minute))
	if err != nil {
		return "", err
	}

	return taskID, nil
}
