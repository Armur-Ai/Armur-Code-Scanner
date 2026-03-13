package worker

import (
	"armur-codescanner/internal/logger"
	"armur-codescanner/internal/tasks"
	"armur-codescanner/internal/webhook"
	utils "armur-codescanner/pkg"
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"
)

type ScanTaskHandler struct{}

func (h *ScanTaskHandler) ProcessTask(ctx context.Context, task *asynq.Task) error {

	var taskData map[string]string
	if err := json.Unmarshal(task.Payload(), &taskData); err != nil {
		return fmt.Errorf("failed to unmarshal task payload: %w", err)
	}

	repoURL := taskData["repository_url"]
	language := taskData["language"]
	scanType := taskData["scan_type"]
	taskID := taskData["task_id"]
	webhookURL := taskData["webhook_url"]
	webhookSecret := taskData["webhook_secret"]

	var result map[string]interface{}
	switch scanType {
	case utils.SimpleScan:
		result = tasks.RunScanTask(repoURL, language)
	case utils.AdvancedScan:
		result = tasks.AdvancedScanRepositoryTask(repoURL, language)
	case utils.FileScan:
		result, _ = tasks.ScanFileTask(repoURL)
	case utils.LocalScan:
		result = tasks.RunScanTaskLocal(repoURL, language)
	default:
		return fmt.Errorf("unknown scan type: %s", scanType)
	}

	if err := tasks.SaveTaskResult(taskID, result); err != nil {
		return fmt.Errorf("failed to store scan result: %w", err)
	}

	// Fire webhook asynchronously if configured.
	if webhookURL != "" {
		go func() {
			d := webhook.NewDelivery(webhookURL, webhookSecret)
			res := d.Send(taskID, result)
			if res.Err != nil {
				logger.Error().
					Str("task_id", taskID).
					Str("webhook_url", webhookURL).
					Err(res.Err).
					Msg("webhook delivery failed")
			}
		}()
	}

	return nil
}
