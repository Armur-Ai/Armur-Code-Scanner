package tasks

import (
	"context"
	"sync"
	"time"

	"armur-codescanner/internal/redis"
)

// cancelRegistry stores cancel functions keyed by task ID.
var cancelRegistry sync.Map

// RegisterCancel stores a cancel function for a task ID.
func RegisterCancel(taskID string, cancel context.CancelFunc) {
	cancelRegistry.Store(taskID, cancel)
}

// UnregisterCancel removes the cancel function for a task ID.
func UnregisterCancel(taskID string) {
	cancelRegistry.Delete(taskID)
}

// CancelTask cancels an in-progress scan by calling its stored CancelFunc
// and updating its status in Redis.
func CancelTask(taskID string) error {
	val, ok := cancelRegistry.Load(taskID)
	if !ok {
		return nil // task not found or already finished
	}

	cancel, ok := val.(context.CancelFunc)
	if ok {
		cancel()
	}
	cancelRegistry.Delete(taskID)

	// Mark as cancelled in Redis
	ctx := context.Background()
	return redis.RedisClient().Set(ctx, taskID+":status", "cancelled", 24*time.Hour).Err()
}
