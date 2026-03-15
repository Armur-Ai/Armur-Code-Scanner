package tasks

import (
	"encoding/json"
	"sync"
	"time"
)

// ScanEvent represents a real-time event during scan execution.
type ScanEvent struct {
	Event     string      `json:"event"`     // tool_started, tool_progress, tool_completed, tool_failed, tool_skipped, scan_completed
	Tool      string      `json:"tool,omitempty"`
	Percent   int         `json:"pct,omitempty"`
	Findings  int         `json:"findings,omitempty"`
	Duration  int64       `json:"duration_ms,omitempty"`
	Error     string      `json:"error,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	Total     int         `json:"total_findings,omitempty"`
	Timestamp int64       `json:"ts"`
}

// EventRegistry stores per-task event channels for SSE streaming.
type EventRegistry struct {
	mu       sync.RWMutex
	channels map[string]chan ScanEvent
	history  map[string][]ScanEvent // last 50 events per task for replay
}

var globalRegistry = &EventRegistry{
	channels: make(map[string]chan ScanEvent),
	history:  make(map[string][]ScanEvent),
}

// GetRegistry returns the global event registry.
func GetRegistry() *EventRegistry {
	return globalRegistry
}

// Subscribe creates a buffered channel for a task's events.
func (r *EventRegistry) Subscribe(taskID string) chan ScanEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	ch := make(chan ScanEvent, 64)
	r.channels[taskID] = ch
	return ch
}

// Unsubscribe removes the channel for a task.
func (r *EventRegistry) Unsubscribe(taskID string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ch, ok := r.channels[taskID]; ok {
		close(ch)
		delete(r.channels, taskID)
	}
}

// Emit sends an event to subscribers and stores in history.
func (r *EventRegistry) Emit(taskID string, event ScanEvent) {
	event.Timestamp = time.Now().UnixMilli()

	r.mu.Lock()
	// Store in history (keep last 50)
	r.history[taskID] = append(r.history[taskID], event)
	if len(r.history[taskID]) > 50 {
		r.history[taskID] = r.history[taskID][len(r.history[taskID])-50:]
	}
	ch := r.channels[taskID]
	r.mu.Unlock()

	// Non-blocking send
	if ch != nil {
		select {
		case ch <- event:
		default:
			// Channel full, drop event
		}
	}
}

// Replay returns stored events for late-connecting clients.
func (r *EventRegistry) Replay(taskID string) []ScanEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.history[taskID]
}

// MarshalEvent converts a ScanEvent to JSON bytes for SSE.
func MarshalEvent(event ScanEvent) []byte {
	data, _ := json.Marshal(event)
	return data
}

// ProgressReporter is the interface that tool runners use to report progress.
type ProgressReporter interface {
	Started(tool string)
	Progress(tool string, pct int)
	Completed(tool string, findingCount int, d time.Duration)
	Failed(tool string, err error)
	Skipped(tool string, reason string)
}

// ChannelReporter implements ProgressReporter by emitting events to the registry.
type ChannelReporter struct {
	TaskID   string
	Registry *EventRegistry
}

func NewChannelReporter(taskID string) *ChannelReporter {
	return &ChannelReporter{
		TaskID:   taskID,
		Registry: GetRegistry(),
	}
}

func (r *ChannelReporter) Started(tool string) {
	r.Registry.Emit(r.TaskID, ScanEvent{
		Event: "tool_started",
		Tool:  tool,
	})
}

func (r *ChannelReporter) Progress(tool string, pct int) {
	r.Registry.Emit(r.TaskID, ScanEvent{
		Event:   "tool_progress",
		Tool:    tool,
		Percent: pct,
	})
}

func (r *ChannelReporter) Completed(tool string, findingCount int, d time.Duration) {
	r.Registry.Emit(r.TaskID, ScanEvent{
		Event:    "tool_completed",
		Tool:     tool,
		Findings: findingCount,
		Duration: d.Milliseconds(),
	})
}

func (r *ChannelReporter) Failed(tool string, err error) {
	r.Registry.Emit(r.TaskID, ScanEvent{
		Event: "tool_failed",
		Tool:  tool,
		Error: err.Error(),
	})
}

func (r *ChannelReporter) Skipped(tool string, reason string) {
	r.Registry.Emit(r.TaskID, ScanEvent{
		Event:  "tool_skipped",
		Tool:   tool,
		Reason: reason,
	})
}
