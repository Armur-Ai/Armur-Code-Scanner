package cmd

import (
	"armur-cli/internal/api"
	"armur-cli/internal/config"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
)

// watchAndScan starts a file watcher and triggers scans on changes.
func watchAndScan(target string, apiClient *api.APIClient, language string, isAdvanced bool, outputFormat string) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		color.Red("Error creating watcher: %v", err)
		os.Exit(1)
	}
	defer watcher.Close()

	// Walk the directory and add all subdirectories
	addDirs(watcher, target)

	fmt.Println(color.CyanString("[watch] Watching %s for changes. Press Ctrl+C to stop.", target))

	var mu sync.Mutex
	var debounceTimer *time.Timer
	lastScan := time.Now()

	// Handle signals for clean exit
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !isRelevantChange(event) {
				continue
			}

			mu.Lock()
			// Debounce: wait 3 seconds after last change before scanning
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(3*time.Second, func() {
				mu.Lock()
				defer mu.Unlock()

				if time.Since(lastScan) < 5*time.Second {
					return
				}
				lastScan = time.Now()

				relPath, _ := filepath.Rel(target, event.Name)
				if relPath == "" {
					relPath = event.Name
				}

				now := time.Now().Format("15:04:05")
				fmt.Printf("\n%s File changed: %s — re-scanning...\n",
					color.CyanString("[%s]", now), relPath)

				taskID, scanErr := apiClient.ScanFile(target, isAdvanced)
				if scanErr != nil {
					color.Red("[%s] Error: %v", now, scanErr)
					return
				}

				result := waitForScanQuiet(apiClient, taskID)
				counts := countSeverities(result)

				total := 0
				for _, c := range counts {
					total += c
				}

				fmt.Printf("%s Done. %d findings (critical: %d, high: %d, medium: %d, low: %d)\n",
					color.CyanString("[%s]", time.Now().Format("15:04:05")),
					total, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
			})
			mu.Unlock()

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			color.Red("[watch] Error: %v", err)

		case <-sigCh:
			fmt.Println(color.YellowString("\n[watch] Stopped."))
			return
		}
	}
}

// waitForScanQuiet polls for results without progress display.
func waitForScanQuiet(apiClient *api.APIClient, taskID string) map[string]interface{} {
	for {
		status, result, err := apiClient.GetTaskStatus(taskID)
		if err != nil {
			return nil
		}
		if status == "success" {
			return result
		}
		if status == "failed" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

// addDirs recursively adds directories to the watcher, skipping common ignore patterns.
func addDirs(watcher *fsnotify.Watcher, root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		// Skip hidden dirs, vendor, node_modules, etc.
		if strings.HasPrefix(base, ".") || base == "vendor" || base == "node_modules" ||
			base == "__pycache__" || base == "target" || base == "build" || base == "dist" {
			return filepath.SkipDir
		}
		watcher.Add(path)
		return nil
	})
}

// isRelevantChange checks if a file change should trigger a re-scan.
func isRelevantChange(event fsnotify.Event) bool {
	if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
		return false
	}
	name := filepath.Base(event.Name)
	// Skip hidden files, temp files, and lock files
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") ||
		strings.HasSuffix(name, ".swp") || strings.HasSuffix(name, ".lock") {
		return false
	}
	return true
}

// initWatchFlag adds the --watch flag to scan commands.
// This is called from scan.go init().
func runWatchMode(cfg *config.Config, target, language string, isAdvanced bool, outputFormat string) {
	apiClient := api.NewClient(cfg.API.URL).WithAPIKey(cfg.APIKey)
	watchAndScan(target, apiClient, language, isAdvanced, outputFormat)
}
