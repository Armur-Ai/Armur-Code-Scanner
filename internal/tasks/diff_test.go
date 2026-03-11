package tasks

import (
	"os"
	"testing"
)

func TestChangedFiles_EmptyRef(t *testing.T) {
	dir := t.TempDir()
	_, err := ChangedFiles(dir, "")
	if err == nil {
		t.Error("expected error for empty baseRef, got nil")
	}
}

func TestChangedFiles_NotARepo(t *testing.T) {
	dir := t.TempDir()
	_, err := ChangedFiles(dir, "HEAD~1")
	if err == nil {
		t.Error("expected error for non-git directory, got nil")
	}
}

func TestChangedFiles_UnresolvableRef(t *testing.T) {
	// Skip if git is not available in the test environment.
	if _, err := os.Stat("/usr/bin/git"); os.IsNotExist(err) {
		if _, err2 := os.Stat("/usr/local/bin/git"); os.IsNotExist(err2) {
			t.Skip("git binary not found, skipping")
		}
	}
	if os.Getenv("INTEGRATION_TESTS") == "" {
		t.Skip("set INTEGRATION_TESTS=1 to run")
	}
	// Use the real repo root.
	repoPath := findTestdataDir(t, "../..")
	files, err := ChangedFiles(repoPath, "nonexistent-ref-xyz")
	// Should return nil, nil (fallback to full scan)
	if err != nil {
		t.Errorf("expected nil error for unresolvable ref fallback, got: %v", err)
	}
	_ = files
}
