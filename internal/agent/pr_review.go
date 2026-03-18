package agent

import (
	"armur-codescanner/internal/tasks"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// PRReview represents the result of an automated PR security review.
type PRReview struct {
	PRURL        string        `json:"pr_url"`
	BaseBranch   string        `json:"base_branch"`
	HeadBranch   string        `json:"head_branch"`
	ChangedFiles []string      `json:"changed_files"`
	SASTFindings int           `json:"sast_findings"`
	DASTFindings int           `json:"dast_findings"`
	NewFindings  int           `json:"new_findings"`
	AttackPaths  int           `json:"attack_paths"`
	Verdict      string        `json:"verdict"` // approve, request_changes, comment
	Summary      string        `json:"summary"`
	ReviewedAt   time.Time     `json:"reviewed_at"`
	Duration     time.Duration `json:"duration"`
}

// ReviewOpts configures the PR review behavior.
type ReviewOpts struct {
	DAST           bool   // run DAST in sandbox
	ExploitSim     bool   // run exploit simulation
	PostComment    bool   // post review comment to GitHub/GitLab
	FailOnSeverity string // fail if findings at this level or above
	AIReview       bool   // generate AI narrative
}

// ReviewPR performs a full security review of a pull request.
func ReviewPR(ctx context.Context, prURL string, opts ReviewOpts) (*PRReview, error) {
	start := time.Now()

	review := &PRReview{
		PRURL:      prURL,
		ReviewedAt: time.Now(),
	}

	// 1. Parse PR URL to extract owner, repo, PR number
	owner, repo, prNum, err := parsePRURL(prURL)
	if err != nil {
		return nil, fmt.Errorf("invalid PR URL: %w", err)
	}

	// 2. Fetch PR metadata (base/head branches)
	baseBranch, headBranch, err := fetchPRDetails(ctx, owner, repo, prNum)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PR details: %w", err)
	}
	review.BaseBranch = baseBranch
	review.HeadBranch = headBranch

	// 3. Fetch changed files list
	changedFiles, err := fetchChangedFiles(ctx, owner, repo, prNum)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch changed files: %w", err)
	}
	review.ChangedFiles = changedFiles

	// 4. Clone the repo and checkout the PR's head branch
	tmpDir, err := clonePRBranch(ctx, owner, repo, prNum, headBranch)
	if err != nil {
		return nil, fmt.Errorf("failed to clone PR branch: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// 5. Run SAST scan on the cloned repo
	results, scanErrors, err := tasks.RunSimpleScanLocal(tmpDir, "")
	if err != nil {
		return nil, fmt.Errorf("SAST scan failed: %w", err)
	}

	// Record scan errors but don't fail the review
	if len(scanErrors) > 0 {
		results["scan_errors"] = scanErrors
	}

	// 6. Count findings
	sastCount := countFindings(results)
	review.SASTFindings = sastCount

	// All SAST findings on the PR branch are treated as new findings
	// since we're scanning the PR branch in isolation
	review.NewFindings = sastCount

	// 7. DAST (if enabled) — placeholder for Sprint 17
	if opts.DAST {
		review.DASTFindings = 0
	}

	// 8. Exploit simulation (if enabled) — placeholder for Sprint 18
	if opts.ExploitSim {
		// Attempt exploits for HIGH/CRITICAL findings
	}

	// 9. Determine verdict
	review.Verdict = determineVerdict(review, opts.FailOnSeverity)

	// 10. Generate summary
	review.Summary = generateSummary(review)
	review.Duration = time.Since(start)

	return review, nil
}

// fetchPRDetails retrieves the base and head branch names for a PR from the GitHub API.
func fetchPRDetails(ctx context.Context, owner, repo string, prNum int) (baseBranch, headBranch string, err error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, prNum)

	body, err := githubAPIGet(ctx, url)
	if err != nil {
		return "", "", fmt.Errorf("GET %s: %w", url, err)
	}

	var pr struct {
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		Head struct {
			Ref string `json:"ref"`
		} `json:"head"`
	}
	if err := json.Unmarshal(body, &pr); err != nil {
		return "", "", fmt.Errorf("parsing PR response: %w", err)
	}
	if pr.Base.Ref == "" || pr.Head.Ref == "" {
		return "", "", fmt.Errorf("could not determine base/head branches from API response")
	}

	return pr.Base.Ref, pr.Head.Ref, nil
}

// fetchChangedFiles retrieves the list of files changed in a PR from the GitHub API.
// GitHub paginates at 30 files by default (max 100 per page); this fetches all pages.
func fetchChangedFiles(ctx context.Context, owner, repo string, prNum int) ([]string, error) {
	var allFiles []string
	page := 1

	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d/files?per_page=100&page=%d",
			owner, repo, prNum, page)

		body, err := githubAPIGet(ctx, url)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", url, err)
		}

		var files []struct {
			Filename string `json:"filename"`
		}
		if err := json.Unmarshal(body, &files); err != nil {
			return nil, fmt.Errorf("parsing files response: %w", err)
		}

		if len(files) == 0 {
			break
		}

		for _, f := range files {
			allFiles = append(allFiles, f.Filename)
		}

		// If we got fewer than the page size, we're on the last page
		if len(files) < 100 {
			break
		}
		page++
	}

	return allFiles, nil
}

// githubAPIGet performs an authenticated (if GITHUB_TOKEN is set) GET request
// to the GitHub API and returns the response body.
func githubAPIGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "vibescan-pr-review")

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return body, nil
}

// clonePRBranch clones the repository and checks out the PR's head branch.
// It returns the path to the temporary directory containing the clone.
func clonePRBranch(ctx context.Context, owner, repo string, prNum int, headBranch string) (string, error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), fmt.Sprintf("vibescan-pr-%d-*", prNum))
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	cloneDir := filepath.Join(tmpDir, repo)

	// Try cloning with the head branch directly
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth=50", "--branch", headBranch, repoURL, cloneDir)
	if err := cmd.Run(); err != nil {
		// Branch clone failed — clone default branch, then fetch the PR ref
		cmd = exec.CommandContext(ctx, "git", "clone", "--depth=50", repoURL, cloneDir)
		if err := cmd.Run(); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("git clone failed: %w", err)
		}

		prRef := fmt.Sprintf("pull/%d/head:pr-%d", prNum, prNum)
		cmd = exec.CommandContext(ctx, "git", "-C", cloneDir, "fetch", "origin", prRef)
		if err := cmd.Run(); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("git fetch PR ref failed: %w", err)
		}

		checkoutRef := fmt.Sprintf("pr-%d", prNum)
		cmd = exec.CommandContext(ctx, "git", "-C", cloneDir, "checkout", checkoutRef)
		if err := cmd.Run(); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("git checkout PR ref failed: %w", err)
		}
	}

	return cloneDir, nil
}

// countFindings recursively counts the total number of individual findings
// in a categorized results map. It traverses nested maps and slices to reach
// leaf findings, counting each non-nil, non-container element.
func countFindings(results map[string]interface{}) int {
	count := 0
	for key, value := range results {
		// Skip metadata keys that aren't actual findings
		if key == "scan_errors" || key == "status" || key == "error" {
			continue
		}
		count += countValue(value)
	}
	return count
}

// countValue recursively counts findings within a value.
func countValue(v interface{}) int {
	if v == nil {
		return 0
	}

	switch val := v.(type) {
	case []interface{}:
		count := 0
		for _, item := range val {
			// If the item is a map (a finding object), count it as 1
			if _, ok := item.(map[string]interface{}); ok {
				count++
			} else if nested, ok := item.([]interface{}); ok {
				count += countValue(nested)
			} else {
				// Scalar values in a slice — count each as a finding
				count++
			}
		}
		return count
	case map[string]interface{}:
		// A map could be a single finding or a category containing more findings
		// Check if it looks like a category (values are slices/maps) vs a leaf finding
		hasNestedCollections := false
		count := 0
		for _, innerVal := range val {
			switch innerVal.(type) {
			case []interface{}, map[string]interface{}:
				hasNestedCollections = true
				count += countValue(innerVal)
			}
		}
		if hasNestedCollections {
			return count
		}
		// Leaf finding object
		return 1
	default:
		return 0
	}
}

// truncate shortens a string to at most maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func parsePRURL(url string) (owner, repo string, prNum int, err error) {
	// Parse: https://github.com/owner/repo/pull/123
	url = strings.TrimRight(url, "/")
	parts := strings.Split(url, "/")

	if len(parts) < 5 {
		return "", "", 0, fmt.Errorf("expected https://github.com/owner/repo/pull/123 format")
	}

	// Find "pull" in the URL
	for i, part := range parts {
		if part == "pull" && i+1 < len(parts) {
			owner = parts[i-2]
			repo = parts[i-1]
			fmt.Sscanf(parts[i+1], "%d", &prNum)
			return
		}
	}

	return "", "", 0, fmt.Errorf("could not parse PR number from URL")
}

func determineVerdict(review *PRReview, failOnSeverity string) string {
	if review.NewFindings == 0 {
		return "approve"
	}

	// If attack paths found, always request changes
	if review.AttackPaths > 0 {
		return "request_changes"
	}

	// If DAST confirmed findings, always request changes
	if review.DASTFindings > 0 {
		return "request_changes"
	}

	return "comment"
}

func generateSummary(review *PRReview) string {
	var b strings.Builder

	b.WriteString("## Armur Security Review\n\n")

	switch review.Verdict {
	case "approve":
		b.WriteString("**Verdict: Approve** — No new security issues found.\n\n")
	case "request_changes":
		b.WriteString(fmt.Sprintf("**Verdict: Request Changes** — %d issues require attention.\n\n", review.NewFindings))
	default:
		b.WriteString(fmt.Sprintf("**Verdict: Comment** — %d findings for review.\n\n", review.NewFindings))
	}

	b.WriteString("### Summary\n")
	b.WriteString(fmt.Sprintf("| Metric | Count |\n"))
	b.WriteString(fmt.Sprintf("|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| SAST Findings | %d |\n", review.SASTFindings))
	b.WriteString(fmt.Sprintf("| DAST Findings | %d |\n", review.DASTFindings))
	b.WriteString(fmt.Sprintf("| Attack Paths | %d |\n", review.AttackPaths))
	b.WriteString(fmt.Sprintf("| Files Changed | %d |\n", len(review.ChangedFiles)))
	b.WriteString(fmt.Sprintf("| Review Time | %s |\n", review.Duration.Truncate(time.Second)))

	b.WriteString("\n---\n")
	b.WriteString("Reviewed by [Armur Security Agent](https://armur.ai)\n")

	return b.String()
}

// FormatMarkdownComment formats the review as a GitHub PR comment.
func (r *PRReview) FormatMarkdownComment() string {
	return r.Summary
}
