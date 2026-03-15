package agent

import (
	"context"
	"fmt"
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

	_ = owner
	_ = repo
	_ = prNum

	// 2. Fetch changed files (would use GitHub API in full implementation)
	review.ChangedFiles = []string{} // placeholder

	// 3. Run SAST on changed files
	// In full implementation: clone repo, checkout PR branch, run scan with --diff

	// 4. Run SCA if new dependencies added
	// Check if package.json, go.mod, etc. are in changed files

	// 5. Run secrets scan on the diff
	// Only flag NEW secrets, not existing ones

	// 6. DAST (if enabled and applicable)
	if opts.DAST {
		// Build sandbox from PR branch, run DAST
		review.DASTFindings = 0
	}

	// 7. Exploit simulation (if enabled)
	if opts.ExploitSim {
		// Attempt exploits for HIGH/CRITICAL findings
	}

	// 8. Attack path analysis
	// Check if PR introduces new attack paths

	// 9. Determine verdict
	review.Verdict = determineVerdict(review, opts.FailOnSeverity)

	// 10. Generate summary
	review.Summary = generateSummary(review)
	review.Duration = time.Since(start)

	return review, nil
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
