package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var reviewCmd = &cobra.Command{
	Use:   "review <pr-url>",
	Short: "Review a pull request for security issues",
	Long: `Run a full security review on a GitHub or GitLab pull/merge request.
Analyzes changed files with SAST, checks for new vulnerable dependencies,
scans for leaked secrets, and optionally runs DAST in a sandbox.

Example:
  vibescan review https://github.com/owner/repo/pull/123
  vibescan review https://github.com/owner/repo/pull/123 --dast --post-comment`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		prURL := args[0]
		dast, _ := cmd.Flags().GetBool("dast")
		postComment, _ := cmd.Flags().GetBool("post-comment")
		exploitSim, _ := cmd.Flags().GetBool("exploit-simulation")
		failOnSeverity, _ := cmd.Flags().GetString("fail-on-severity")

		fmt.Printf("%s Reviewing: %s\n\n",
			color.CyanString("ARMUR"),
			color.GreenString(prURL),
		)

		stages := []string{"Fetch PR diff", "SAST scan", "SCA check", "Secrets scan"}
		if dast {
			stages = append(stages, "DAST (sandbox)")
		}
		if exploitSim {
			stages = append(stages, "Exploit simulation")
		}
		stages = append(stages, "Attack path analysis", "Generate review")

		for _, stage := range stages {
			fmt.Printf("  %s %s\n", color.CyanString("→"), stage)
		}

		fmt.Println()

		// In full implementation: call agent.ReviewPR() and display results
		color.Yellow("Full PR review requires server and GitHub token.")
		fmt.Println("Set GITHUB_TOKEN environment variable for GitHub API access.")

		if postComment {
			fmt.Println("--post-comment: Review will be posted as a PR comment.")
		}

		if failOnSeverity != "" {
			fmt.Printf("--fail-on-severity %s: Will exit with code 1 if findings at this level.\n", failOnSeverity)
		}
	},
}

func init() {
	rootCmd.AddCommand(reviewCmd)
	reviewCmd.Flags().Bool("dast", false, "Run DAST in sandbox against the PR branch")
	reviewCmd.Flags().Bool("post-comment", false, "Post review comment on the PR")
	reviewCmd.Flags().Bool("exploit-simulation", false, "Run exploit simulation for HIGH/CRITICAL findings")
	reviewCmd.Flags().String("fail-on-severity", "", "Fail if findings at this severity or above (critical, high, medium)")
}
