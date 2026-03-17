package cmd

import (
	"armur-cli/internal/history"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain [finding-id]",
	Short: "Get a plain-English explanation of a security finding using AI",
	Long: `Uses Claude API or a local LLM to explain a finding in developer-friendly language.
Includes: what it is, why it matters, attack scenario, and how to fix it.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		findingID := args[0]

		// For now, look up the finding from history
		db, err := history.Open()
		if err != nil {
			color.Red("Error opening history: %v", err)
			os.Exit(1)
		}
		defer db.Close()

		// In a full implementation, this would:
		// 1. Look up the finding by ID in the scan results
		// 2. Extract code context from the source file
		// 3. Send to the AI provider for explanation
		// 4. Stream the response to terminal

		fmt.Printf("Explaining finding %s...\n", color.CyanString(findingID))
		fmt.Println()
		color.Yellow("AI explanation requires ANTHROPIC_API_KEY or a running Ollama instance.")
		fmt.Println("Set up AI: vibescan config set anthropic-api-key <your-key>")
		fmt.Println("Or install Ollama: brew install ollama && ollama pull llama3.1:8b")
	},
}

var fixCmd = &cobra.Command{
	Use:   "fix [finding-id]",
	Short: "Generate an AI-powered code patch to fix a security finding",
	Long: `Uses Claude API or a local LLM to generate a minimal code patch
that fixes the reported security issue without changing functionality.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		findingID := args[0]
		apply, _ := cmd.Flags().GetBool("apply")

		fmt.Printf("Generating fix for finding %s...\n", color.CyanString(findingID))

		if apply {
			fmt.Println("--apply flag set: patch will be applied directly to the file")
		}

		fmt.Println()
		color.Yellow("AI fix generation requires ANTHROPIC_API_KEY or a running Ollama instance.")
		fmt.Println("Set up AI: vibescan config set anthropic-api-key <your-key>")
	},
}

func init() {
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(fixCmd)
	fixCmd.Flags().Bool("apply", false, "Apply the generated patch directly to the file")
	fixCmd.Flags().Bool("dry-run", false, "Show the patch without applying")
}
