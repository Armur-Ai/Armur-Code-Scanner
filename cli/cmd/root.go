package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vibescan",
	Short: "vibescan — Security Scanner for Vibe-Coded Software",
	Long:  `vibescan is a security scanner built for the vibecoding era. It analyzes AI-generated code, runs it in a sandbox, simulates attacks, and shows you exactly how to fix what it finds.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			os.Setenv("LOG_LEVEL", "debug")
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("api-key", "k", "", "API key for authenticating with the server")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose (debug) output")
}
