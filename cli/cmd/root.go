package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "armur",
	Short: "Armur — Your Personal Security Agent",
	Long:  `Armur is a personal security agent that analyzes your code, runs it in a sandbox, simulates attacks, and shows you exactly how to fix what it finds.`,
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
	// --api-key / -k flag overrides config file and ARMUR_API_KEY env var
	rootCmd.PersistentFlags().StringP("api-key", "k", "", "API key for authenticating with the Armur server (overrides ARMUR_API_KEY env var)")
	// --verbose / -v enables debug-level logging
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose (debug) output")
}
