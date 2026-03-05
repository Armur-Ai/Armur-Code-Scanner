package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "armur",
	Short: "Armur Code Scanner CLI",
	Long:  `A fast and powerful CLI for interacting with the Armur Code Scanner service.`,
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
}
