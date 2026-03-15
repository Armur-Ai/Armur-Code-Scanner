package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Set at build time via ldflags
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print Armur version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s %s (commit %s, built %s)\n",
			color.CyanString("armur"),
			color.GreenString(Version),
			Commit,
			Date,
		)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
