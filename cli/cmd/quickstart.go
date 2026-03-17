package cmd

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var quickstartCmd = &cobra.Command{
	Use:   "quickstart",
	Short: "Get started with Armur in 60 seconds",
	Long:  `Interactive guide to set up and run your first security scan.`,
	Run: func(cmd *cobra.Command, args []string) {
		banner := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39")).
			BorderStyle(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(1, 3).
			Width(60).
			Align(lipgloss.Center)

		fmt.Println(banner.Render("Welcome to Armur\nYour Personal Security Agent"))
		fmt.Println()

		stepStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
		descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252")).PaddingLeft(2)

		steps := []struct {
			num  string
			cmd  string
			desc string
		}{
			{"1", "vibescan doctor", "Check which security tools are available on your machine"},
			{"2", "vibescan init", "Create a .vibescan.yml config file for your project"},
			{"3", "vibescan run", "Launch the interactive security agent with live dashboard"},
			{"4", "vibescan scan .", "Quick one-shot scan of your project"},
			{"5", "vibescan history", "View past scan results"},
			{"6", "vibescan explain <id>", "Get an AI explanation of a finding"},
		}

		for _, s := range steps {
			fmt.Printf("  %s  %s\n", stepStyle.Render("Step "+s.num+":"), color.CyanString(s.cmd))
			fmt.Println(descStyle.Render(s.desc))
			fmt.Println()
		}

		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("  For CI/CD setup: vibescan scan . --format sarif --fail-on-severity high"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("  For AI editors:  vibescan mcp setup claude-code"))
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("  Docs: https://docs.armur.ai"))
		fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("  Help: armur --help"))
	},
}

func init() {
	rootCmd.AddCommand(quickstartCmd)
}
