package cmd

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a .armur.yml configuration file in the current directory",
	Long:  `Initialize a new .armur.yml project configuration with sane defaults using an interactive wizard.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if .armur.yml already exists
		if _, err := os.Stat(".armur.yml"); err == nil {
			var overwrite bool
			huh.NewConfirm().
				Title(".armur.yml already exists. Overwrite?").
				Value(&overwrite).
				Run()
			if !overwrite {
				fmt.Println("Cancelled.")
				return
			}
		}

		var depth string
		var language string
		var severity string
		var failOnFindings bool

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Default scan depth").
					Options(
						huh.NewOption("Quick (simple tools, ~30s)", "quick"),
						huh.NewOption("Deep (full tool suite, ~2-3min)", "deep"),
					).
					Value(&depth),
				huh.NewSelect[string]().
					Title("Primary language (or auto-detect)").
					Options(
						huh.NewOption("Auto-detect", "auto"),
						huh.NewOption("Go", "go"),
						huh.NewOption("Python", "py"),
						huh.NewOption("JavaScript/TypeScript", "js"),
						huh.NewOption("Rust", "rust"),
						huh.NewOption("Java/Kotlin", "java"),
						huh.NewOption("Ruby", "ruby"),
						huh.NewOption("PHP", "php"),
						huh.NewOption("C/C++", "c"),
					).
					Value(&language),
				huh.NewSelect[string]().
					Title("Minimum severity to report").
					Options(
						huh.NewOption("Info (show everything)", "info"),
						huh.NewOption("Low", "low"),
						huh.NewOption("Medium (recommended)", "medium"),
						huh.NewOption("High", "high"),
						huh.NewOption("Critical", "critical"),
					).
					Value(&severity),
				huh.NewConfirm().
					Title("Fail CI builds when findings are found?").
					Value(&failOnFindings),
			),
		)

		if err := form.Run(); err != nil {
			color.Red("Cancelled.")
			return
		}

		// Build YAML content
		langLine := ""
		if language != "auto" {
			langLine = fmt.Sprintf("  language: %s\n", language)
		}

		yaml := fmt.Sprintf(`# Armur Security Agent — Project Configuration
# Docs: https://docs.armur.ai/configuration

scan:
  depth: %s                 # quick | deep
%s  severity-threshold: %s    # minimum severity to include in output
  fail-on-findings: %t      # exit with code 1 if findings at threshold or above

exclude:
  - vendor/
  - node_modules/
  - testdata/
  - "**/*_test.go"
  - "*.pb.go"
  - "*.generated.*"

# tools:
#   disabled:
#     - gocyclo              # uncomment to skip specific tools
#   timeout: 300             # per-tool timeout in seconds

# output:
#   format: text             # text | json | sarif
#   save-to: ./reports/      # auto-save reports after each scan

# secrets:
#   validate: false          # set true to test if found secrets are still active
#   scan-history: false      # set true to scan full git history

# plugins:
#   - name: my-custom-linter
#     command: "my-linter --json {target}"
#     output-format: json
#     language: go
`, depth, langLine, severity, failOnFindings)

		if err := os.WriteFile(".armur.yml", []byte(yaml), 0644); err != nil {
			color.Red("Error writing .armur.yml: %v", err)
			os.Exit(1)
		}

		color.Green("Created .armur.yml in current directory.")
		fmt.Println("Run 'armur scan .' to start scanning.")
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
