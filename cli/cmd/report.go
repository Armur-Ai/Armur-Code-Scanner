package cmd

import (
	"armur-cli/internal/api"
	"armur-cli/internal/config"
	"armur-cli/internal/reports"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a report for a completed scan task",
	Long: `Generate reports in various formats for a completed scan task.

Formats: owasp, sans, html, csv
Use --format to specify the output format and --task to provide the task ID.`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			color.Red("Error loading configuration: %v", err)
			os.Exit(1)
		}

		taskID, _ := cmd.Flags().GetString("task")
		reportFormat, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		// If no flags provided, launch interactive mode
		if taskID == "" || reportFormat == "" {
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().Title("Task ID").Value(&taskID),
					huh.NewSelect[string]().
						Title("Select report format").
						Options(
							huh.NewOption("HTML (standalone report)", "html"),
							huh.NewOption("CSV (spreadsheet)", "csv"),
							huh.NewOption("OWASP Top 10 mapping", "owasp"),
							huh.NewOption("SANS Top 25 mapping", "sans"),
						).
						Value(&reportFormat),
				),
			)
			if err := form.Run(); err != nil {
				fmt.Println("Cancelled.")
				return
			}
		}

		apiClient := api.NewClient(cfg.API.URL).WithAPIKey(cfg.APIKey)

		switch strings.ToLower(reportFormat) {
		case "html":
			_, results, err := apiClient.GetTaskStatus(taskID)
			if err != nil {
				color.Red("Error fetching results: %v", err)
				os.Exit(1)
			}
			path, err := reports.GenerateHTML(taskID, results)
			if err != nil {
				color.Red("Error generating HTML report: %v", err)
				os.Exit(1)
			}
			color.Green("HTML report saved to: %s", path)

		case "csv":
			_, results, err := apiClient.GetTaskStatus(taskID)
			if err != nil {
				color.Red("Error fetching results: %v", err)
				os.Exit(1)
			}
			path, err := reports.GenerateCSV(taskID, results, output)
			if err != nil {
				color.Red("Error generating CSV report: %v", err)
				os.Exit(1)
			}
			color.Green("CSV report saved to: %s", path)

		case "owasp":
			report, err := apiClient.GetOwaspReport(taskID)
			if err != nil {
				color.Red("Error generating OWASP report: %v", err)
				os.Exit(1)
			}
			fmt.Println(color.CyanString("OWASP Report for Task %s:", taskID))
			fmt.Println(report)

		case "sans":
			report, err := apiClient.GetSansReport(taskID)
			if err != nil {
				color.Red("Error generating SANS report: %v", err)
				os.Exit(1)
			}
			fmt.Println(color.CyanString("SANS Report for Task %s:", taskID))
			fmt.Println(report)

		default:
			color.Red("Unknown format: %s. Supported: html, csv, owasp, sans", reportFormat)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringP("task", "t", "", "Task ID of the completed scan")
	reportCmd.Flags().StringP("format", "f", "", "Report format (html, csv, owasp, sans)")
	reportCmd.Flags().StringP("output", "o", "", "Output file path (for csv)")
}
