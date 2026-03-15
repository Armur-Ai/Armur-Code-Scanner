package cmd

import (
	"armur-cli/internal/history"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "List past scans with timestamps and finding counts",
	Long:  `View scan history stored locally in SQLite (~/.armur/history.db).`,
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.Open()
		if err != nil {
			color.Red("Error opening history: %v", err)
			os.Exit(1)
		}
		defer db.Close()

		limit, _ := cmd.Flags().GetInt("limit")
		records, err := db.List(limit)
		if err != nil {
			color.Red("Error listing history: %v", err)
			os.Exit(1)
		}

		if len(records) == 0 {
			fmt.Println("No scan history found.")
			return
		}

		fmt.Printf("%-4s %-36s %-30s %-6s %-8s %4s %4s %4s %4s %4s  %s\n",
			"ID", "TASK ID", "TARGET", "LANG", "STATUS", "CRIT", "HIGH", "MED", "LOW", "INFO", "DATE")
		fmt.Println(color.HiBlackString("─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────"))

		for _, r := range records {
			statusColor := color.GreenString
			if r.Status == "failed" {
				statusColor = color.RedString
			} else if r.Status == "pending" {
				statusColor = color.YellowString
			}

			target := r.Target
			if len(target) > 30 {
				target = target[:27] + "..."
			}

			fmt.Printf("%-4d %-36s %-30s %-6s %-8s %4d %4d %4d %4d %4d  %s\n",
				r.ID, r.TaskID, target, r.Language, statusColor(r.Status),
				r.Critical, r.High, r.Medium, r.Low, r.Info,
				r.CreatedAt.Format("2006-01-02 15:04"),
			)
		}
	},
}

var historyShowCmd = &cobra.Command{
	Use:   "show [task-id]",
	Short: "Show full results of a past scan",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.Open()
		if err != nil {
			color.Red("Error opening history: %v", err)
			os.Exit(1)
		}
		defer db.Close()

		record, err := db.Get(args[0])
		if err != nil {
			color.Red("Scan not found: %v", err)
			os.Exit(1)
		}

		fmt.Printf("Task ID:    %s\n", record.TaskID)
		fmt.Printf("Target:     %s\n", record.Target)
		fmt.Printf("Language:   %s\n", record.Language)
		fmt.Printf("Scan Type:  %s\n", record.ScanType)
		fmt.Printf("Status:     %s\n", record.Status)
		fmt.Printf("Date:       %s\n", record.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Findings:   Critical=%d  High=%d  Medium=%d  Low=%d  Info=%d\n",
			record.Critical, record.High, record.Medium, record.Low, record.Info)
		fmt.Println()

		// Pretty-print the JSON results
		var results interface{}
		if err := json.Unmarshal([]byte(record.Results), &results); err == nil {
			data, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println(string(data))
		}
	},
}

var historyClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear all scan history",
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.Open()
		if err != nil {
			color.Red("Error opening history: %v", err)
			os.Exit(1)
		}
		defer db.Close()

		if err := db.Clear(); err != nil {
			color.Red("Error clearing history: %v", err)
			os.Exit(1)
		}

		color.Green("Scan history cleared.")
	},
}

var compareCmd = &cobra.Command{
	Use:   "compare [task-id-1] [task-id-2]",
	Short: "Compare two scan results to find new and fixed findings",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		db, err := history.Open()
		if err != nil {
			color.Red("Error opening history: %v", err)
			os.Exit(1)
		}
		defer db.Close()

		newFindings, fixedFindings, err := db.Compare(args[0], args[1])
		if err != nil {
			color.Red("Error comparing scans: %v", err)
			os.Exit(1)
		}

		if len(newFindings) == 0 && len(fixedFindings) == 0 {
			fmt.Println("No differences found between the two scans.")
			return
		}

		if len(newFindings) > 0 {
			color.Red("\nNew findings (%d):", len(newFindings))
			for _, f := range newFindings {
				fmt.Printf("  + %s\n", f)
			}
		}

		if len(fixedFindings) > 0 {
			color.Green("\nFixed findings (%d):", len(fixedFindings))
			for _, f := range fixedFindings {
				fmt.Printf("  - %s\n", f)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(historyCmd)
	rootCmd.AddCommand(compareCmd)
	historyCmd.AddCommand(historyShowCmd)
	historyCmd.AddCommand(historyClearCmd)
	historyCmd.Flags().IntP("limit", "n", 50, "Number of recent scans to show")
}
