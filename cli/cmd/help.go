package cmd

import (
	"armur-cli/internal/tui"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

func runInteractiveMenu() {
	menu := tui.NewMenu()
	p := tea.NewProgram(menu, tea.WithAltScreen())

	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	m := finalModel.(tui.MenuModel)
	if m.Quit {
		return
	}

	// Route to the selected command
	switch m.Selected {
	case "scan":
		runScanFlow()
	case "run":
		runCmd.Run(runCmd, []string{})
	case "review":
		fmt.Print("\n")
		fmt.Print(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).PaddingLeft(2).Render("Enter PR URL: "))
		var prURL string
		fmt.Scanln(&prURL)
		if prURL != "" {
			reviewCmd.Run(reviewCmd, []string{prURL})
		}
	case "history":
		historyCmd.Run(historyCmd, []string{})
	case "report":
		reportCmd.Run(reportCmd, []string{})
	case "explain":
		fmt.Print("\n")
		fmt.Print(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).PaddingLeft(2).Render("Enter finding ID: "))
		var findingID string
		fmt.Scanln(&findingID)
		if findingID != "" {
			explainCmd.Run(explainCmd, []string{findingID})
		}
	case "fix":
		fmt.Print("\n")
		fmt.Print(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).PaddingLeft(2).Render("Enter finding ID: "))
		var findingID string
		fmt.Scanln(&findingID)
		if findingID != "" {
			fixCmd.Run(fixCmd, []string{findingID})
		}
	case "doctor":
		doctorCmd.Run(doctorCmd, []string{})
	case "init":
		initCmd.Run(initCmd, []string{})
	case "setup":
		runSetupFlow()
	}
}

func runScanFlow() {
	cwd, _ := os.Getwd()
	flow := tui.NewScanFlow(cwd)
	p := tea.NewProgram(flow, tea.WithAltScreen())

	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}

	m := finalModel.(tui.ScanFlowModel)
	if m.Cancelled {
		fmt.Println("Scan cancelled.")
		return
	}

	if m.Confirmed {
		target, language, depth := m.GetScanConfig()

		// Build scan args
		args := []string{target}
		if language != "" {
			scanCmd.Flags().Set("language", language)
		}
		if depth == "deep" {
			scanCmd.Flags().Set("advanced", "true")
		}
		scanCmd.Run(scanCmd, args)
	}
}

func runSetupFlow() {
	fmt.Println()

	setupStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).PaddingLeft(2)
	optStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252")).PaddingLeft(4)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).PaddingLeft(6)

	fmt.Println(setupStyle.Render("Setup Options"))
	fmt.Println()
	fmt.Println(optStyle.Render("1. Configure AI provider (Claude API / Ollama)"))
	fmt.Println(dimStyle.Render("   Run: armur config set anthropic-api-key <your-key>"))
	fmt.Println()
	fmt.Println(optStyle.Render("2. Set up MCP for Claude Code"))
	fmt.Println(dimStyle.Render("   Run: claude mcp add armur -- armur mcp"))
	fmt.Println()
	fmt.Println(optStyle.Render("3. Set up MCP for Cursor"))
	fmt.Println(dimStyle.Render("   Run: armur mcp setup cursor"))
	fmt.Println()
	fmt.Println(optStyle.Render("4. Initialize project config"))
	fmt.Println(dimStyle.Render("   Run: armur init"))
	fmt.Println()
}

func init() {
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		runInteractiveMenu()
	}
}
