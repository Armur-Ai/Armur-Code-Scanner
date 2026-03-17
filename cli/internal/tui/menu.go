package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MenuItem represents a single option in the interactive menu.
type MenuItem struct {
	ID          string
	Title       string
	Description string
	Icon        string
}

// MenuModel is the full-screen interactive menu TUI.
type MenuModel struct {
	Items    []MenuItem
	Cursor   int
	Selected string
	Quit     bool
	Width    int
	Height   int
}

func NewMenu() MenuModel {
	return MenuModel{
		Items: []MenuItem{
			{ID: "scan", Title: "Scan Project", Description: "Analyze your code for security vulnerabilities", Icon: ""},
			{ID: "run", Title: "Interactive Scan", Description: "Guided wizard with live dashboard and results browser", Icon: ""},
			{ID: "review", Title: "Review Pull Request", Description: "Security review a GitHub/GitLab PR", Icon: ""},
			{ID: "history", Title: "View History", Description: "Browse past scan results and compare scans", Icon: ""},
			{ID: "report", Title: "Generate Report", Description: "Create HTML, CSV, OWASP, or SANS reports", Icon: ""},
			{ID: "explain", Title: "Explain Finding", Description: "Get an AI explanation of a security finding", Icon: ""},
			{ID: "fix", Title: "Fix Finding", Description: "Generate an AI-powered code patch", Icon: ""},
			{ID: "doctor", Title: "Check Health", Description: "Verify tools, server, and configuration", Icon: ""},
			{ID: "init", Title: "Initialize Project", Description: "Create .armur.yml config for this project", Icon: ""},
			{ID: "setup", Title: "Setup AI / MCP", Description: "Configure Claude API, Ollama, or editor integration", Icon: ""},
		},
	}
}

func (m MenuModel) Init() tea.Cmd {
	return nil
}

func (m MenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.Quit = true
			return m, tea.Quit
		case "up", "k":
			if m.Cursor > 0 {
				m.Cursor--
			}
		case "down", "j":
			if m.Cursor < len(m.Items)-1 {
				m.Cursor++
			}
		case "enter":
			m.Selected = m.Items[m.Cursor].ID
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
	}
	return m, nil
}

func (m MenuModel) View() string {
	var b strings.Builder

	width := m.Width
	if width == 0 {
		width = 80
	}
	if width > 90 {
		width = 90
	}

	// Banner
	bannerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39")).
		Align(lipgloss.Center).
		Width(width)

	subtitleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("245")).
		Align(lipgloss.Center).
		Width(width)

	b.WriteString("\n")
	b.WriteString(bannerStyle.Render("A R M U R"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Your Personal Security Agent"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("SAST  +  DAST  +  Exploit Simulation  +  Attack Paths"))
	b.WriteString("\n\n")

	// Separator
	sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("236"))
	b.WriteString(sepStyle.Render(strings.Repeat("─", width-4)))
	b.WriteString("\n\n")

	// Prompt
	promptStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("252")).
		Bold(true).
		PaddingLeft(2)
	b.WriteString(promptStyle.Render("What would you like to do?"))
	b.WriteString("\n\n")

	// Menu items
	for i, item := range m.Items {
		selected := i == m.Cursor

		cursor := "  "
		if selected {
			cursor = lipgloss.NewStyle().
				Foreground(lipgloss.Color("39")).
				Bold(true).
				Render("▸ ")
		}

		titleStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("252")).
			PaddingLeft(1)

		descStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			PaddingLeft(1)

		if selected {
			titleStyle = titleStyle.
				Foreground(lipgloss.Color("39")).
				Bold(true)
			descStyle = descStyle.
				Foreground(lipgloss.Color("69"))
		}

		icon := item.Icon
		if selected {
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render(item.Icon)
		} else {
			icon = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(item.Icon)
		}

		line := fmt.Sprintf("%s%s %s  %s",
			cursor,
			icon,
			titleStyle.Render(item.Title),
			descStyle.Render(item.Description),
		)

		if selected {
			// Highlight background for selected row
			rowStyle := lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Width(width - 4)
			b.WriteString(rowStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	// Footer
	b.WriteString("\n")
	b.WriteString(sepStyle.Render(strings.Repeat("─", width-4)))
	b.WriteString("\n")

	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		PaddingLeft(2)
	b.WriteString(footerStyle.Render("↑↓ navigate  enter select  q quit"))
	b.WriteString("\n")

	// Version hint
	versionStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("238")).
		PaddingLeft(2)
	b.WriteString(versionStyle.Render("armur v0.1.0 — https://armur.ai"))
	b.WriteString("\n")

	return b.String()
}
