package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ResultItem represents a single finding in the results browser.
type ResultItem struct {
	Severity string
	File     string
	Line     int
	RuleID   string
	Message  string
	Category string
	CWE      string
	Tool     string
}

// ResultsModel is the interactive results browser TUI.
type ResultsModel struct {
	Items    []ResultItem
	Cursor   int
	Offset   int // scroll offset
	Width    int
	Height   int
	Filter   string // severity filter: "", "critical", "high", "medium", "low"
	filtered []ResultItem
}

func NewResults(items []ResultItem) ResultsModel {
	m := ResultsModel{Items: items}
	m.applyFilter()
	return m
}

func (m *ResultsModel) applyFilter() {
	if m.Filter == "" {
		m.filtered = m.Items
		return
	}
	var out []ResultItem
	for _, item := range m.Items {
		if strings.EqualFold(item.Severity, m.Filter) {
			out = append(out, item)
		}
	}
	m.filtered = out
	if m.Cursor >= len(m.filtered) {
		m.Cursor = max(0, len(m.filtered)-1)
	}
}

func (m ResultsModel) Init() tea.Cmd {
	return nil
}

func (m ResultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.Cursor > 0 {
				m.Cursor--
				if m.Cursor < m.Offset {
					m.Offset = m.Cursor
				}
			}
		case "down", "j":
			if m.Cursor < len(m.filtered)-1 {
				m.Cursor++
				maxVisible := m.visibleRows()
				if m.Cursor >= m.Offset+maxVisible {
					m.Offset = m.Cursor - maxVisible + 1
				}
			}
		case "f":
			// Cycle filter: all → critical → high → medium → low → all
			switch m.Filter {
			case "":
				m.Filter = "critical"
			case "critical":
				m.Filter = "high"
			case "high":
				m.Filter = "medium"
			case "medium":
				m.Filter = "low"
			case "low":
				m.Filter = ""
			}
			m.applyFilter()
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
	}

	return m, nil
}

func (m ResultsModel) View() string {
	if m.Width == 0 || len(m.filtered) == 0 {
		if len(m.Items) == 0 {
			return lipgloss.NewStyle().
				Foreground(lipgloss.Color("40")).
				Bold(true).
				Render("\n  ✓ No security findings. Your code looks good!\n")
		}
		return "\n  No findings match the current filter. Press [f] to cycle filters.\n"
	}

	var b strings.Builder

	// Summary bar
	summaryStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	filterText := "all"
	if m.Filter != "" {
		filterText = m.Filter + " only"
	}
	b.WriteString(summaryStyle.Render(fmt.Sprintf(
		"  %d findings · Showing: %s · [f] filter · [↑↓/jk] navigate · [q] quit",
		len(m.filtered), filterText,
	)))
	b.WriteString("\n\n")

	// Header
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-9s %-30s %5s  %-40s", "SEV", "FILE", "LINE", "MESSAGE")))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", min(m.Width-2, 90))))
	b.WriteString("\n")

	// Findings list
	maxRows := m.visibleRows()
	end := min(m.Offset+maxRows, len(m.filtered))

	for i := m.Offset; i < end; i++ {
		item := m.filtered[i]
		selected := i == m.Cursor

		sevBadge := severityBadge(item.Severity)

		file := item.File
		if len(file) > 28 {
			file = "..." + file[len(file)-25:]
		}

		msg := item.Message
		if len(msg) > 38 {
			msg = msg[:35] + "..."
		}

		line := fmt.Sprintf("  %s %-30s %5d  %s",
			sevBadge, file, item.Line, msg)

		if selected {
			style := lipgloss.NewStyle().Background(lipgloss.Color("237")).Bold(true)
			b.WriteString(style.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	// Detail pane for selected item
	if m.Cursor >= 0 && m.Cursor < len(m.filtered) {
		item := m.filtered[m.Cursor]
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", min(m.Width-2, 90))))
		b.WriteString("\n")

		detailStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
		dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

		b.WriteString(detailStyle.Render(fmt.Sprintf("  File:     %s:%d", item.File, item.Line)))
		b.WriteString("\n")
		b.WriteString(detailStyle.Render(fmt.Sprintf("  Severity: %s", severityBadge(item.Severity))))
		b.WriteString("\n")
		if item.RuleID != "" {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  Rule:     %s", item.RuleID)))
			b.WriteString("\n")
		}
		if item.CWE != "" {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  CWE:      %s", item.CWE)))
			b.WriteString("\n")
		}
		if item.Tool != "" {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  Tool:     %s", item.Tool)))
			b.WriteString("\n")
		}
		b.WriteString(detailStyle.Render(fmt.Sprintf("  Category: %s", item.Category)))
		b.WriteString("\n")
		b.WriteString(detailStyle.Render(fmt.Sprintf("  Message:  %s", item.Message)))
		b.WriteString("\n")
	}

	return b.String()
}

func (m ResultsModel) visibleRows() int {
	// Reserve lines for: summary, header, separator, detail pane (~10), padding
	available := m.Height - 15
	if available < 5 {
		return 5
	}
	return available
}

func severityBadge(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return lipgloss.NewStyle().Background(lipgloss.Color("196")).Foreground(lipgloss.Color("255")).Bold(true).Padding(0, 1).Render("CRIT")
	case "HIGH":
		return lipgloss.NewStyle().Background(lipgloss.Color("208")).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1).Render("HIGH")
	case "MEDIUM":
		return lipgloss.NewStyle().Background(lipgloss.Color("220")).Foreground(lipgloss.Color("0")).Padding(0, 1).Render(" MED")
	case "LOW":
		return lipgloss.NewStyle().Background(lipgloss.Color("40")).Foreground(lipgloss.Color("0")).Padding(0, 1).Render(" LOW")
	default:
		return lipgloss.NewStyle().Background(lipgloss.Color("39")).Foreground(lipgloss.Color("0")).Padding(0, 1).Render("INFO")
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
