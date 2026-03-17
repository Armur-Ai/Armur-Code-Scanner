package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ToolStatus represents the state of a single tool in the scan.
type ToolStatus struct {
	Name     string
	Status   string // "queued", "running", "completed", "failed", "skipped"
	Findings int
	Started  time.Time
	Duration time.Duration
}

// SeverityCounts tracks finding counts by severity.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func (s SeverityCounts) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Info
}

// DashboardModel is the Bubbletea model for the live scan dashboard.
type DashboardModel struct {
	Target     string
	Language   string
	Mode       string // "quick" or "deep"
	Tools      []ToolStatus
	Counts     SeverityCounts
	StartedAt  time.Time
	Done       bool
	Failed     bool
	spinner    spinner.Model
	width      int
	height     int
}

// TickMsg triggers a time update.
type TickMsg time.Time

// ScanDoneMsg signals scan completion.
type ScanDoneMsg struct {
	Results map[string]interface{}
}

// ScanFailedMsg signals scan failure.
type ScanFailedMsg struct {
	Error string
}

// ToolUpdateMsg updates a specific tool's status.
type ToolUpdateMsg struct {
	Tool     string
	Status   string
	Findings int
}

func NewDashboard(target, language, mode string, tools []string) DashboardModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	statuses := make([]ToolStatus, len(tools))
	for i, t := range tools {
		statuses[i] = ToolStatus{Name: t, Status: "queued"}
	}

	return DashboardModel{
		Target:    target,
		Language:  language,
		Mode:      mode,
		Tools:     statuses,
		StartedAt: time.Now(),
		spinner:   s,
	}
}

func (m DashboardModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case TickMsg:
		return m, tickCmd()

	case ToolUpdateMsg:
		for i := range m.Tools {
			if m.Tools[i].Name == msg.Tool {
				m.Tools[i].Status = msg.Status
				m.Tools[i].Findings = msg.Findings
				if msg.Status == "running" && m.Tools[i].Started.IsZero() {
					m.Tools[i].Started = time.Now()
				}
				if msg.Status == "completed" || msg.Status == "failed" {
					if !m.Tools[i].Started.IsZero() {
						m.Tools[i].Duration = time.Since(m.Tools[i].Started)
					}
				}
			}
		}

	case ScanDoneMsg:
		m.Done = true
		return m, tea.Quit

	case ScanFailedMsg:
		m.Failed = true
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m DashboardModel) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39")).
		BorderStyle(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 1).
		Width(min(m.width-2, 70))

	elapsed := time.Since(m.StartedAt).Truncate(time.Second)
	header := fmt.Sprintf("VIBESCAN  ·  %s  ·  %s  ·  %s scan  ·  %s",
		m.Target, strings.ToUpper(m.Language), m.Mode, elapsed)
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n\n")

	// Tool table
	toolHeaderStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	b.WriteString(toolHeaderStyle.Render(fmt.Sprintf("  %-20s %-12s %8s", "Tool", "Status", "Found")))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", min(m.width-2, 50))))
	b.WriteString("\n")

	for _, t := range m.Tools {
		icon, style := statusDisplay(t.Status)

		elapsed := ""
		if t.Status == "running" && !t.Started.IsZero() {
			elapsed = fmt.Sprintf(" %s", time.Since(t.Started).Truncate(time.Second))
		}
		if t.Status == "completed" && t.Duration > 0 {
			elapsed = fmt.Sprintf(" %s", t.Duration.Truncate(time.Second))
		}

		findings := "-"
		if t.Status == "completed" || t.Status == "failed" {
			findings = fmt.Sprintf("%d", t.Findings)
		}

		line := fmt.Sprintf("  %s %-18s %-10s %8s",
			icon,
			t.Name,
			style.Render(t.Status)+elapsed,
			findings,
		)
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Severity counts footer
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", min(m.width-2, 50))))
	b.WriteString("\n")

	critStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	highStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	medStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	lowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("40"))
	infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("39"))

	counts := fmt.Sprintf("  %s: %d  %s: %d  %s: %d  %s: %d  %s: %d",
		critStyle.Render("Critical"), m.Counts.Critical,
		highStyle.Render("High"), m.Counts.High,
		medStyle.Render("Medium"), m.Counts.Medium,
		lowStyle.Render("Low"), m.Counts.Low,
		infoStyle.Render("Info"), m.Counts.Info,
	)
	b.WriteString(counts)
	b.WriteString("\n")

	helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	b.WriteString(helpStyle.Render("  [q] quit"))
	b.WriteString("\n")

	return b.String()
}

func statusDisplay(status string) (string, lipgloss.Style) {
	switch status {
	case "running":
		return "⟳", lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	case "completed":
		return "✓", lipgloss.NewStyle().Foreground(lipgloss.Color("40"))
	case "failed":
		return "✗", lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	case "skipped":
		return "⚠", lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	default: // queued
		return "○", lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
