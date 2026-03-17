package tui

import (
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ScanFlowStep represents a step in the scan configuration flow.
type ScanFlowStep int

const (
	StepTarget ScanFlowStep = iota
	StepLanguage
	StepDepth
	StepConfirm
)

// ScanFlowModel is the interactive scan configuration flow.
type ScanFlowModel struct {
	Step     ScanFlowStep
	Target   string
	Language string
	Depth    string

	// Options for each step
	targetOptions   []string
	targetCursor    int
	languageOptions []string
	languageCursor  int
	depthOptions    []string
	depthCursor     int
	confirmCursor   int // 0 = Start, 1 = Back, 2 = Cancel

	Confirmed bool
	Cancelled bool
	Width     int
	Height    int
}

func NewScanFlow(cwd string) ScanFlowModel {
	return ScanFlowModel{
		Step:   StepTarget,
		Target: cwd,
		targetOptions: []string{
			fmt.Sprintf("Current directory (%s)", filepath.Base(cwd)),
			"Enter a different path",
			"Scan a remote repository",
		},
		languageOptions: []string{
			"Auto-detect",
			"Go",
			"Python",
			"JavaScript / TypeScript",
			"Rust",
			"Java / Kotlin",
			"Ruby",
			"PHP",
			"C / C++",
			"Infrastructure as Code",
		},
		depthOptions: []string{
			"Quick  — Core tools, ~30 seconds",
			"Deep   — Full tool suite, ~2-3 minutes",
		},
	}
}

func (m ScanFlowModel) Init() tea.Cmd {
	return nil
}

func (m ScanFlowModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.Cancelled = true
			return m, tea.Quit
		case "up", "k":
			m.moveCursorUp()
		case "down", "j":
			m.moveCursorDown()
		case "enter":
			return m.selectCurrent()
		case "backspace", "left":
			if m.Step > StepTarget {
				m.Step--
			}
		}
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
	}
	return m, nil
}

func (m *ScanFlowModel) moveCursorUp() {
	switch m.Step {
	case StepTarget:
		if m.targetCursor > 0 {
			m.targetCursor--
		}
	case StepLanguage:
		if m.languageCursor > 0 {
			m.languageCursor--
		}
	case StepDepth:
		if m.depthCursor > 0 {
			m.depthCursor--
		}
	case StepConfirm:
		if m.confirmCursor > 0 {
			m.confirmCursor--
		}
	}
}

func (m *ScanFlowModel) moveCursorDown() {
	switch m.Step {
	case StepTarget:
		if m.targetCursor < len(m.targetOptions)-1 {
			m.targetCursor++
		}
	case StepLanguage:
		if m.languageCursor < len(m.languageOptions)-1 {
			m.languageCursor++
		}
	case StepDepth:
		if m.depthCursor < len(m.depthOptions)-1 {
			m.depthCursor++
		}
	case StepConfirm:
		if m.confirmCursor < 2 {
			m.confirmCursor++
		}
	}
}

func (m ScanFlowModel) selectCurrent() (tea.Model, tea.Cmd) {
	switch m.Step {
	case StepTarget:
		m.Step = StepLanguage
	case StepLanguage:
		langMap := map[int]string{0: "", 1: "go", 2: "py", 3: "js", 4: "rust", 5: "java", 6: "ruby", 7: "php", 8: "c", 9: "iac"}
		m.Language = langMap[m.languageCursor]
		m.Step = StepDepth
	case StepDepth:
		if m.depthCursor == 0 {
			m.Depth = "quick"
		} else {
			m.Depth = "deep"
		}
		m.Step = StepConfirm
	case StepConfirm:
		switch m.confirmCursor {
		case 0: // Start Scan
			m.Confirmed = true
			return m, tea.Quit
		case 1: // Back
			m.Step = StepDepth
		case 2: // Cancel
			m.Cancelled = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m ScanFlowModel) View() string {
	var b strings.Builder

	width := m.Width
	if width == 0 {
		width = 80
	}
	if width > 80 {
		width = 80
	}

	// Header with step indicator
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("39")).
		PaddingLeft(2)

	stepNames := []string{"Target", "Language", "Depth", "Confirm"}
	var steps []string
	for i, name := range stepNames {
		if i == int(m.Step) {
			steps = append(steps, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(fmt.Sprintf("● %s", name)))
		} else if i < int(m.Step) {
			steps = append(steps, lipgloss.NewStyle().Foreground(lipgloss.Color("40")).Render(fmt.Sprintf("✓ %s", name)))
		} else {
			steps = append(steps, lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(fmt.Sprintf("○ %s", name)))
		}
	}

	b.WriteString("\n")
	b.WriteString(headerStyle.Render("VIBESCAN — Scan Configuration"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(strings.Join(steps, "  →  ")))
	b.WriteString("\n\n")

	sepStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("236"))
	b.WriteString(sepStyle.Render(strings.Repeat("─", width-4)))
	b.WriteString("\n\n")

	// Current step content
	switch m.Step {
	case StepTarget:
		b.WriteString(m.renderOptions("What would you like to scan?", m.targetOptions, m.targetCursor))
	case StepLanguage:
		b.WriteString(m.renderOptions("Select language (or auto-detect)", m.languageOptions, m.languageCursor))
	case StepDepth:
		b.WriteString(m.renderOptions("Scan depth", m.depthOptions, m.depthCursor))
	case StepConfirm:
		b.WriteString(m.renderConfirmation())
	}

	// Footer
	b.WriteString("\n")
	b.WriteString(sepStyle.Render(strings.Repeat("─", width-4)))
	b.WriteString("\n")
	footerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).PaddingLeft(2)
	b.WriteString(footerStyle.Render("↑↓ navigate  enter select  backspace back  esc cancel"))
	b.WriteString("\n")

	return b.String()
}

func (m ScanFlowModel) renderOptions(title string, options []string, cursor int) string {
	var b strings.Builder

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252")).PaddingLeft(2)
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")

	for i, opt := range options {
		selected := i == cursor

		indicator := "  ○ "
		style := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

		if selected {
			indicator = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true).Render("  ● ")
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
		}

		b.WriteString(indicator)
		b.WriteString(style.Render(opt))
		b.WriteString("\n")
	}

	return b.String()
}

func (m ScanFlowModel) renderConfirmation() string {
	var b strings.Builder

	boxStyle := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(1, 3).
		Width(50)

	langDisplay := m.Language
	if langDisplay == "" {
		langDisplay = "auto-detect"
	}

	content := fmt.Sprintf("%s\n\n%s  %s\n%s  %s\n%s  %s",
		lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("Ready to scan"),
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("Target:  "),
		m.Target,
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("Language:"),
		langDisplay,
		lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("Depth:   "),
		m.Depth,
	)

	b.WriteString(lipgloss.NewStyle().PaddingLeft(2).Render(boxStyle.Render(content)))
	b.WriteString("\n\n")

	confirmOptions := []string{"Start Scan", "Go Back", "Cancel"}
	for i, opt := range confirmOptions {
		selected := i == m.confirmCursor
		if selected {
			color := "39"
			if i == 0 {
				color = "40" // green for start
			}
			if i == 2 {
				color = "196" // red for cancel
			}
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).PaddingLeft(4).Render("▸ " + opt))
		} else {
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).PaddingLeft(4).Render("  " + opt))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// GetScanConfig extracts the scan configuration from the flow model.
func (m ScanFlowModel) GetScanConfig() (target, language, depth string) {
	return m.Target, m.Language, m.Depth
}
