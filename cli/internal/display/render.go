package display

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// Finding represents a display-ready finding.
type Finding struct {
	Category    string
	File        string
	Line        int
	Severity    string
	Message     string
	CWE         string
	Tool        string
	Remediation string
}

// ScanMeta holds scan metadata for the summary card.
type ScanMeta struct {
	Target   string
	Language string
	Mode     string
	Duration string
	ToolsOK  int
	ToolsFailed int
	TaskID   string
}

// SeverityCounts for the summary card.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func (c SeverityCounts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// termWidth returns the current terminal width, defaulting to 80.
func termWidth() int {
	w, _, err := term.GetSize(0)
	if err != nil || w < 40 {
		return 80
	}
	return w
}

// RenderFindingsTable renders a grouped, color-coded findings table.
func RenderFindingsTable(findings []Finding) string {
	if len(findings) == 0 {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color("40")).
			Bold(true).
			Render("✓ No security findings detected.")
	}

	width := termWidth()

	// Group by category
	byCategory := map[string][]Finding{}
	categoryOrder := []string{}
	for _, f := range findings {
		if _, exists := byCategory[f.Category]; !exists {
			categoryOrder = append(categoryOrder, f.Category)
		}
		byCategory[f.Category] = append(byCategory[f.Category], f)
	}

	var b strings.Builder

	for _, cat := range categoryOrder {
		items := byCategory[cat]

		// Category header
		headerStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39")).
			MarginTop(1)
		countBadge := lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Render(fmt.Sprintf("(%d)", len(items)))
		b.WriteString(headerStyle.Render(formatCategoryName(cat)) + " " + countBadge + "\n")

		// Column widths based on terminal size
		fileW := min(width/3, 35)
		msgW := min(width/2, 50)

		// Table header
		dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
		b.WriteString(dimStyle.Render(fmt.Sprintf("  %-8s %-*s %5s  %-*s",
			"SEV", fileW, "FILE", "LINE", msgW, "MESSAGE")))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render(strings.Repeat("─", min(width-2, fileW+msgW+20))))
		b.WriteString("\n")

		for i, f := range items {
			sev := severityBadge(f.Severity)

			file := f.File
			if len(file) > fileW-2 {
				file = "..." + file[len(file)-(fileW-5):]
			}

			msg := f.Message
			if len(msg) > msgW-2 {
				msg = msg[:msgW-5] + "..."
			}

			// Alternate row shading
			rowStyle := lipgloss.NewStyle()
			if i%2 == 1 {
				rowStyle = rowStyle.Background(lipgloss.Color("235"))
			}

			line := fmt.Sprintf("  %s %-*s %5d  %s", sev, fileW, file, f.Line, msg)
			b.WriteString(rowStyle.Render(line))
			b.WriteString("\n")
		}
	}

	return b.String()
}

// RenderSummaryCard renders a bordered severity summary card.
func RenderSummaryCard(meta ScanMeta, counts SeverityCounts) string {
	critStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	highStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	medStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
	lowStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("40"))
	infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("39"))

	card := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 2).
		Width(55)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))

	if counts.Total() == 0 {
		content := fmt.Sprintf("%s\n%s",
			title.Render("✓ Scan Complete — No Issues Found"),
			fmt.Sprintf("Target: %s (%s, %s)", meta.Target, meta.Language, meta.Mode),
		)
		return card.BorderForeground(lipgloss.Color("40")).Render(content)
	}

	content := fmt.Sprintf("%s\n%s\n%s\n\n%s: %d  %s: %d  %s: %d  %s: %d  %s: %d\n\nTotal: %d findings",
		title.Render("Scan Complete"),
		fmt.Sprintf("Target: %s (%s, %s)", meta.Target, meta.Language, meta.Mode),
		fmt.Sprintf("Tools: %d ok, %d failed", meta.ToolsOK, meta.ToolsFailed),
		critStyle.Render("Critical"), counts.Critical,
		highStyle.Render("High"), counts.High,
		medStyle.Render("Medium"), counts.Medium,
		lowStyle.Render("Low"), counts.Low,
		infoStyle.Render("Info"), counts.Info,
		counts.Total(),
	)

	if meta.TaskID != "" {
		content += fmt.Sprintf("\n\nTask ID: %s\nView: armur history show %s", meta.TaskID, meta.TaskID)
	}

	return card.Render(content)
}

// RenderToolErrors renders a warning block for failed tools.
func RenderToolErrors(errors []map[string]string) string {
	if len(errors) == 0 {
		return ""
	}

	warnStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("220")).
		Bold(true)

	var b strings.Builder
	b.WriteString(warnStyle.Render("⚠ Tool Errors"))
	b.WriteString("\n")

	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	for _, e := range errors {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  • %s: %s", e["tool"], e["message"])))
		b.WriteString("\n")
	}
	return b.String()
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

func formatCategoryName(cat string) string {
	name := strings.ReplaceAll(cat, "_", " ")
	name = strings.Title(name)
	return name
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
