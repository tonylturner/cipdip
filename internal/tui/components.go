package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// SectionBox renders a titled box with content.
//
//	╭─ TITLE ──────────────────────────╮
//	│  content line 1                  │
//	│  content line 2                  │
//	╰──────────────────────────────────╯
func SectionBox(title, content string, width int, s Styles) string {
	if width < 20 {
		width = 60
	}

	// Build title bar: ─ TITLE ──────
	titleText := " " + title + " "
	titleLen := lipgloss.Width(titleText)
	remainingWidth := width - 4 - titleLen // 4 for corners and initial dash
	if remainingWidth < 0 {
		remainingWidth = 0
	}

	titleBar := "─" + s.Header.Render(titleText) + strings.Repeat("─", remainingWidth)

	// Apply box style
	box := lipgloss.NewStyle().
		Border(lipgloss.Border{
			Top:         "",
			Bottom:      "─",
			Left:        "│",
			Right:       "│",
			TopLeft:     "╭",
			TopRight:    "╮",
			BottomLeft:  "╰",
			BottomRight: "╯",
		}).
		BorderForeground(DefaultTheme.Border).
		Width(width - 2). // Account for border
		Padding(0, 1)

	// Build the full box manually for the custom top border
	contentBox := box.Render(content)
	lines := strings.Split(contentBox, "\n")

	// Replace first line with our custom title bar
	var result strings.Builder
	result.WriteString("╭" + titleBar + "╮\n")
	for i := 1; i < len(lines); i++ {
		result.WriteString(lines[i])
		if i < len(lines)-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

// Table renders a data table with headers and rows.
type Table struct {
	Headers []string
	Rows    [][]string
	Widths  []int // Column widths (0 = auto)
}

// Render renders the table.
func (t Table) Render(width int, s Styles) string {
	if len(t.Headers) == 0 || len(t.Rows) == 0 {
		return ""
	}

	// Calculate column widths
	colWidths := make([]int, len(t.Headers))
	for i, h := range t.Headers {
		if i < len(t.Widths) && t.Widths[i] > 0 {
			colWidths[i] = t.Widths[i]
		} else {
			colWidths[i] = lipgloss.Width(h)
		}
	}
	for _, row := range t.Rows {
		for i, cell := range row {
			if i < len(colWidths) {
				w := lipgloss.Width(cell)
				if w > colWidths[i] && (i >= len(t.Widths) || t.Widths[i] == 0) {
					colWidths[i] = w
				}
			}
		}
	}

	var b strings.Builder

	// Header row
	for i, h := range t.Headers {
		cell := padRight(h, colWidths[i])
		b.WriteString(s.SectionName.Render(cell))
		if i < len(t.Headers)-1 {
			b.WriteString("  ")
		}
	}
	b.WriteString("\n")

	// Separator
	totalWidth := 0
	for i, w := range colWidths {
		totalWidth += w
		if i < len(colWidths)-1 {
			totalWidth += 2 // spacing
		}
	}
	b.WriteString(s.Muted.Render(strings.Repeat("─", totalWidth)))
	b.WriteString("\n")

	// Data rows
	for _, row := range t.Rows {
		for i := 0; i < len(t.Headers); i++ {
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			cell = padRight(cell, colWidths[i])
			b.WriteString(cell)
			if i < len(t.Headers)-1 {
				b.WriteString("  ")
			}
		}
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

// ProgressBar renders a progress bar.
//
//	Running ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 67%
func ProgressBar(label string, percent int, width int, s Styles) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	// Reserve space for label and percentage
	labelWidth := lipgloss.Width(label)
	percentStr := fmt.Sprintf("%3d%%", percent)
	barWidth := width - labelWidth - len(percentStr) - 2 // 2 for spacing
	if barWidth < 10 {
		barWidth = 10
	}

	filled := (barWidth * percent) / 100
	empty := barWidth - filled

	bar := s.ProgressFilled.Render(strings.Repeat("━", filled)) +
		s.ProgressEmpty.Render(strings.Repeat("━", empty))

	return label + " " + bar + " " + s.Dim.Render(percentStr)
}

// StatusBadge renders a colored status indicator with label.
//
//	● Running
func StatusBadge(status, label string, s Styles) string {
	icon := StatusIcon(status, s)
	var style lipgloss.Style
	switch status {
	case "success", "ok", "done", "completed":
		style = s.Success
	case "error", "failed", "fail":
		style = s.Error
	case "warning", "warn":
		style = s.Warning
	case "running", "active":
		style = s.Running
	default:
		style = s.Dim
	}
	return icon + " " + style.Render(label)
}

// InputField renders a styled input field.
//
//	Label    │ value█                      │
func InputField(label, value string, active bool, width int, s Styles) string {
	labelWidth := 12
	inputWidth := width - labelWidth - 5 // Account for separator and padding
	if inputWidth < 10 {
		inputWidth = 20
	}

	labelStr := padRight(label, labelWidth)

	// Add cursor if active
	displayValue := value
	if active {
		displayValue = value + "█"
	}

	// Pad or truncate value
	if lipgloss.Width(displayValue) > inputWidth {
		displayValue = displayValue[:inputWidth-3] + "..."
	}
	displayValue = padRight(displayValue, inputWidth)

	var valueStyle lipgloss.Style
	if active {
		valueStyle = s.InputActive
	} else {
		valueStyle = s.Input
	}

	return s.Label.Render(labelStr) + " │ " + valueStyle.Render(displayValue) + " │"
}

// TabBar renders a horizontal tab bar.
//
//	┌────────┬─────────┬────────┐
//	│ Active │  Tab 2  │ Tab 3  │
//	└────────┴─────────┴────────┘
func TabBar(tabs []string, selected int, s Styles) string {
	if len(tabs) == 0 {
		return ""
	}

	// Calculate tab widths (minimum 8 chars)
	tabWidths := make([]int, len(tabs))
	for i, tab := range tabs {
		w := lipgloss.Width(tab) + 2 // padding
		if w < 8 {
			w = 8
		}
		tabWidths[i] = w
	}

	var top, mid, bot strings.Builder

	for i, tab := range tabs {
		w := tabWidths[i]

		// Top border
		if i == 0 {
			top.WriteString("┌")
		} else {
			top.WriteString("┬")
		}
		top.WriteString(strings.Repeat("─", w))

		// Content
		mid.WriteString("│")
		content := padCenter(tab, w)
		if i == selected {
			mid.WriteString(s.Selected.Render(content))
		} else {
			mid.WriteString(s.Dim.Render(content))
		}

		// Bottom border
		if i == 0 {
			bot.WriteString("└")
		} else {
			bot.WriteString("┴")
		}
		bot.WriteString(strings.Repeat("─", w))
	}

	// Close the borders
	top.WriteString("┐")
	mid.WriteString("│")
	bot.WriteString("┘")

	return top.String() + "\n" + mid.String() + "\n" + bot.String()
}

// KeyHints renders a row of keyboard shortcuts.
//
//	[c] Client    [s] Server    [q] Quit
func KeyHints(hints []KeyHint, s Styles) string {
	var parts []string
	for _, h := range hints {
		key := s.KeyBinding.Render("[" + h.Key + "]")
		label := s.KeyHint.Render(h.Label)
		parts = append(parts, key+" "+label)
	}
	return strings.Join(parts, "    ")
}

// KeyHint represents a keyboard shortcut hint.
type KeyHint struct {
	Key   string
	Label string
}

// MenuItem renders a menu item with optional selection.
//
//	> [c] Client    Description here
func MenuItem(key, label, description string, selected bool, s Styles) string {
	cursor := "  "
	if selected {
		cursor = s.Selected.Render("> ")
	}

	keyPart := s.KeyBinding.Render("[" + key + "]")
	labelPart := label
	if selected {
		labelPart = s.Selected.Render(label)
	}

	descPart := s.Dim.Render(description)

	return cursor + keyPart + " " + padRight(labelPart, 12) + " " + descPart
}

// RadioOption renders a radio button option.
//
//	(●) Selected option
//	( ) Other option
func RadioOption(label string, selected bool, s Styles) string {
	icon := RadioIcon(selected, s)
	if selected {
		return icon + " " + s.Selected.Render(label)
	}
	return icon + " " + label
}

// CheckboxOption renders a checkbox option.
//
//	[✓] Enabled option
//	[ ] Disabled option
func CheckboxOption(label string, checked bool, s Styles) string {
	icon := CheckboxIcon(checked, s)
	if checked {
		return icon + " " + s.Success.Render(label)
	}
	return icon + " " + s.Dim.Render(label)
}

// Divider renders a horizontal divider line.
func Divider(width int, s Styles) string {
	return s.Muted.Render(strings.Repeat("─", width))
}

// CodeBlock renders text in a code-style box.
func CodeBlock(content string, width int, s Styles) string {
	style := lipgloss.NewStyle().
		Foreground(DefaultTheme.TextDim).
		Background(DefaultTheme.BgPanel).
		Padding(0, 1).
		Width(width)
	return style.Render(content)
}

// Helper functions

func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func padCenter(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	left := (width - w) / 2
	right := width - w - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

// truncateString truncates a string to max length, adding "..." if truncated.
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// TestResultMsg represents the result of a catalog test execution.
type TestResultMsg struct {
	Result string
	Error  string
}
