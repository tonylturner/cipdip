package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Layout constants
const (
	DefaultWidth  = 120
	DefaultHeight = 40
	MinWidth      = 60
	MaxWidth      = 120

	PaddingSmall  = 1
	PaddingMedium = 2
	PaddingLarge  = 3

	SpacingTight  = 1
	SpacingNormal = 2
	SpacingWide   = 3
)

// Layout holds layout calculations for the current terminal size.
type Layout struct {
	Width  int
	Height int

	// Calculated regions
	ContentWidth  int
	ContentHeight int
	SidebarWidth  int
}

// NewLayout creates a new layout for the given terminal size.
func NewLayout(width, height int) Layout {
	if width < MinWidth {
		width = MinWidth
	}
	if width > MaxWidth {
		width = MaxWidth
	}

	l := Layout{
		Width:  width,
		Height: height,
	}

	// Content area: full width minus padding
	l.ContentWidth = width - (PaddingMedium * 2) - 2 // 2 for border

	// Height: leave room for header and footer
	l.ContentHeight = height - 6

	// Sidebar for help panel
	l.SidebarWidth = 36

	return l
}

// MainWidth returns the width for main content when sidebar is shown.
func (l Layout) MainWidth() int {
	return l.Width - l.SidebarWidth - 3 // 3 for gap
}

// JoinVertical joins strings vertically with the specified gap.
func JoinVertical(gap int, parts ...string) string {
	spacer := strings.Repeat("\n", gap)
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, spacer)
}

// JoinHorizontal joins strings horizontally with the specified gap.
func JoinHorizontal(gap int, parts ...string) string {
	if len(parts) == 0 {
		return ""
	}

	// Split each part into lines
	partLines := make([][]string, len(parts))
	maxLines := 0
	for i, p := range parts {
		partLines[i] = strings.Split(p, "\n")
		if len(partLines[i]) > maxLines {
			maxLines = len(partLines[i])
		}
	}

	// Calculate widths
	widths := make([]int, len(parts))
	for i, lines := range partLines {
		for _, line := range lines {
			w := lipgloss.Width(line)
			if w > widths[i] {
				widths[i] = w
			}
		}
	}

	// Build output
	spacer := strings.Repeat(" ", gap)
	var result strings.Builder
	for lineNum := 0; lineNum < maxLines; lineNum++ {
		for i, lines := range partLines {
			line := ""
			if lineNum < len(lines) {
				line = lines[lineNum]
			}
			// Pad to width
			lineWidth := lipgloss.Width(line)
			if lineWidth < widths[i] {
				line += strings.Repeat(" ", widths[i]-lineWidth)
			}
			result.WriteString(line)
			if i < len(parts)-1 {
				result.WriteString(spacer)
			}
		}
		if lineNum < maxLines-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}

// Center centers text within the given width.
func Center(text string, width int) string {
	lines := strings.Split(text, "\n")
	var result []string
	for _, line := range lines {
		lineWidth := lipgloss.Width(line)
		if lineWidth >= width {
			result = append(result, line)
			continue
		}
		padding := (width - lineWidth) / 2
		result = append(result, strings.Repeat(" ", padding)+line)
	}
	return strings.Join(result, "\n")
}

// Truncate truncates text to fit within width, adding ellipsis if needed.
func Truncate(text string, width int) string {
	if width < 4 {
		return text
	}
	if lipgloss.Width(text) <= width {
		return text
	}
	// Find truncation point
	runes := []rune(text)
	for i := len(runes) - 1; i >= 0; i-- {
		truncated := string(runes[:i]) + "..."
		if lipgloss.Width(truncated) <= width {
			return truncated
		}
	}
	return "..."
}

// WrapText wraps text to fit within the given width.
func WrapText(text string, width int) []string {
	if width < 10 {
		width = 10
	}

	var lines []string
	for _, paragraph := range strings.Split(text, "\n") {
		if paragraph == "" {
			lines = append(lines, "")
			continue
		}

		// Preserve leading whitespace
		leadingSpaces := 0
		for _, c := range paragraph {
			if c == ' ' {
				leadingSpaces++
			} else {
				break
			}
		}
		indent := strings.Repeat(" ", leadingSpaces)
		paragraph = strings.TrimLeft(paragraph, " ")

		words := strings.Fields(paragraph)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}

		currentLine := indent
		for _, word := range words {
			testLine := currentLine
			if currentLine != indent {
				testLine += " "
			}
			testLine += word

			if lipgloss.Width(testLine) <= width {
				if currentLine != indent {
					currentLine += " "
				}
				currentLine += word
			} else {
				if currentLine != indent {
					lines = append(lines, currentLine)
				}
				currentLine = indent + word
			}
		}
		if currentLine != indent {
			lines = append(lines, currentLine)
		}
	}

	return lines
}

// Grid creates a grid layout with the specified number of columns.
type Grid struct {
	Columns int
	Gap     int
	Items   []string
}

// Render renders the grid.
func (g Grid) Render(totalWidth int) string {
	if g.Columns < 1 {
		g.Columns = 2
	}
	if g.Gap < 1 {
		g.Gap = 2
	}

	// Calculate column width
	colWidth := (totalWidth - (g.Columns-1)*g.Gap) / g.Columns

	// Chunk items into rows
	var rows []string
	for i := 0; i < len(g.Items); i += g.Columns {
		end := i + g.Columns
		if end > len(g.Items) {
			end = len(g.Items)
		}
		rowItems := g.Items[i:end]

		// Pad each item to column width
		var paddedItems []string
		for _, item := range rowItems {
			lines := strings.Split(item, "\n")
			var paddedLines []string
			for _, line := range lines {
				w := lipgloss.Width(line)
				if w < colWidth {
					line += strings.Repeat(" ", colWidth-w)
				}
				paddedLines = append(paddedLines, line)
			}
			paddedItems = append(paddedItems, strings.Join(paddedLines, "\n"))
		}

		rows = append(rows, JoinHorizontal(g.Gap, paddedItems...))
	}

	return strings.Join(rows, "\n")
}

// AlignColumns aligns multiple columns of text.
func AlignColumns(columns [][]string, widths []int, gap int) string {
	if len(columns) == 0 {
		return ""
	}

	// Find max rows
	maxRows := 0
	for _, col := range columns {
		if len(col) > maxRows {
			maxRows = len(col)
		}
	}

	spacer := strings.Repeat(" ", gap)
	var result strings.Builder

	for row := 0; row < maxRows; row++ {
		for colIdx, col := range columns {
			cell := ""
			if row < len(col) {
				cell = col[row]
			}

			// Get width
			width := 10
			if colIdx < len(widths) {
				width = widths[colIdx]
			}

			// Pad cell
			cellWidth := lipgloss.Width(cell)
			if cellWidth < width {
				cell += strings.Repeat(" ", width-cellWidth)
			}

			result.WriteString(cell)
			if colIdx < len(columns)-1 {
				result.WriteString(spacer)
			}
		}
		if row < maxRows-1 {
			result.WriteString("\n")
		}
	}

	return result.String()
}
