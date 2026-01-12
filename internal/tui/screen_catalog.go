package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// CatalogScreenModel handles the full-screen catalog view.
type CatalogScreenModel struct {
	state  *AppState
	styles Styles
	cursor int
	search string
	mode   string // "browse", "search", "detail"
}

// NewCatalogScreenModel creates a new catalog screen.
func NewCatalogScreenModel(state *AppState, styles Styles) *CatalogScreenModel {
	return &CatalogScreenModel{
		state:  state,
		styles: styles,
		mode:   "browse",
	}
}

// Update handles input for the catalog screen.
func (m *CatalogScreenModel) Update(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	switch msg.String() {
	case "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down":
		m.cursor++
	case "/":
		m.mode = "search"
	case "esc":
		if m.mode == "search" || m.mode == "detail" {
			m.mode = "browse"
		}
	case "enter":
		if m.mode == "browse" {
			m.mode = "detail"
		}
	}
	return m, nil
}

// View renders the catalog screen.
func (m *CatalogScreenModel) View() string {
	fullWidth := 118
	s := m.styles

	header := m.renderHeader(fullWidth)

	// Sample catalog categories
	categories := []struct {
		name  string
		items []string
	}{
		{"Identity Objects", []string{"Identity (0x01)", "Message Router (0x02)", "Assembly (0x04)"}},
		{"Network Objects", []string{"TCP/IP Interface (0xF5)", "Ethernet Link (0xF6)", "Connection Manager (0x06)"}},
		{"Application Objects", []string{"Parameter (0x0F)", "File (0x37)", "Time Sync (0x43)"}},
	}

	var lines []string
	idx := 0
	for _, cat := range categories {
		lines = append(lines, s.Header.Render(cat.name))
		for _, item := range cat.items {
			cursor := "  "
			if idx == m.cursor {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+item)
			idx++
		}
		lines = append(lines, "")
	}

	content := strings.Join(lines, "\n")

	// Build box
	innerWidth := fullWidth - 4
	var result strings.Builder
	result.WriteString(header + "\n\n")

	for _, line := range strings.Split(content, "\n") {
		lineWidth := lipgloss.Width(line)
		if lineWidth < innerWidth {
			line += strings.Repeat(" ", innerWidth-lineWidth)
		}
		result.WriteString(line + "\n")
	}

	outerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(DefaultTheme.Border).
		Padding(0, 1)

	return outerStyle.Render(result.String())
}

func (m *CatalogScreenModel) renderHeader(width int) string {
	s := m.styles

	title := lipgloss.NewStyle().
		Foreground(DefaultTheme.Purple).
		Bold(true).
		Render("CATALOG")

	subtitle := s.Dim.Render("CIP Object Browser")

	count := s.Dim.Render(fmt.Sprintf("%d entries", len(m.state.Catalog)))

	left := title + "  " + subtitle
	right := count

	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	padding := width - leftWidth - rightWidth
	if padding < 1 {
		padding = 1
	}

	header := left + strings.Repeat(" ", padding) + right
	return header + "\n" + s.Muted.Render(strings.Repeat("─", width))
}

// Footer returns the footer text.
func (m *CatalogScreenModel) Footer() string {
	return KeyHints([]KeyHint{
		{"/", "Search"},
		{"Enter", "Details"},
		{"m", "Menu"},
		{"q", "Quit"},
	}, m.styles)
}
