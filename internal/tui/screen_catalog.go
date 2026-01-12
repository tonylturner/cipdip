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
	mode   string // "browse", "search", "detail", "probe"

	// Filtering
	filter     int // 0=all, 1=logix, 2=core
	filterText string

	// Probe
	probeIP   string
	probePort string

	// Expanded items
	expanded map[int]bool
}

// NewCatalogScreenModel creates a new catalog screen.
func NewCatalogScreenModel(state *AppState, styles Styles) *CatalogScreenModel {
	return &CatalogScreenModel{
		state:     state,
		styles:    styles,
		mode:      "browse",
		probePort: "44818",
		expanded:  make(map[int]bool),
	}
}

// Update handles input for the catalog screen.
func (m *CatalogScreenModel) Update(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	// Handle search mode input
	if m.mode == "search" {
		switch msg.String() {
		case "esc":
			m.mode = "browse"
			m.search = ""
		case "enter":
			m.mode = "browse"
			m.filterText = m.search
		case "backspace":
			if len(m.search) > 0 {
				m.search = m.search[:len(m.search)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.search += msg.String()
			}
		}
		return m, nil
	}

	// Handle probe mode input
	if m.mode == "probe" {
		switch msg.String() {
		case "esc":
			m.mode = "browse"
		case "enter":
			// TODO: Actually probe the device
			m.mode = "detail"
		case "tab":
			// Toggle between IP and port
		case "backspace":
			if len(m.probeIP) > 0 {
				m.probeIP = m.probeIP[:len(m.probeIP)-1]
			}
		default:
			ch := msg.String()
			if len(ch) == 1 && (ch == "." || (ch >= "0" && ch <= "9")) {
				m.probeIP += ch
			}
		}
		return m, nil
	}

	// Browse mode
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		m.cursor++
	case "/":
		m.mode = "search"
		m.search = ""
	case "esc":
		if m.mode == "detail" {
			m.mode = "browse"
		} else if m.filterText != "" {
			m.filterText = ""
			m.filter = 0
		}
	case "enter":
		if m.mode == "browse" {
			// Toggle expanded
			m.expanded[m.cursor] = !m.expanded[m.cursor]
		}
	case "p":
		// Probe mode
		m.mode = "probe"
	case "y":
		// Copy EPATH to clipboard (TODO: implement)
	case "0":
		m.filter = 0
		m.filterText = ""
	case "1":
		m.filter = 1
		m.filterText = "logix"
	case "2":
		m.filter = 2
		m.filterText = "core"
	}
	return m, nil
}

// View renders the catalog screen.
func (m *CatalogScreenModel) View() string {
	fullWidth := 118
	s := m.styles

	header := m.renderHeader(fullWidth)

	var lines []string

	// Filter/search bar
	filterBar := m.renderFilterBar(s)
	lines = append(lines, filterBar)
	lines = append(lines, "")

	// Handle probe mode
	if m.mode == "probe" {
		lines = append(lines, s.Header.Render("Probe Device"))
		lines = append(lines, "")
		lines = append(lines, s.Selected.Render("Target IP")+": "+m.probeIP+s.Cursor.Render("█"))
		lines = append(lines, s.Dim.Render("Port")+": "+m.probePort)
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Press Enter to probe, Esc to cancel"))
	} else if m.mode == "search" {
		lines = append(lines, s.Header.Render("Search: ")+m.search+s.Cursor.Render("█"))
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Type to search, Enter to filter, Esc to cancel"))
	} else {
		// Catalog content
		lines = append(lines, m.renderCatalogContent(s)...)
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

func (m *CatalogScreenModel) renderFilterBar(s Styles) string {
	filters := []string{"All", "Logix", "Core"}
	var parts []string
	for i, f := range filters {
		if i == m.filter {
			parts = append(parts, s.Selected.Render("["+f+"]"))
		} else {
			parts = append(parts, s.Dim.Render(f))
		}
	}
	filterLine := "Filter: " + strings.Join(parts, " | ")

	if m.filterText != "" && m.filterText != "logix" && m.filterText != "core" {
		filterLine += "  " + s.Info.Render("Search: "+m.filterText)
	}

	return filterLine
}

func (m *CatalogScreenModel) renderCatalogContent(s Styles) []string {
	// Sample catalog categories
	categories := []struct {
		name   string
		filter string // "all", "logix", "core"
		items  []struct {
			code string
			name string
			desc string
		}
	}{
		{"Identity Objects", "core", []struct {
			code string
			name string
			desc string
		}{
			{"0x01", "Identity", "Device identification"},
			{"0x02", "Message Router", "Message routing"},
			{"0x04", "Assembly", "I/O data assembly"},
		}},
		{"Network Objects", "core", []struct {
			code string
			name string
			desc string
		}{
			{"0xF5", "TCP/IP Interface", "TCP/IP configuration"},
			{"0xF6", "Ethernet Link", "Ethernet statistics"},
			{"0x06", "Connection Manager", "Connection handling"},
		}},
		{"Logix Objects", "logix", []struct {
			code string
			name string
			desc string
		}{
			{"0xAC", "Symbol", "Tag symbols"},
			{"0xB2", "Template", "Data templates"},
			{"0x8E", "Wall Clock", "Time sync"},
		}},
	}

	var lines []string
	idx := 0
	for _, cat := range categories {
		// Filter categories
		if m.filter == 1 && cat.filter != "logix" {
			continue
		}
		if m.filter == 2 && cat.filter != "core" {
			continue
		}

		lines = append(lines, s.Header.Render(cat.name))
		for _, item := range cat.items {
			// Filter by search text
			if m.filterText != "" && m.filterText != "logix" && m.filterText != "core" {
				if !strings.Contains(strings.ToLower(item.name), strings.ToLower(m.filterText)) &&
					!strings.Contains(strings.ToLower(item.code), strings.ToLower(m.filterText)) {
					continue
				}
			}

			cursor := "  "
			if idx == m.cursor {
				cursor = s.Selected.Render("> ")
			}

			itemLine := fmt.Sprintf("%s%s %-20s", cursor, s.Info.Render(item.code), item.name)
			if m.expanded[idx] {
				itemLine += " - " + s.Dim.Render(item.desc)
			}
			lines = append(lines, itemLine)
			idx++
		}
		lines = append(lines, "")
	}

	return lines
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
	if m.mode == "search" {
		return KeyHints([]KeyHint{
			{"Enter", "Apply"},
			{"Esc", "Cancel"},
		}, m.styles)
	}
	if m.mode == "probe" {
		return KeyHints([]KeyHint{
			{"Enter", "Probe"},
			{"Esc", "Cancel"},
		}, m.styles)
	}
	return KeyHints([]KeyHint{
		{"/", "Search"},
		{"0/1/2", "Filter"},
		{"p", "Probe"},
		{"y", "Copy"},
		{"Enter", "Expand"},
		{"m", "Menu"},
	}, m.styles)
}
