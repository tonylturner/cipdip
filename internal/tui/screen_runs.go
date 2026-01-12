package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// RunsScreenModel handles the full-screen runs history view.
type RunsScreenModel struct {
	state      *AppState
	styles     Styles
	cursor     int
	filterType string // "all", "client", "server", "pcap"
	showDetail bool
}

var runsFilterTypes = []string{"all", "client", "server", "pcap"}

// NewRunsScreenModel creates a new runs screen.
func NewRunsScreenModel(state *AppState, styles Styles) *RunsScreenModel {
	return &RunsScreenModel{
		state:      state,
		styles:     styles,
		filterType: "all",
	}
}

// Update handles input for the runs screen.
func (m *RunsScreenModel) Update(msg tea.KeyMsg) (*RunsScreenModel, tea.Cmd) {
	if m.showDetail {
		switch msg.String() {
		case "esc", "enter", "backspace":
			m.showDetail = false
		}
		return m, nil
	}

	filtered := m.filteredRuns()

	switch msg.String() {
	case "tab":
		for i, t := range runsFilterTypes {
			if t == m.filterType {
				m.filterType = runsFilterTypes[(i+1)%len(runsFilterTypes)]
				m.cursor = 0
				break
			}
		}
	case "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down":
		if m.cursor < len(filtered)-1 {
			m.cursor++
		}
	case "enter":
		if m.cursor < len(filtered) {
			m.showDetail = true
		}
	}
	return m, nil
}

func (m *RunsScreenModel) filteredRuns() []string {
	if m.filterType == "all" {
		return m.state.Runs
	}

	var filtered []string
	for _, run := range m.state.Runs {
		parts := strings.Split(run, "_")
		if len(parts) >= 3 {
			runType := parts[2]
			if strings.Contains(runType, m.filterType) {
				filtered = append(filtered, run)
			}
		}
	}
	return filtered
}

// View renders the runs screen.
func (m *RunsScreenModel) View() string {
	fullWidth := 118
	s := m.styles

	header := m.renderHeader(fullWidth)

	// Filter tabs
	var tabs []string
	for _, t := range runsFilterTypes {
		if t == m.filterType {
			tabs = append(tabs, s.Selected.Render("["+t+"]"))
		} else {
			tabs = append(tabs, s.Dim.Render(t))
		}
	}
	filterLine := "Filter: " + strings.Join(tabs, " | ")

	// Run list
	filtered := m.filteredRuns()
	var lines []string

	if len(filtered) == 0 {
		lines = append(lines, s.Dim.Render("No runs found"))
	} else {
		for i, run := range filtered {
			if i >= 15 {
				lines = append(lines, s.Dim.Render(fmt.Sprintf("  +%d more...", len(filtered)-15)))
				break
			}

			name := filepath.Base(run)
			parts := strings.Split(name, "_")

			timeStr := ""
			runType := "run"
			scenario := ""
			status := "success"

			if len(parts) >= 2 {
				if t, err := time.Parse("2006-01-02_15-04", parts[0]+"_"+parts[1]); err == nil {
					timeStr = t.Format("01-02 15:04")
				}
			}
			if len(parts) >= 3 {
				runType = parts[2]
			}
			if len(parts) >= 4 {
				scenario = parts[3]
			}

			cursor := "  "
			if i == m.cursor {
				cursor = s.Selected.Render("> ")
			}

			icon := StatusIcon(status, s)
			timePart := s.Dim.Render(padRight(timeStr, 12))
			typePart := padRight(runType, 8)
			scenarioPart := s.Dim.Render(scenario)

			if i == m.cursor {
				typePart = s.Selected.Render(typePart)
			}

			line := fmt.Sprintf("%s%s %s %-8s %s", cursor, icon, timePart, typePart, scenarioPart)
			lines = append(lines, line)
		}
	}

	content := filterLine + "\n\n" + strings.Join(lines, "\n")

	// Build output
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

func (m *RunsScreenModel) renderHeader(width int) string {
	s := m.styles

	title := lipgloss.NewStyle().
		Foreground(DefaultTheme.Info).
		Bold(true).
		Render("RUNS")

	subtitle := s.Dim.Render("History")

	filtered := m.filteredRuns()
	count := s.Dim.Render(fmt.Sprintf("%d runs", len(filtered)))

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
func (m *RunsScreenModel) Footer() string {
	if m.showDetail {
		return KeyHints([]KeyHint{{"Esc", "Back"}, {"o", "Open"}, {"m", "Menu"}}, m.styles)
	}
	return KeyHints([]KeyHint{
		{"Tab", "Filter"},
		{"Enter", "Details"},
		{"m", "Menu"},
		{"q", "Quit"},
	}, m.styles)
}
