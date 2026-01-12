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

	// Detail view
	selectedArtifact int
	artifacts        []string
	artifactContent  string

	// Confirmation
	confirmDelete bool
}

var runsFilterTypes = []string{"all", "client", "server", "pcap"}

// NewRunsScreenModel creates a new runs screen.
func NewRunsScreenModel(state *AppState, styles Styles) *RunsScreenModel {
	return &RunsScreenModel{
		state:      state,
		styles:     styles,
		filterType: "all",
		artifacts:  []string{"command.txt", "stdout.log", "resolved.yaml", "summary.json"},
	}
}

// Update handles input for the runs screen.
func (m *RunsScreenModel) Update(msg tea.KeyMsg) (*RunsScreenModel, tea.Cmd) {
	// Handle delete confirmation
	if m.confirmDelete {
		switch msg.String() {
		case "y", "Y":
			// TODO: Actually delete the run
			m.confirmDelete = false
		case "n", "N", "esc":
			m.confirmDelete = false
		}
		return m, nil
	}

	if m.showDetail {
		switch msg.String() {
		case "esc", "backspace":
			m.showDetail = false
		case "up", "k":
			if m.selectedArtifact > 0 {
				m.selectedArtifact--
			}
		case "down", "j":
			if m.selectedArtifact < len(m.artifacts)-1 {
				m.selectedArtifact++
			}
		case "o":
			// TODO: Open in editor
		case "r":
			// TODO: Re-run command
		case "y":
			// TODO: Copy command to clipboard
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
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(filtered)-1 {
			m.cursor++
		}
	case "enter":
		if m.cursor < len(filtered) {
			m.showDetail = true
			m.selectedArtifact = 0
		}
	case "o":
		// Open selected run in editor
		// TODO: implement
	case "r":
		// Re-run selected
		// TODO: implement
	case "y":
		// Copy command
		// TODO: implement
	case "d":
		// Delete with confirmation
		if m.cursor < len(filtered) {
			m.confirmDelete = true
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

	var content string

	// Handle delete confirmation
	if m.confirmDelete {
		filtered := m.filteredRuns()
		runName := ""
		if m.cursor < len(filtered) {
			runName = filepath.Base(filtered[m.cursor])
		}
		content = s.Warning.Render("Delete run: "+runName+"?") + "\n\n" +
			s.Dim.Render("Press [y] to confirm, [n] or [Esc] to cancel")
	} else if m.showDetail {
		content = m.renderDetailView(s, fullWidth)
	} else {
		content = m.renderListView(s)
	}

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

func (m *RunsScreenModel) renderListView(s Styles) string {
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

	return filterLine + "\n\n" + strings.Join(lines, "\n")
}

func (m *RunsScreenModel) renderDetailView(s Styles, width int) string {
	filtered := m.filteredRuns()
	if m.cursor >= len(filtered) {
		return s.Dim.Render("No run selected")
	}

	runName := filepath.Base(filtered[m.cursor])
	parts := strings.Split(runName, "_")

	var lines []string
	lines = append(lines, s.Header.Render("Run Details: ")+runName)
	lines = append(lines, "")

	// Parse run info
	if len(parts) >= 3 {
		lines = append(lines, fmt.Sprintf("Type:     %s", parts[2]))
	}
	if len(parts) >= 4 {
		lines = append(lines, fmt.Sprintf("Scenario: %s", parts[3]))
	}
	if len(parts) >= 2 {
		if t, err := time.Parse("2006-01-02_15-04", parts[0]+"_"+parts[1]); err == nil {
			lines = append(lines, fmt.Sprintf("Time:     %s", t.Format("2006-01-02 15:04")))
		}
	}

	// Artifacts
	lines = append(lines, "")
	lines = append(lines, s.Header.Render("Artifacts:"))
	for i, artifact := range m.artifacts {
		cursor := "  "
		if i == m.selectedArtifact {
			cursor = s.Selected.Render("> ")
		}
		icon := "📄"
		if artifact == "stdout.log" {
			icon = "📋"
		} else if artifact == "summary.json" {
			icon = "📊"
		}
		lines = append(lines, fmt.Sprintf("%s%s %s", cursor, icon, artifact))
	}

	// Sample artifact content preview
	lines = append(lines, "")
	lines = append(lines, s.Header.Render("Preview:"))
	switch m.artifacts[m.selectedArtifact] {
	case "command.txt":
		lines = append(lines, s.Dim.Render("  cipdip client --ip 192.168.1.100 --scenario baseline"))
	case "stdout.log":
		lines = append(lines, s.Dim.Render("  [INFO] Starting client scenario"))
		lines = append(lines, s.Dim.Render("  [INFO] Connected to 192.168.1.100:44818"))
		lines = append(lines, s.Dim.Render("  [INFO] Running baseline tests..."))
	case "resolved.yaml":
		lines = append(lines, s.Dim.Render("  target_ip: 192.168.1.100"))
		lines = append(lines, s.Dim.Render("  port: 44818"))
		lines = append(lines, s.Dim.Render("  scenario: baseline"))
	case "summary.json":
		lines = append(lines, s.Dim.Render("  {"))
		lines = append(lines, s.Dim.Render("    \"status\": \"success\","))
		lines = append(lines, s.Dim.Render("    \"requests\": 1234,"))
		lines = append(lines, s.Dim.Render("    \"errors\": 0"))
		lines = append(lines, s.Dim.Render("  }"))
	}

	return strings.Join(lines, "\n")
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
	if m.confirmDelete {
		return KeyHints([]KeyHint{{"y", "Confirm"}, {"n/Esc", "Cancel"}}, m.styles)
	}
	if m.showDetail {
		return KeyHints([]KeyHint{
			{"Esc", "Back"},
			{"o", "Open"},
			{"r", "Re-run"},
			{"y", "Copy"},
			{"m", "Menu"},
		}, m.styles)
	}
	return KeyHints([]KeyHint{
		{"Tab", "Filter"},
		{"Enter", "Details"},
		{"o", "Open"},
		{"r", "Re-run"},
		{"d", "Delete"},
		{"m", "Menu"},
	}, m.styles)
}
