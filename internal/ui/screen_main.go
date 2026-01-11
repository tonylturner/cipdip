package ui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// MainScreenModel handles the main menu screen.
type MainScreenModel struct {
	state    *AppState
	cursor   int
	Navigate Screen // Set to navigate to another screen
}

// Menu items for main screen
var mainMenuItems = []struct {
	Key   string
	Label string
	Desc  string
}{
	{"c", "Client", "Configure and run client scenarios"},
	{"s", "Server", "Start server emulator"},
	{"p", "PCAP", "Analyze, replay, or rewrite captures"},
	{"k", "Catalog", "Browse CIP classes and services"},
	{"r", "Runs", "View past run results"},
}

// NewMainScreenModel creates a new main screen model.
func NewMainScreenModel(state *AppState) *MainScreenModel {
	return &MainScreenModel{
		state:    state,
		Navigate: ScreenMain,
	}
}

// Update handles input for the main screen.
func (m *MainScreenModel) Update(msg tea.KeyMsg) (*MainScreenModel, tea.Cmd) {
	switch msg.String() {
	case "c":
		m.Navigate = ScreenClient
	case "s":
		m.Navigate = ScreenServer
	case "p":
		m.Navigate = ScreenPCAP
	case "k":
		m.Navigate = ScreenCatalog
	case "r":
		m.Navigate = ScreenRuns
	case "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down":
		if m.cursor < len(mainMenuItems)-1 {
			m.cursor++
		}
	case "enter":
		// Navigate based on cursor position
		switch m.cursor {
		case 0:
			m.Navigate = ScreenClient
		case 1:
			m.Navigate = ScreenServer
		case 2:
			m.Navigate = ScreenPCAP
		case 3:
			m.Navigate = ScreenCatalog
		case 4:
			m.Navigate = ScreenRuns
		}
	}
	return m, nil
}

// View renders the main screen.
func (m *MainScreenModel) View() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("CIPDIP"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Menu items
	for i, item := range mainMenuItems {
		prefix := "  "
		if i == m.cursor {
			prefix = "> "
			line := fmt.Sprintf("%s[%s] %-12s %s", prefix, item.Key, item.Label, item.Desc)
			b.WriteString(selectedStyle.Render(line))
		} else {
			line := fmt.Sprintf("%s[%s] %-12s %s", prefix, item.Key, item.Label, item.Desc)
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Recent runs section
	b.WriteString("Recent:\n")

	if len(m.state.Runs) == 0 && !m.state.ServerRunning {
		b.WriteString(dimStyle.Render("  (no recent activity)"))
		b.WriteString("\n")
	} else {
		// Show running server if active
		if m.state.ServerRunning {
			b.WriteString(warningStyle.Render("          server adapter   :44818        running..."))
			b.WriteString("\n")
		}

		// Show recent runs (up to 5)
		displayRuns := m.state.Runs
		if len(displayRuns) > 5 {
			displayRuns = displayRuns[:5]
		}
		for _, run := range displayRuns {
			b.WriteString(m.formatRunEntry(run))
			b.WriteString("\n")
		}
	}

	return borderStyle.Render(b.String())
}

// formatRunEntry formats a run directory name into a display entry.
// Run dirs have format: 2026-01-10_10-41_client_baseline
func (m *MainScreenModel) formatRunEntry(runDir string) string {
	name := filepath.Base(runDir)
	parts := strings.Split(name, "_")

	// Default values
	timeStr := ""
	runType := "run"
	scenario := ""
	status := "✓"

	if len(parts) >= 2 {
		// Parse date and time: 2026-01-10_10-41
		if t, err := time.Parse("2006-01-02_15-04", parts[0]+"_"+parts[1]); err == nil {
			timeStr = t.Format("15:04")
		} else {
			timeStr = parts[1]
		}
	}
	if len(parts) >= 3 {
		runType = parts[2]
	}
	if len(parts) >= 4 {
		scenario = parts[3]
	}

	// Try to load summary to get status
	summaryPath := filepath.Join(m.state.WorkspaceRoot, "runs", name, "summary.json")
	if summary, err := LoadRunSummary(summaryPath); err == nil {
		if summary.Status == "failed" || summary.Status == "error" {
			status = "✗"
		}
	}

	// Format: "  10:41  client baseline  192.168.1.50   ✓"
	typeScenario := runType
	if scenario != "" {
		typeScenario = runType + " " + scenario
	}

	statusStyle := successStyle
	if status == "✗" {
		statusStyle = errorStyle
	}

	return fmt.Sprintf("  %s  %-20s %s", dimStyle.Render(timeStr), typeScenario, statusStyle.Render(status))
}
