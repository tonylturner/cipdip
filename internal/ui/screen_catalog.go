package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// CatalogScreenModel handles the CIP catalog browser screen.
type CatalogScreenModel struct {
	state *AppState

	// Filter
	Filter string

	// Navigation
	cursor       int
	expanded     bool  // Whether viewing class detail
	expandedIdx  int   // Which class is expanded
	attrCursor   int   // Cursor within expanded class
	probeDialog  bool  // Whether probe dialog is open

	// Probe dialog fields
	ProbeIP     string
	ProbePort   string
	ProbeResult string
	ProbeRunning bool

	// UI state
	focusIndex int
	Status     string
}

// NewCatalogScreenModel creates a new catalog screen model.
func NewCatalogScreenModel(state *AppState) *CatalogScreenModel {
	return &CatalogScreenModel{
		state:     state,
		ProbePort: "44818",
	}
}

// Update handles input for the catalog screen.
func (m *CatalogScreenModel) Update(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	if m.probeDialog {
		return m.updateProbeDialog(msg)
	}
	if m.expanded {
		return m.updateExpanded(msg)
	}
	return m.updateList(msg)
}

func (m *CatalogScreenModel) updateList(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	filtered := m.filteredEntries()

	switch msg.String() {
	case "/":
		m.Filter = ""
		m.focusIndex = 0 // Focus on filter
	case "esc":
		if m.Filter != "" {
			m.Filter = ""
			m.cursor = 0
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
		if len(filtered) > 0 && m.cursor < len(filtered) {
			m.expanded = true
			m.expandedIdx = m.cursor
			m.attrCursor = 0
		}
	case "y":
		if len(filtered) > 0 && m.cursor < len(filtered) {
			entry := filtered[m.cursor]
			if err := copyToClipboard(entry.Key); err != nil {
				m.Status = fmt.Sprintf("Copy failed: %v", err)
			} else {
				m.Status = fmt.Sprintf("Copied: %s", entry.Key)
			}
		}
	case "backspace":
		if len(m.Filter) > 0 {
			m.Filter = m.Filter[:len(m.Filter)-1]
			m.cursor = 0
		}
	default:
		// Typing adds to filter
		if len(msg.String()) == 1 {
			m.Filter += msg.String()
			m.cursor = 0
		}
	}
	return m, nil
}

func (m *CatalogScreenModel) updateExpanded(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		m.expanded = false
	case "up", "k":
		if m.attrCursor > 0 {
			m.attrCursor--
		}
	case "down", "j":
		m.attrCursor++
	case "enter":
		// Open probe dialog
		m.probeDialog = true
		m.focusIndex = 0
	case "y":
		filtered := m.filteredEntries()
		if m.expandedIdx < len(filtered) {
			entry := filtered[m.expandedIdx]
			path := fmt.Sprintf("%s / %s / %s", entry.Class, entry.Instance, entry.Attribute)
			if err := copyToClipboard(path); err != nil {
				m.Status = fmt.Sprintf("Copy failed: %v", err)
			} else {
				m.Status = fmt.Sprintf("Copied path: %s", path)
			}
		}
	}
	return m, nil
}

func (m *CatalogScreenModel) updateProbeDialog(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.probeDialog = false
	case "tab":
		m.focusIndex = (m.focusIndex + 1) % 2
	case "enter":
		if m.ProbeIP != "" {
			return m.runProbe()
		}
	case "y":
		cmd := m.buildProbeCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "backspace":
		switch m.focusIndex {
		case 0:
			if len(m.ProbeIP) > 0 {
				m.ProbeIP = m.ProbeIP[:len(m.ProbeIP)-1]
			}
		case 1:
			if len(m.ProbePort) > 0 {
				m.ProbePort = m.ProbePort[:len(m.ProbePort)-1]
			}
		}
	default:
		if len(msg.String()) == 1 {
			switch m.focusIndex {
			case 0:
				if strings.ContainsAny(msg.String(), "0123456789.") {
					m.ProbeIP += msg.String()
				}
			case 1:
				if strings.ContainsAny(msg.String(), "0123456789") {
					m.ProbePort += msg.String()
				}
			}
		}
	}
	return m, nil
}

func (m *CatalogScreenModel) filteredEntries() []CatalogEntry {
	if m.Filter == "" {
		return m.state.Catalog
	}
	return FilterCatalogEntries(m.state.Catalog, m.Filter)
}

func (m *CatalogScreenModel) runProbe() (*CatalogScreenModel, tea.Cmd) {
	if m.ProbeIP == "" {
		m.Status = "Target IP is required"
		return m, nil
	}

	m.ProbeRunning = true
	m.ProbeResult = ""
	m.Status = "Running probe..."

	// Build the command
	args := m.buildProbeCommandArgs()
	command := CommandSpec{Args: args}

	// Create run directory
	filtered := m.filteredEntries()
	runName := "probe"
	if m.expandedIdx < len(filtered) {
		runName = fmt.Sprintf("probe_%s", filtered[m.expandedIdx].Key)
	}
	runDir, err := CreateRunDir(m.state.WorkspaceRoot, runName)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to create run directory: %v", err)
		m.ProbeRunning = false
		return m, nil
	}

	// Execute the probe
	startTime := time.Now()
	ctx := context.Background()
	return m, func() tea.Msg {
		stdout, exitCode, runErr := ExecuteCommand(ctx, command)

		// Write artifacts
		resolved := map[string]interface{}{
			"target_ip": m.ProbeIP,
			"port":      m.ProbePort,
		}
		if m.expandedIdx < len(filtered) {
			entry := filtered[m.expandedIdx]
			resolved["class"] = entry.Class
			resolved["instance"] = entry.Instance
			resolved["attribute"] = entry.Attribute
		}
		status := "success"
		if runErr != nil {
			status = "failed"
		}
		summary := RunSummary{
			Status:     status,
			Command:    args,
			StartedAt:  startTime.UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
			ExitCode:   exitCode,
		}
		_ = WriteRunArtifacts(runDir, resolved, args, stdout, summary)

		return probeResultMsg{
			RunDir:   runDir,
			ExitCode: exitCode,
			Stdout:   stdout,
			Err:      runErr,
		}
	}
}

// probeResultMsg is sent when a probe completes.
type probeResultMsg struct {
	RunDir   string
	ExitCode int
	Stdout   string
	Err      error
}

func (m *CatalogScreenModel) buildProbeCommandArgs() []string {
	filtered := m.filteredEntries()
	if m.expandedIdx >= len(filtered) {
		return nil
	}
	entry := filtered[m.expandedIdx]

	args := []string{"cipdip", "single"}
	if m.ProbeIP != "" {
		args = append(args, "--ip", m.ProbeIP)
	}
	if m.ProbePort != "" && m.ProbePort != "44818" {
		args = append(args, "--port", m.ProbePort)
	}
	if entry.Class != "" {
		args = append(args, "--class", entry.Class)
	}
	if entry.Instance != "" {
		args = append(args, "--instance", entry.Instance)
	}
	if entry.Attribute != "" {
		args = append(args, "--attribute", entry.Attribute)
	}
	if entry.Service != "" {
		args = append(args, "--service", entry.Service)
	}
	return args
}

func (m *CatalogScreenModel) buildProbeCommand() string {
	args := m.buildProbeCommandArgs()
	if len(args) == 0 {
		return ""
	}
	// Replace empty IP with placeholder for display
	for i, arg := range args {
		if arg == "--ip" && i+1 < len(args) && args[i+1] == "" {
			args[i+1] = "???"
		}
	}
	if m.ProbeIP == "" {
		// Add placeholder if IP not in args
		return "cipdip single --ip ??? ..."
	}
	return strings.Join(args, " ")
}

// View renders the catalog screen.
func (m *CatalogScreenModel) View() string {
	if m.probeDialog {
		return m.viewProbeDialog()
	}
	if m.expanded {
		return m.viewExpanded()
	}
	return m.viewList()
}

func (m *CatalogScreenModel) viewList() string {
	var b strings.Builder
	filtered := m.filteredEntries()

	// Header
	b.WriteString(headerStyle.Render("CIP CATALOG"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Filter
	b.WriteString("Filter: ")
	if m.Filter == "" {
		b.WriteString(dimStyle.Render("__________"))
	} else {
		b.WriteString(m.Filter + "█")
	}
	b.WriteString("\n\n")

	// Classes list
	b.WriteString("Classes:\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")

	if len(filtered) == 0 {
		b.WriteString(dimStyle.Render("  (no matching entries)"))
		b.WriteString("\n")
	} else {
		// Group by class
		displayEntries := filtered
		if len(displayEntries) > 15 {
			displayEntries = displayEntries[:15]
		}

		for i, entry := range displayEntries {
			prefix := "  "
			if i == m.cursor {
				prefix = "> "
			}
			name := entry.Name
			if name == "" {
				name = entry.Key
			}
			// Show class/instance/attribute path for unique identification
			path := fmt.Sprintf("%s/%s/%s", entry.Class, entry.Instance, entry.Attribute)
			line := fmt.Sprintf("%s%-28s %s", prefix, name, path)
			if i == m.cursor {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}

		if len(filtered) > 15 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ... and %d more", len(filtered)-15)))
			b.WriteString("\n")
		}
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *CatalogScreenModel) viewExpanded() string {
	var b strings.Builder
	filtered := m.filteredEntries()

	if m.expandedIdx >= len(filtered) {
		return m.viewList()
	}
	entry := filtered[m.expandedIdx]

	// Header with class name
	b.WriteString(headerStyle.Render(fmt.Sprintf("CIP CATALOG > %s (%s)", entry.Name, entry.Class)))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Entry details
	b.WriteString("Details:\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Key:       %s\n", entry.Key))
	b.WriteString(fmt.Sprintf("  Service:   %s\n", entry.Service))
	b.WriteString(fmt.Sprintf("  Class:     %s\n", entry.Class))
	b.WriteString(fmt.Sprintf("  Instance:  %s\n", entry.Instance))
	b.WriteString(fmt.Sprintf("  Attribute: %s\n", entry.Attribute))
	if entry.PayloadHex != "" {
		b.WriteString(fmt.Sprintf("  Payload:   %s\n", entry.PayloadHex))
	}
	if entry.Notes != "" {
		b.WriteString(fmt.Sprintf("\n  Notes: %s\n", entry.Notes))
	}

	// Services section (if we had more data)
	b.WriteString("\n")
	b.WriteString("Services:\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n", entry.Service, entry.Name))

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *CatalogScreenModel) viewProbeDialog() string {
	var b strings.Builder
	filtered := m.filteredEntries()

	entryName := "Unknown"
	entryPath := "???"
	if m.expandedIdx < len(filtered) {
		entry := filtered[m.expandedIdx]
		entryName = entry.Name
		entryPath = fmt.Sprintf("%s / %s / %s", entry.Class, entry.Instance, entry.Attribute)
	}

	// Header
	b.WriteString(headerStyle.Render(fmt.Sprintf("PROBE: %s", entryName)))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Path info
	b.WriteString(fmt.Sprintf("Path: %s\n\n", entryPath))

	// Target IP
	ipValue := m.ProbeIP
	if ipValue == "" {
		ipValue = "_____________"
	}
	if m.focusIndex == 0 {
		b.WriteString(selectedStyle.Render("Target IP: " + ipValue + "█"))
	} else {
		b.WriteString("Target IP: " + ipValue)
	}
	b.WriteString("    ")

	// Port
	portValue := m.ProbePort
	if portValue == "" {
		portValue = "44818"
	}
	if m.focusIndex == 1 {
		b.WriteString(selectedStyle.Render("Port: " + portValue + "█"))
	} else {
		b.WriteString("Port: " + portValue)
	}
	b.WriteString("\n")

	// Command preview
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")
	b.WriteString("Command:\n")
	b.WriteString(dimStyle.Render(m.buildProbeCommand()))
	b.WriteString("\n")

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

// Footer returns the footer text for the catalog screen.
func (m *CatalogScreenModel) Footer() string {
	if m.probeDialog {
		return "Tab: next    Enter: run    y: copy command    Esc: cancel    m: menu"
	}
	if m.expanded {
		return "Enter: probe this attribute    y: copy path    Esc: back    m: menu"
	}
	return "↑↓: navigate    Enter: expand    /: filter    y: copy key    m: menu"
}
