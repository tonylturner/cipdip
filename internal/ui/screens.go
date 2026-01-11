package ui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Screen represents the current active screen in the TUI.
type Screen int

const (
	ScreenMain Screen = iota
	ScreenClient
	ScreenServer
	ScreenPCAP
	ScreenCatalog
	ScreenRuns
)

// AppState holds shared state across all screens.
type AppState struct {
	// Workspace
	WorkspaceRoot string
	WorkspaceName string

	// Cached data
	Profiles       []ProfileInfo
	Runs           []string
	Catalog        []CatalogEntry
	CatalogSources []string

	// Active operations
	ServerRunning     bool
	ServerCtx         context.Context
	ServerCancel      context.CancelFunc
	ServerStatsChan   <-chan StatsUpdate
	ServerResultChan  <-chan CommandResult
	ClientRunning     bool
	ClientCtx         context.Context
	ClientCancel      context.CancelFunc
	ClientStatsChan   <-chan StatsUpdate
	ClientResultChan  <-chan CommandResult

	// Recent runs for main menu
	RecentRuns []RecentRun
}

// RecentRun represents a recent operation for display on main menu.
type RecentRun struct {
	Time      time.Time
	Type      string // "client", "server", "pcap"
	Details   string // scenario name, file, etc.
	Target    string // IP or file
	Status    string // "running", "ok", "error"
	Count     int    // request count or packet count
	ErrorCount int
}

// Model is the main TUI model using bubbletea.
type Model struct {
	state        *AppState
	screen       Screen
	prevScreen   Screen
	showHelp     bool
	error        string
	errorFatal   bool
	width        int
	height       int

	// Screen-specific models
	mainModel    *MainScreenModel
	clientModel  *ClientScreenModel
	serverModel  *ServerScreenModel
	pcapModel    *PCAPScreenModel
	catalogModel *CatalogScreenModel
	runsModel    *RunsScreenModel
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Bold(true)

	headerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("12")).
			Bold(true)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")).
			Bold(true)

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("9")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11"))

	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(1, 2)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
)

// NewModel creates a new TUI model.
func NewModel(state *AppState) Model {
	m := Model{
		state:  state,
		screen: ScreenMain,
	}
	m.mainModel = NewMainScreenModel(state)
	m.clientModel = NewClientScreenModel(state)
	m.serverModel = NewServerScreenModel(state)
	m.pcapModel = NewPCAPScreenModel(state)
	m.catalogModel = NewCatalogScreenModel(state)
	m.runsModel = NewRunsScreenModel(state)
	return m
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return tickCmd()
}

// tickMsg is sent periodically to update live stats.
type tickMsg time.Time

// tickCmd returns a command that fires a tick after 1 second.
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		// Update live stats for running operations
		return m.handleTick(time.Time(msg))

	case tea.KeyMsg:
		// Handle help overlay
		if m.showHelp {
			if msg.String() == "?" || msg.String() == "esc" {
				m.showHelp = false
				return m, nil
			}
			return m, nil
		}

		// Handle fatal error screen
		if m.errorFatal {
			switch msg.String() {
			case "1", "2", "3":
				m.errorFatal = false
				m.error = ""
				m.screen = ScreenMain
				return m, nil
			case "q":
				return m, tea.Quit
			}
			return m, nil
		}

		// Global keys
		switch msg.String() {
		case "q", "ctrl+c":
			// Confirm if operations running
			if m.state.ServerRunning || m.state.ClientRunning {
				// For now, just quit. Could add confirmation.
			}
			return m, tea.Quit

		case "m":
			m.screen = ScreenMain
			m.error = ""
			return m, nil

		case "?":
			m.showHelp = true
			return m, nil

		case "esc":
			// Clear error if present
			if m.error != "" {
				m.error = ""
				return m, nil
			}
			// Otherwise pass to screen for back navigation
		}

		// Screen-specific handling
		return m.updateCurrentScreen(msg)

	case runResultMsg:
		return m.handleRunResult(msg)

	case serverStatusMsg:
		return m.handleServerStatus(msg)

	case serverTickMsg:
		return m.handleServerTick(msg)

	case clientTickMsg:
		return m.handleClientTick(msg)

	case pcapResultMsg:
		return m.handlePCAPResult(msg)

	case probeResultMsg:
		return m.handleProbeResult(msg)

	case rerunResultMsg:
		return m.handleRerunResult(msg)

	case errorMsg:
		m.error = string(msg)
		return m, nil

	case clearErrorMsg:
		m.error = ""
		return m, nil
	}

	return m, nil
}

func (m Model) updateCurrentScreen(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch m.screen {
	case ScreenMain:
		newScreen, cmd := m.mainModel.Update(msg)
		m.mainModel = newScreen
		if m.mainModel.Navigate != ScreenMain {
			m.screen = m.mainModel.Navigate
			m.mainModel.Navigate = ScreenMain
		}
		return m, cmd

	case ScreenClient:
		newScreen, cmd := m.clientModel.Update(msg)
		m.clientModel = newScreen
		return m, cmd

	case ScreenServer:
		newScreen, cmd := m.serverModel.Update(msg)
		m.serverModel = newScreen
		return m, cmd

	case ScreenPCAP:
		newScreen, cmd := m.pcapModel.Update(msg)
		m.pcapModel = newScreen
		return m, cmd

	case ScreenCatalog:
		newScreen, cmd := m.catalogModel.Update(msg)
		m.catalogModel = newScreen
		return m, cmd

	case ScreenRuns:
		newScreen, cmd := m.runsModel.Update(msg)
		m.runsModel = newScreen
		return m, cmd
	}

	return m, cmd
}

// View implements tea.Model.
func (m Model) View() string {
	if m.errorFatal {
		return m.renderFatalError()
	}

	var content string
	var footer string

	switch m.screen {
	case ScreenMain:
		content = m.mainModel.View()
		footer = "c/s/p/k/r: select    q: quit    ?: help"
	case ScreenClient:
		content = m.clientModel.View()
		footer = m.clientModel.Footer()
	case ScreenServer:
		content = m.serverModel.View()
		footer = m.serverModel.Footer()
	case ScreenPCAP:
		content = m.pcapModel.View()
		footer = m.pcapModel.Footer()
	case ScreenCatalog:
		content = m.catalogModel.View()
		footer = m.catalogModel.Footer()
	case ScreenRuns:
		content = m.runsModel.View()
		footer = m.runsModel.Footer()
	}

	// Add error bar if present
	if m.error != "" {
		content += "\n\n" + errorStyle.Render("ERROR: "+m.error)
	}

	// Add help overlay if active
	if m.showHelp {
		content = m.renderHelpOverlay(content)
	}

	// Add footer
	content += "\n\n" + footerStyle.Render(footer)

	return content
}

func (m Model) renderFatalError() string {
	lines := []string{
		headerStyle.Render("ERROR"),
		"",
		m.error,
		"",
		"Options:",
		"",
		"  [1] Try again",
		"  [2] Return to menu",
		"  [3] Quit",
	}
	content := strings.Join(lines, "\n")
	return borderStyle.Render(content) + "\n\n" + footerStyle.Render("1/2/3: select    q: quit")
}

func (m Model) renderHelpOverlay(baseContent string) string {
	helpContent := m.getHelpForScreen()

	// Simple side-by-side layout
	lines := strings.Split(baseContent, "\n")
	helpLines := strings.Split(helpContent, "\n")

	maxLines := len(lines)
	if len(helpLines) > maxLines {
		maxLines = len(helpLines)
	}

	var result strings.Builder
	for i := 0; i < maxLines; i++ {
		left := ""
		if i < len(lines) {
			left = lines[i]
		}
		right := ""
		if i < len(helpLines) {
			right = helpLines[i]
		}
		// Pad left side and add separator
		if len(left) < 40 {
			left += strings.Repeat(" ", 40-len(left))
		}
		result.WriteString(left[:min(40, len(left))] + " | " + right + "\n")
	}
	return result.String()
}

func (m Model) getHelpForScreen() string {
	switch m.screen {
	case ScreenMain:
		return `HELP

This is the main menu.
Select a screen to navigate.

Keys:
c    Client screen
s    Server screen
p    PCAP tools
k    CIP Catalog
r    Run history

Press ? or Esc to close`

	case ScreenClient:
		return `HELP

Configure and run CIP
client scenarios.

Keys:
Tab    next field
Enter  start run
e      edit config
y      copy command
x      stop run
m      main menu

Press ? or Esc to close`

	case ScreenServer:
		return `HELP

Start and monitor the
CIP server emulator.

Keys:
Tab    next field
Enter  start server
e      edit config
y      copy command
x      stop server
m      main menu

Press ? or Esc to close`

	case ScreenPCAP:
		return `HELP

PCAP analysis and replay.

Keys:
b      browse files
1-6    select action
Enter  run action
y      copy command
m      main menu

Press ? or Esc to close`

	case ScreenCatalog:
		return `HELP

Browse CIP classes and
services.

Keys:
/      filter
Enter  expand/probe
y      copy path
m      main menu

Press ? or Esc to close`

	case ScreenRuns:
		return `HELP

View past run results.

Keys:
Tab    filter type
Enter  view details
o      open artifact
r      re-run
y      copy command
d      delete
m      main menu

Press ? or Esc to close`
	}
	return "Press ? or Esc to close"
}

func (m Model) handleRunResult(msg runResultMsg) (tea.Model, tea.Cmd) {
	m.state.ClientRunning = false
	if m.state.ClientCancel != nil {
		m.state.ClientCancel()
		m.state.ClientCancel = nil
	}

	// Update client model with result
	if m.clientModel != nil {
		m.clientModel.Running = false
		m.clientModel.Completed = true
		m.clientModel.Output = msg.Stdout
		m.clientModel.RunDir = msg.RunDir
		if msg.Err != nil {
			// Extract a meaningful error from the output
			errMsg := extractErrorFromOutput(msg.Stdout)
			if errMsg == "" {
				errMsg = msg.Err.Error()
			}
			m.clientModel.Status = fmt.Sprintf("FAILED: %s", errMsg)
		} else {
			m.clientModel.Status = fmt.Sprintf("Completed successfully. Artifacts: %s", msg.RunDir)
		}
	}

	// Refresh runs list
	runs, _ := ListRuns(m.state.WorkspaceRoot, 10)
	m.state.Runs = runs

	return m, nil
}

func (m Model) handleServerStatus(msg serverStatusMsg) (tea.Model, tea.Cmd) {
	if msg.Stopped {
		m.state.ServerRunning = false
		if m.state.ServerCancel != nil {
			m.state.ServerCancel()
			m.state.ServerCancel = nil
		}
		if m.serverModel != nil {
			m.serverModel.Running = false
			m.serverModel.Completed = true
			m.serverModel.Output = msg.Stdout
			m.serverModel.RunDir = msg.RunDir
			if msg.Err != nil {
				// Extract a meaningful error from the output
				errMsg := extractErrorFromOutput(msg.Stdout)
				if errMsg == "" {
					errMsg = msg.Err.Error()
				}
				m.serverModel.Status = fmt.Sprintf("FAILED: %s", errMsg)
			} else {
				m.serverModel.Status = "Server stopped normally"
			}
		}
	}
	return m, nil
}

func (m Model) handleServerTick(msg serverTickMsg) (tea.Model, tea.Cmd) {
	if m.serverModel == nil {
		return m, nil
	}
	newModel, cmd := m.serverModel.HandleServerTick(msg)
	m.serverModel = newModel
	return m, cmd
}

func (m Model) handleClientTick(msg clientTickMsg) (tea.Model, tea.Cmd) {
	if m.clientModel == nil {
		return m, nil
	}
	newModel, cmd := m.clientModel.HandleClientTick(msg)
	m.clientModel = newModel
	return m, cmd
}

func (m Model) handlePCAPResult(msg pcapResultMsg) (tea.Model, tea.Cmd) {
	// Update PCAP model with result
	if m.pcapModel != nil {
		m.pcapModel.Running = false
		m.pcapModel.Completed = true
		m.pcapModel.Output = msg.Stdout
		m.pcapModel.RunDir = msg.RunDir
		m.pcapModel.SubView = 3 // Switch to completed view

		// If a report was generated, read it
		if m.pcapModel.ReportPath != "" {
			if content, err := os.ReadFile(m.pcapModel.ReportPath); err == nil {
				m.pcapModel.ReportContent = string(content)
			}
		}

		if msg.Err != nil {
			errMsg := extractErrorFromOutput(msg.Stdout)
			if errMsg == "" {
				errMsg = msg.Err.Error()
			}
			m.pcapModel.Status = fmt.Sprintf("FAILED: %s", errMsg)
		} else {
			if m.pcapModel.ReportPath != "" {
				m.pcapModel.Status = fmt.Sprintf("Report saved to: %s", m.pcapModel.ReportPath)
			} else {
				m.pcapModel.Status = "Completed successfully"
			}
		}
	}

	// Refresh runs list
	runs, _ := ListRuns(m.state.WorkspaceRoot, 10)
	m.state.Runs = runs

	return m, nil
}

func (m Model) handleProbeResult(msg probeResultMsg) (tea.Model, tea.Cmd) {
	// Update catalog model with result
	if m.catalogModel != nil {
		m.catalogModel.ProbeRunning = false
		if msg.Err != nil {
			m.catalogModel.Status = fmt.Sprintf("Probe failed: %v", msg.Err)
			m.catalogModel.ProbeResult = msg.Stdout
		} else {
			m.catalogModel.Status = "Probe completed"
			m.catalogModel.ProbeResult = msg.Stdout
		}
	}

	// Refresh runs list
	runs, _ := ListRuns(m.state.WorkspaceRoot, 10)
	m.state.Runs = runs

	return m, nil
}

func (m Model) handleRerunResult(msg rerunResultMsg) (tea.Model, tea.Cmd) {
	// Update runs model with result
	if m.runsModel != nil {
		if msg.Err != nil {
			m.runsModel.Status = fmt.Sprintf("Re-run failed: %v", msg.Err)
		} else {
			m.runsModel.Status = fmt.Sprintf("Re-run completed. Artifacts: %s", msg.RunDir)
		}
	}

	// Refresh runs list
	runs, _ := ListRuns(m.state.WorkspaceRoot, 20)
	m.state.Runs = runs

	return m, nil
}

func (m Model) handleTick(t time.Time) (tea.Model, tea.Cmd) {
	// Update client elapsed time if running
	if m.clientModel != nil && m.clientModel.Running && m.clientModel.StartTime != nil {
		elapsed := t.Sub(*m.clientModel.StartTime)
		m.clientModel.Elapsed = formatElapsed(elapsed)
	}

	// Update server uptime if running
	if m.serverModel != nil && m.serverModel.Running && m.serverModel.StartTime != nil {
		elapsed := t.Sub(*m.serverModel.StartTime)
		m.serverModel.Uptime = elapsed
	}

	// Continue ticking if any operation is running
	if m.state.ClientRunning || m.state.ServerRunning {
		return m, tickCmd()
	}

	// Keep ticking at a slower rate when idle (for potential future updates)
	return m, tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func formatElapsed(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// extractErrorFromOutput tries to find a meaningful error message from command output.
func extractErrorFromOutput(output string) string {
	if output == "" {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// First pass: look for specific error patterns anywhere in output
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		// Check for connection/network errors
		if strings.Contains(lower, "connection refused") {
			return "Connection refused - is the target running?"
		}
		if strings.Contains(lower, "no route to host") {
			return "No route to host - check the IP address"
		}
		if strings.Contains(lower, "network is unreachable") {
			return "Network unreachable - check network connection"
		}
		if strings.Contains(lower, "i/o timeout") || strings.Contains(lower, "deadline exceeded") {
			return "Connection timed out - target not responding"
		}
		if strings.Contains(lower, "dial tcp") && strings.Contains(lower, "connect:") {
			// Extract the actual error from "dial tcp x.x.x.x:port: connect: <error>"
			if idx := strings.LastIndex(lower, "connect:"); idx != -1 {
				return strings.TrimSpace(line[idx+8:])
			}
		}
	}

	// Second pass: look for explicit error messages
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "error:") {
			return strings.TrimSpace(line[6:])
		}
		if strings.HasPrefix(lower, "fatal:") {
			return strings.TrimSpace(line[6:])
		}
	}

	// Check for "0 operations" which indicates nothing happened
	for _, line := range lines {
		if strings.Contains(line, "0 operations") {
			return "No operations completed - could not connect to target"
		}
	}

	// Last resort: return last non-empty line that isn't a "Completed" summary
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" && !strings.HasPrefix(strings.ToLower(line), "completed") {
			return line
		}
	}

	return "Unknown error"
}

// Message types
type runResultMsg struct {
	RunDir   string
	ExitCode int
	Stdout   string
	Err      error
}

type serverStatusMsg struct {
	Stopped  bool
	Stdout   string
	RunDir   string
	ExitCode int
	Err      error
}

type errorMsg string

type clearErrorMsg struct{}

// Helper to copy to clipboard with error handling
func copyToClipboard(text string) error {
	return clipboard.WriteAll(text)
}

// formatCommandPreview formats a command for display/copying.
func formatCommandPreview(args []string) string {
	if len(args) == 0 {
		return ""
	}
	// Simple formatting - could be improved for line wrapping
	return strings.Join(args, " ")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RunTUIV2 starts the new screen-based TUI.
func RunTUIV2(workspaceRoot string) error {
	ws, err := LoadWorkspace(workspaceRoot)
	if err != nil {
		return err
	}
	if err := EnsureWorkspaceLayout(ws.Root); err != nil {
		return err
	}

	profiles, _ := ListProfiles(ws.Root)
	runs, _ := ListRuns(ws.Root, 20)
	catalog, _ := ListCatalogEntries(ws.Root)
	catalogSources, _ := ListCatalogSources(ws.Root)

	state := &AppState{
		WorkspaceRoot:  ws.Root,
		WorkspaceName:  ws.Config.Name,
		Profiles:       profiles,
		Runs:           runs,
		Catalog:        catalog,
		CatalogSources: catalogSources,
	}

	model := NewModel(state)
	program := tea.NewProgram(model, tea.WithAltScreen())
	_, err = program.Run()
	return err
}
