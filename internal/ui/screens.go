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
	ScreenProfile
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
	profileModel *ProfileScreenModel
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
	m.profileModel = NewProfileScreenModel(state)
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
			if msg.String() == "?" || msg.String() == "h" || msg.String() == "esc" {
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

		case "?", "h":
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

	case profileTickMsg:
		return m.handleProfileTick(msg)

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
		// Check if client model wants to navigate to profile screen
		if m.clientModel.NavigateToProfile {
			m.clientModel.NavigateToProfile = false
			// Copy IP and Port to profile screen
			m.profileModel.TargetIP = m.clientModel.TargetIP
			m.profileModel.Port = m.clientModel.Port
			if m.profileModel.PcapEnabled {
				m.profileModel.updateAutoDetectedInterface()
			}
			m.screen = ScreenProfile
		}
		return m, cmd

	case ScreenProfile:
		newScreen, cmd := m.profileModel.Update(msg)
		m.profileModel = newScreen
		// Check if profile model wants to navigate back to client screen
		if m.profileModel.NavigateToClient {
			m.profileModel.NavigateToClient = false
			// Copy IP and Port back to client screen
			m.clientModel.TargetIP = m.profileModel.TargetIP
			m.clientModel.Port = m.profileModel.Port
			if m.clientModel.PcapEnabled {
				m.clientModel.updateAutoDetectedInterface()
			}
			m.screen = ScreenClient
		}
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
		footer = "c/s/p/k/r: select    q: quit    ?/h: help"
	case ScreenClient:
		content = m.clientModel.View()
		footer = m.clientModel.Footer()
	case ScreenProfile:
		content = m.profileModel.View()
		footer = m.profileModel.Footer()
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
	helpTitle, helpBody := m.getHelpForScreen()

	// Get main content lines
	contentLines := strings.Split(baseContent, "\n")

	// Find the actual content width
	mainWidth := 0
	for _, line := range contentLines {
		w := lipgloss.Width(line)
		if w > mainWidth {
			mainWidth = w
		}
	}

	// Help styling
	helpTitleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")).
		Bold(true)

	dimHelpStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8"))

	// Build help content lines manually for precise control
	helpInnerWidth := 34
	var helpContentLines []string
	helpContentLines = append(helpContentLines, helpTitleStyle.Render(helpTitle))
	helpContentLines = append(helpContentLines, strings.Repeat("─", helpInnerWidth))

	// Word wrap the body text
	for _, line := range strings.Split(helpBody, "\n") {
		if line == "" {
			helpContentLines = append(helpContentLines, "")
			continue
		}
		// Simple word wrap
		wrapped := wrapText(line, helpInnerWidth)
		helpContentLines = append(helpContentLines, wrapped...)
	}

	helpContentLines = append(helpContentLines, "")
	helpContentLines = append(helpContentLines, dimHelpStyle.Render("h/Esc to close"))

	// Calculate heights - main content height (count lines in the bordered box)
	mainHeight := len(contentLines)
	helpContentHeight := len(helpContentLines)

	// We need to match heights - help content + border (top/bottom) + padding (top/bottom)
	// Border adds 2 lines, padding adds 2 lines = 4 extra lines for the box
	helpBoxPadding := 4
	targetHelpContent := mainHeight - helpBoxPadding
	if targetHelpContent < helpContentHeight {
		targetHelpContent = helpContentHeight
	}

	// Pad help content to match
	for len(helpContentLines) < targetHelpContent {
		helpContentLines = append(helpContentLines, "")
	}

	// Build help box manually to match main box height
	helpBoxWidth := helpInnerWidth + 4 // 2 for border, 2 for padding
	var helpLines []string

	// Top border
	helpLines = append(helpLines, "╭"+strings.Repeat("─", helpBoxWidth-2)+"╮")

	// Padding top
	helpLines = append(helpLines, "│"+strings.Repeat(" ", helpBoxWidth-2)+"│")

	// Content lines
	for _, line := range helpContentLines {
		lineWidth := lipgloss.Width(line)
		padding := helpBoxWidth - 4 - lineWidth // 4 = 2 border + 2 internal padding
		if padding < 0 {
			padding = 0
		}
		helpLines = append(helpLines, "│ "+line+strings.Repeat(" ", padding)+" │")
	}

	// Padding bottom
	helpLines = append(helpLines, "│"+strings.Repeat(" ", helpBoxWidth-2)+"│")

	// Bottom border
	helpLines = append(helpLines, "╰"+strings.Repeat("─", helpBoxWidth-2)+"╯")

	// Now match the number of lines
	for len(helpLines) < mainHeight {
		helpLines = append(helpLines, strings.Repeat(" ", helpBoxWidth))
	}
	for len(contentLines) < len(helpLines) {
		contentLines = append(contentLines, strings.Repeat(" ", mainWidth))
	}

	// Build side-by-side output
	var result strings.Builder
	for i := 0; i < len(contentLines); i++ {
		mainLine := contentLines[i]
		lineWidth := lipgloss.Width(mainLine)
		if lineWidth < mainWidth {
			mainLine += strings.Repeat(" ", mainWidth-lineWidth)
		}

		helpLine := ""
		if i < len(helpLines) {
			helpLine = helpLines[i]
		}

		result.WriteString(mainLine)
		result.WriteString(helpLine)
		result.WriteString("\n")
	}

	return result.String()
}

// wrapText wraps text to the specified width, preserving leading spaces
func wrapText(text string, width int) []string {
	if lipgloss.Width(text) <= width {
		return []string{text}
	}

	// Count leading spaces to preserve indentation
	leadingSpaces := 0
	for _, c := range text {
		if c == ' ' {
			leadingSpaces++
		} else {
			break
		}
	}
	indent := strings.Repeat(" ", leadingSpaces)
	text = strings.TrimLeft(text, " ")

	var lines []string
	words := strings.Fields(text)
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

	return lines
}

func (m Model) getHelpForScreen() (string, string) {
	switch m.screen {
	case ScreenMain:
		return "CIPDIP", `Protocol-aware CIP/EtherNet-IP
test harness for DPI validation.

SCREENS
 c Client   Test scenarios
 s Server   Device emulator
 p PCAP     Capture analysis
 k Catalog  CIP objects
 r Runs     Past results

QUICK START
 1. Start Server to emulate PLC
 2. Run Client scenarios
 3. Check Runs for results

All runs save artifacts:
configs, logs, and JSON.`

	case ScreenClient:
		return "Client", `Run CIP scenarios against a
target device or emulator.

SCENARIOS
 baseline  Basic CIP ops
 mixed     Various services
 stress    High-rate load
 io        I/O connections
 edge      Edge cases
 vendor    Vendor behaviors

WORKFLOW
 1. Enter target IP
 2. Select scenario
 3. Enter to start
 4. View live stats

TIPS
 'a' for advanced options
 'p' for profile mode`

	case ScreenProfile:
		return "Profile", `Run YAML-defined traffic.

PROFILES
 Realistic patterns for:
 - PLC polling intervals
 - HMI update rates
 - SCADA collection

LOCATION
 profiles/*.yaml

CREATING
 Copy existing, modify:
 - target_rate: req/sec
 - services: CIP services
 - objects: class/instance

'r' refreshes profile list`

	case ScreenServer:
		return "Server", `Emulate a CIP device.

PERSONALITIES
 adapter     Basic I/O
 logix_like  Rockwell style

FEATURES
 - CIP service handling
 - Forward Open/Close
 - Identity queries
 - Tags and assemblies

USE CASES
 - Test without hardware
 - Validate DPI engines
 - Local development

Logs all requests with
full connection state.`

	case ScreenPCAP:
		return "PCAP", `Analyze and replay captures.

ACTIONS
 1 Summary   Quick stats
 2 Timeline  Time analysis
 3 Coverage  Protocol map
 4 Compare   Diff captures
 5 Replay    To target
 6 Rewrite   Modify pcap
 7 I/O       Extract I/O

FORMATS
 .pcap, .pcapng

Reports saved to runs/
with full CIP breakdown.

'b' to browse files`

	case ScreenCatalog:
		return "Catalog", `Browse CIP definitions.

STRUCTURE
 Class → Instance → Attr

FILTERS
 1  Logix objects
 2  Core CIP only
 0  Show all
 /  Text search

PROBING
 Enter on attribute to
 probe live device.

SOURCES
 - ODVA CIP spec
 - Rockwell extensions
 - Discovered objects

'y' copies EPATH`

	case ScreenRuns:
		return "Runs", `View past test runs.

ARTIFACTS
 command.txt   Command
 stdout.log    Output
 resolved.yaml Config
 summary.json  Results

FILTERS
 Tab: all/client/server/pcap

ACTIONS
 Enter  View details
 o      Open in $EDITOR
 r      Re-run command
 y      Copy command
 d      Delete run

Sorted newest first.`
	}
	return "Help", "h/Esc to close"
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

func (m Model) handleProfileTick(msg profileTickMsg) (tea.Model, tea.Cmd) {
	if m.profileModel == nil {
		return m, nil
	}
	newModel, cmd := m.profileModel.HandleProfileTick(msg)
	m.profileModel = newModel
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
