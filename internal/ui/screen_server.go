package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/netdetect"
	"github.com/tturner/cipdip/internal/profile"
)

// ServerScreenModel handles the server emulator screen.
type ServerScreenModel struct {
	state *AppState

	// Form fields
	ListenIP    string
	Port        string
	Personality int // Index into personalities slice
	ConfigPath  string

	// Profile mode (alternative to config mode)
	ProfileMode  bool // true = use profile, false = use config/personality
	Profiles     []profile.ProfileInfo
	ProfileIndex int

	// Advanced options
	ShowAdvanced     bool
	ModeIndex        int    // Index into serverModes
	CIPProfiles      []bool // energy, safety, motion toggles
	EnableUDPIO      bool
	PcapEnabled           bool
	PcapFile              string
	CaptureInterface      string // Network interface for PCAP (empty = auto-detect)
	AutoDetectedInterface string // The auto-detected interface for display

	// Interface selector
	InterfaceSelector       *InterfaceSelectorModel
	InterfaceSelectorActive bool

	// UI state
	focusIndex int
	Running    bool
	Completed  bool   // True after server stops (success or failure)
	Status     string
	Output     string // Captured stdout from the run
	RunDir     string // Directory where artifacts were saved

	// Stats when running
	StartTime       *time.Time
	Uptime          time.Duration
	ConnectionCount int
	RequestCount    int
	ErrorCount      int
	Connections     []ServerConnection
	RecentRequests  []ServerRequest
}

// ServerConnection represents an active connection.
type ServerConnection struct {
	RemoteAddr string
	SessionID  string
	IdleTime   time.Duration
}

// ServerRequest represents a recent request for display.
type ServerRequest struct {
	Time       time.Time
	RemoteAddr string
	Service    string
	Path       string
}

var serverPersonalities = []struct {
	Name string
	Desc string
}{
	{"adapter", "Assembly-based (like CLICK PLCs)"},
	{"logix_like", "Tag-based (like Allen-Bradley Logix)"},
}

// Server mode presets
var serverModes = []struct {
	Name string
	Desc string
}{
	{"baseline", "Standard compliant responses"},
	{"realistic", "Realistic timing and behavior"},
	{"dpi-torture", "Edge cases to stress DPI engines"},
	{"perf", "High-performance mode for load testing"},
}

// CIP profiles for server (reuse from client)
var serverCIPProfiles = []string{"energy", "safety", "motion"}

const (
	serverFieldIP = iota
	serverFieldPort
	serverFieldPersonality
	serverFieldProfile // Only visible in profile mode
	serverFieldMode
	// Advanced fields
	serverFieldCIPProfiles
	serverFieldUDPIO
	serverFieldPcap
	serverFieldCount
)

// NewServerScreenModel creates a new server screen model.
func NewServerScreenModel(state *AppState) *ServerScreenModel {
	m := &ServerScreenModel{
		state:       state,
		ListenIP:    "", // Empty means 0.0.0.0 (all interfaces)
		Port:        "44818",
		CIPProfiles: make([]bool, len(serverCIPProfiles)),
	}
	m.loadProfiles()
	return m
}

// loadProfiles loads available profiles from the profiles directory.
func (m *ServerScreenModel) loadProfiles() {
	profiles, err := profile.ListProfilesDefault()
	if err != nil || len(profiles) == 0 {
		profiles, _ = profile.ListProfiles("profiles")
	}
	m.Profiles = profiles
}

// updateAutoDetectedInterface detects the interface for the current listen IP.
func (m *ServerScreenModel) updateAutoDetectedInterface() {
	listenIP := m.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	iface, err := netdetect.DetectInterfaceForListen(listenIP)
	if err != nil {
		m.AutoDetectedInterface = "unknown"
	} else {
		// Get the display-friendly name
		m.AutoDetectedInterface = netdetect.GetDisplayNameForInterface(iface)
	}
}

// displayIP returns the listen IP for display, showing default when empty.
func (m *ServerScreenModel) displayIP() string {
	if m.ListenIP == "" {
		return "0.0.0.0"
	}
	return m.ListenIP
}

// generatePcapFilename creates a filename based on current settings
func (m *ServerScreenModel) generatePcapFilename() string {
	var name string
	if m.ProfileMode && m.ProfileIndex < len(m.Profiles) {
		name = strings.ReplaceAll(m.Profiles[m.ProfileIndex].Name, " ", "_")
		name = strings.ToLower(name)
	} else {
		name = serverPersonalities[m.Personality].Name
	}
	mode := serverModes[m.ModeIndex].Name
	timestamp := time.Now().UTC().Format("2006-01-02T150405Z")
	filename := fmt.Sprintf("server_%s_%s_%s.pcap", name, mode, timestamp)
	return filepath.Join(m.state.WorkspaceRoot, "pcaps", filename)
}

// Update handles input for the server screen.
func (m *ServerScreenModel) Update(msg tea.KeyMsg) (*ServerScreenModel, tea.Cmd) {
	// Handle interface selector if active
	if m.InterfaceSelectorActive && m.InterfaceSelector != nil {
		selector, cmd, done := m.InterfaceSelector.Update(msg)
		m.InterfaceSelector = selector
		if done {
			m.InterfaceSelectorActive = false
			if selector.Selected != "" || msg.String() == "enter" {
				m.CaptureInterface = selector.Selected
				if selector.Selected == "" {
					m.Status = "Interface: auto-detect"
				} else {
					m.Status = fmt.Sprintf("Interface: %s", selector.Selected)
				}
			}
		}
		return m, cmd
	}

	if m.Running {
		return m.updateRunning(msg)
	}
	if m.Completed {
		return m.updateCompleted(msg)
	}
	return m.updateEditing(msg)
}

func (m *ServerScreenModel) updateEditing(msg tea.KeyMsg) (*ServerScreenModel, tea.Cmd) {
	// Handle text input fields first - these consume single characters
	isTextInputField := m.focusIndex == serverFieldIP || m.focusIndex == serverFieldPort
	if isTextInputField {
		switch msg.String() {
		case "tab", "down":
			m.focusIndex = m.nextField(1)
			return m, nil
		case "shift+tab", "up":
			m.focusIndex = m.nextField(-1)
			return m, nil
		case "enter":
			return m.startServer()
		case "backspace":
			m.handleBackspace()
			return m, nil
		default:
			if len(msg.String()) == 1 {
				m.handleCharInput(msg.String())
			}
			return m, nil
		}
	}

	switch msg.String() {
	case "tab", "down", "j":
		m.focusIndex = m.nextField(1)
	case "shift+tab", "up", "k":
		m.focusIndex = m.nextField(-1)
	case "p":
		// Toggle profile mode
		m.ProfileMode = !m.ProfileMode
		if m.ProfileMode {
			m.loadProfiles()
			m.focusIndex = serverFieldProfile
			// Set UDP I/O based on selected profile's default
			if m.ProfileIndex < len(m.Profiles) {
				m.EnableUDPIO = m.Profiles[m.ProfileIndex].EnableUDPIO
			}
		} else {
			m.focusIndex = serverFieldPersonality
		}
	case "a":
		// Toggle advanced options
		m.ShowAdvanced = !m.ShowAdvanced
		if !m.ShowAdvanced && m.focusIndex > serverFieldMode {
			m.focusIndex = serverFieldMode
		}
	case "enter":
		return m.startServer()
	case "e":
		// Open config in editor
		configPath := m.ConfigPath
		if configPath == "" {
			configPath = filepath.Join(m.state.WorkspaceRoot, "profiles", "server_config.yaml")
		}
		// Check if file exists, create template if not
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			template := `# CIPDIP Server Configuration
# Generated by TUI

server:
  name: "CIPDIP Server Emulator"
  personality: "adapter"
  tcp_port: 44818
  udp_io_port: 2222

adapter_assemblies:
  - name: "InputAssembly1"
    class: 0x04
    instance: 0x65
    attribute: 0x03
    size_bytes: 16
    update_pattern: "counter"
`
			if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
				m.Status = fmt.Sprintf("Failed to create directory: %v", err)
				return m, nil
			}
			if err := os.WriteFile(configPath, []byte(template), 0644); err != nil {
				m.Status = fmt.Sprintf("Failed to create config: %v", err)
				return m, nil
			}
		}
		m.ConfigPath = configPath
		if err := OpenEditor(configPath); err != nil {
			m.Status = fmt.Sprintf("Editor failed: %v", err)
		} else {
			m.Status = fmt.Sprintf("Edited: %s", filepath.Base(configPath))
		}
	case "y":
		cmd := m.buildCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "backspace":
		m.handleBackspace()
	default:
		if len(msg.String()) == 1 {
			m.handleCharInput(msg.String())
		}
	}

	// Handle field-specific controls
	switch m.focusIndex {
	case serverFieldPersonality:
		switch msg.String() {
		case "1", "2":
			idx := int(msg.String()[0] - '1')
			if idx >= 0 && idx < len(serverPersonalities) {
				m.Personality = idx
			}
		case " ", "right", "l":
			m.Personality = (m.Personality + 1) % len(serverPersonalities)
		case "left", "h":
			m.Personality = (m.Personality - 1 + len(serverPersonalities)) % len(serverPersonalities)
		}
	case serverFieldProfile:
		switch msg.String() {
		case " ", "right", "l":
			if len(m.Profiles) > 0 {
				m.ProfileIndex = (m.ProfileIndex + 1) % len(m.Profiles)
				// Update UDP I/O based on newly selected profile
				m.EnableUDPIO = m.Profiles[m.ProfileIndex].EnableUDPIO
			}
		case "left", "h":
			if len(m.Profiles) > 0 {
				m.ProfileIndex = (m.ProfileIndex - 1 + len(m.Profiles)) % len(m.Profiles)
				// Update UDP I/O based on newly selected profile
				m.EnableUDPIO = m.Profiles[m.ProfileIndex].EnableUDPIO
			}
		}
	case serverFieldMode:
		switch msg.String() {
		case " ", "right", "l":
			m.ModeIndex = (m.ModeIndex + 1) % len(serverModes)
		case "left", "h":
			m.ModeIndex = (m.ModeIndex - 1 + len(serverModes)) % len(serverModes)
		}
	case serverFieldCIPProfiles:
		switch msg.String() {
		case "1":
			m.CIPProfiles[0] = !m.CIPProfiles[0] // energy
		case "2":
			m.CIPProfiles[1] = !m.CIPProfiles[1] // safety
		case "3":
			m.CIPProfiles[2] = !m.CIPProfiles[2] // motion
		case " ":
			// Toggle all
			allOn := m.CIPProfiles[0] && m.CIPProfiles[1] && m.CIPProfiles[2]
			for i := range m.CIPProfiles {
				m.CIPProfiles[i] = !allOn
			}
		}
	case serverFieldUDPIO:
		switch msg.String() {
		case " ":
			m.EnableUDPIO = !m.EnableUDPIO
		}
	case serverFieldPcap:
		switch msg.String() {
		case " ":
			m.PcapEnabled = !m.PcapEnabled
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		case "i":
			// Open interface selector
			if m.PcapEnabled {
				m.InterfaceSelector = NewInterfaceSelectorModel()
				m.InterfaceSelector.CurrentAutoDetected = m.AutoDetectedInterface
				if err := m.InterfaceSelector.LoadInterfaces(); err != nil {
					m.Status = fmt.Sprintf("Failed to load interfaces: %v", err)
				} else {
					m.InterfaceSelectorActive = true
				}
			}
		}
	}

	return m, nil
}

// nextField returns the next valid field index, skipping hidden fields
func (m *ServerScreenModel) nextField(dir int) int {
	// Determine which fields are visible
	visibleFields := []int{serverFieldIP, serverFieldPort}

	// Show either personality (config mode) or profile (profile mode)
	if m.ProfileMode {
		visibleFields = append(visibleFields, serverFieldProfile)
	} else {
		visibleFields = append(visibleFields, serverFieldPersonality)
	}

	visibleFields = append(visibleFields, serverFieldMode, serverFieldPcap)
	if m.ShowAdvanced {
		visibleFields = append(visibleFields, serverFieldCIPProfiles, serverFieldUDPIO)
	}

	// Find current position in visible fields
	currentPos := 0
	for i, f := range visibleFields {
		if f == m.focusIndex {
			currentPos = i
			break
		}
	}

	// Move to next/prev
	newPos := (currentPos + dir + len(visibleFields)) % len(visibleFields)
	return visibleFields[newPos]
}

func (m *ServerScreenModel) updateRunning(msg tea.KeyMsg) (*ServerScreenModel, tea.Cmd) {
	switch msg.String() {
	case "x":
		if m.state.ServerCancel != nil {
			m.state.ServerCancel()
		}
		m.Running = false
		m.state.ServerRunning = false
		m.Status = "Server stopped"
	case "l":
		// Toggle full log view
	case "f":
		// Filter by IP
		m.Status = "IP filter not yet implemented"
	}
	return m, nil
}

func (m *ServerScreenModel) updateCompleted(msg tea.KeyMsg) (*ServerScreenModel, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		// Return to editing mode
		m.Completed = false
		m.Output = ""
		m.Status = ""
	case "r":
		// Re-run server
		m.Completed = false
		return m.startServer()
	case "o":
		// Open artifacts
		if m.RunDir != "" {
			if err := OpenEditor(m.RunDir + "/stdout.log"); err != nil {
				m.Status = fmt.Sprintf("Failed to open: %v", err)
			}
		}
	}
	return m, nil
}

func (m *ServerScreenModel) handleBackspace() {
	switch m.focusIndex {
	case serverFieldIP:
		if len(m.ListenIP) > 0 {
			m.ListenIP = m.ListenIP[:len(m.ListenIP)-1]
			// Update auto-detected interface if PCAP is enabled
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		}
	case serverFieldPort:
		if len(m.Port) > 0 {
			m.Port = m.Port[:len(m.Port)-1]
		}
	}
}

func (m *ServerScreenModel) handleCharInput(ch string) {
	switch m.focusIndex {
	case serverFieldIP:
		if strings.ContainsAny(ch, "0123456789.") {
			m.ListenIP += ch
			// Update auto-detected interface if PCAP is enabled
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		}
	case serverFieldPort:
		if strings.ContainsAny(ch, "0123456789") {
			m.Port += ch
		}
	}
}

func (m *ServerScreenModel) startServer() (*ServerScreenModel, tea.Cmd) {
	m.Running = true
	m.Status = "Starting server..."
	m.ConnectionCount = 0
	m.RequestCount = 0
	m.ErrorCount = 0
	m.Connections = nil
	m.RecentRequests = nil
	now := time.Now()
	m.StartTime = &now
	m.Uptime = 0

	// Set up cancellation context
	ctx, cancel := context.WithCancel(context.Background())
	m.state.ServerCtx = ctx
	m.state.ServerCancel = cancel
	m.state.ServerRunning = true

	// Build the command
	args := m.buildCommandArgs()
	command := CommandSpec{Args: args}

	// Create run directory for server
	runName := fmt.Sprintf("server_%s", serverPersonalities[m.Personality].Name)
	runDir, err := CreateRunDir(m.state.WorkspaceRoot, runName)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to create run directory: %v", err)
		m.Running = false
		m.state.ServerRunning = false
		return m, nil
	}
	m.RunDir = runDir

	// Start the streaming command
	statsChan, resultChan, err := StartStreamingCommand(ctx, command)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to start server: %v", err)
		m.Running = false
		m.state.ServerRunning = false
		return m, nil
	}

	// Store channels for polling
	m.state.ServerStatsChan = statsChan
	m.state.ServerResultChan = resultChan

	// Return a tick command to poll for updates
	return m, tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return serverTickMsg{Time: t}
	})
}

func (m *ServerScreenModel) buildCommandArgs() []string {
	args := []string{"cipdip", "server"}

	// Profile mode uses --profile, config mode uses --personality
	if m.ProfileMode && m.ProfileIndex < len(m.Profiles) {
		args = append(args, "--profile", m.Profiles[m.ProfileIndex].Name)
	} else {
		args = append(args, "--personality", serverPersonalities[m.Personality].Name)
	}

	if m.ListenIP != "" && m.ListenIP != "0.0.0.0" {
		args = append(args, "--listen-ip", m.ListenIP)
	}
	if m.Port != "" && m.Port != "44818" {
		args = append(args, "--listen-port", m.Port)
	}

	// Mode (only if not default baseline)
	if m.ModeIndex > 0 {
		args = append(args, "--mode", serverModes[m.ModeIndex].Name)
	}

	// CIP Profiles (only in config mode)
	if !m.ProfileMode {
		var profiles []string
		for i, enabled := range m.CIPProfiles {
			if enabled {
				profiles = append(profiles, serverCIPProfiles[i])
			}
		}
		if len(profiles) > 0 {
			args = append(args, "--cip-profile", strings.Join(profiles, ","))
		}
	}

	// UDP I/O
	if m.EnableUDPIO {
		args = append(args, "--enable-udp-io")
	}

	// PCAP capture
	if m.PcapEnabled {
		args = append(args, "--pcap", m.generatePcapFilename())
		if m.CaptureInterface != "" {
			args = append(args, "--capture-interface", m.CaptureInterface)
		}
	}

	// Config file (only in config mode)
	if !m.ProfileMode && m.ConfigPath != "" {
		args = append(args, "--server-config", m.ConfigPath)
	}

	return args
}

func (m *ServerScreenModel) buildCommand() string {
	return strings.Join(m.buildCommandArgs(), " ")
}

// View renders the server screen.
func (m *ServerScreenModel) View() string {
	// Show interface selector if active
	if m.InterfaceSelectorActive && m.InterfaceSelector != nil {
		return m.InterfaceSelector.View()
	}

	if m.Running {
		return m.viewRunning()
	}
	if m.Completed {
		return m.viewCompleted()
	}
	return m.viewEditing()
}

func (m *ServerScreenModel) viewEditing() string {
	var b strings.Builder

	// Header with mode indicator
	var header string
	if m.ProfileMode {
		header = "SERVER - PROFILE MODE"
		if m.ShowAdvanced {
			header += "                   [advanced]"
		} else {
			header += "               [p] config ▸"
		}
	} else {
		header = "SERVER - CONFIG MODE"
		if m.ShowAdvanced {
			header += "                    [advanced]"
		} else {
			header += "                [p]rofile ▸"
		}
	}
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Listen IP field
	ipLabel := "Listen IP: "
	ipValue := m.ListenIP
	if ipValue == "" {
		ipValue = "0.0.0.0"
	}
	if m.focusIndex == serverFieldIP {
		b.WriteString(selectedStyle.Render(ipLabel + ipValue + "█"))
	} else {
		b.WriteString(ipLabel + ipValue)
	}
	b.WriteString("            ")

	// Port field
	portLabel := "TCP Port: "
	portValue := m.Port
	if portValue == "" {
		portValue = "44818"
	}
	if m.focusIndex == serverFieldPort {
		b.WriteString(selectedStyle.Render(portLabel + portValue + "█"))
	} else {
		b.WriteString(portLabel + portValue)
	}
	b.WriteString("\n\n")

	// Profile mode: show profile selection
	// Config mode: show personality selection
	if m.ProfileMode {
		b.WriteString("Profile:\n")
		if len(m.Profiles) == 0 {
			b.WriteString(dimStyle.Render("  (no profiles found)"))
			b.WriteString("\n")
		} else {
			for i, p := range m.Profiles {
				prefix := "  ( ) "
				if i == m.ProfileIndex {
					prefix = "  (•) "
				}
				line := fmt.Sprintf("%s%-26s %s", prefix, p.Name, p.Description)
				if m.focusIndex == serverFieldProfile && i == m.ProfileIndex {
					b.WriteString(selectedStyle.Render(line))
				} else {
					b.WriteString(line)
				}
				b.WriteString("\n")
			}
		}
	} else {
		b.WriteString("Personality:\n")
		for i, p := range serverPersonalities {
			prefix := "  ( ) "
			if i == m.Personality {
				prefix = "  (•) "
			}
			line := fmt.Sprintf("%s%-12s %s", prefix, p.Name, p.Desc)
			if m.focusIndex == serverFieldPersonality && i == m.Personality {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}
	}

	// Mode selector
	b.WriteString("\n")
	modeLine := "Mode: "
	for i, mode := range serverModes {
		if i == m.ModeIndex {
			modeLine += fmt.Sprintf("[%s] ", mode.Name)
		} else {
			modeLine += fmt.Sprintf(" %s  ", mode.Name)
		}
	}
	if m.focusIndex == serverFieldMode {
		b.WriteString(selectedStyle.Render(modeLine))
	} else {
		b.WriteString(modeLine)
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("      %s", serverModes[m.ModeIndex].Desc)))
	b.WriteString("\n")

	// PCAP capture toggle (always visible)
	b.WriteString("\n")
	pcapCheck := " "
	if m.PcapEnabled {
		pcapCheck = "x"
	}
	pcapFullPath := m.generatePcapFilename()
	pcapFilename := filepath.Base(pcapFullPath)
	ifaceDisplay := "auto"
	if m.CaptureInterface != "" {
		ifaceDisplay = m.CaptureInterface
	}
	pcapLine := fmt.Sprintf("PCAP Capture: [%s] pcaps/%s", pcapCheck, pcapFilename)
	if m.PcapEnabled {
		// Show actual interface - either manual or auto-detected
		displayIface := ifaceDisplay
		if m.CaptureInterface == "" && m.AutoDetectedInterface != "" {
			displayIface = m.AutoDetectedInterface + " (auto)"
		}
		pcapLine += fmt.Sprintf("  [i]nterface: %s", displayIface)
	}
	if m.focusIndex == serverFieldPcap {
		b.WriteString(selectedStyle.Render(pcapLine))
	} else {
		b.WriteString(pcapLine)
	}
	b.WriteString("\n")

	// Advanced options section
	if m.ShowAdvanced {
		b.WriteString("\n")
		b.WriteString(strings.Repeat("─", 60))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("Advanced Options                                   [a] hide"))
		b.WriteString("\n\n")

		// CIP Profiles
		profileLine := "CIP Profiles: "
		for i, p := range serverCIPProfiles {
			check := " "
			if m.CIPProfiles[i] {
				check = "x"
			}
			profileLine += fmt.Sprintf("[%s] %s  ", check, p)
		}
		profileLine += "  (1/2/3 toggle, space=all)"
		if m.focusIndex == serverFieldCIPProfiles {
			b.WriteString(selectedStyle.Render(profileLine))
		} else {
			b.WriteString(profileLine)
		}
		b.WriteString("\n\n")

		// UDP I/O toggle
		udpCheck := " "
		if m.EnableUDPIO {
			udpCheck = "x"
		}
		udpLine := fmt.Sprintf("UDP I/O:      [%s] Enable UDP I/O on port 2222", udpCheck)
		if m.focusIndex == serverFieldUDPIO {
			b.WriteString(selectedStyle.Render(udpLine))
		} else {
			b.WriteString(udpLine)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("                                        [a]dvanced options ▸"))
		b.WriteString("\n")
	}

	// Config info
	b.WriteString("\n")
	if m.ConfigPath != "" {
		b.WriteString(fmt.Sprintf("Config: %s                    [e]dit\n", m.ConfigPath))
	} else {
		b.WriteString(dimStyle.Render("Config: [none - using defaults]                    [e]dit"))
		b.WriteString("\n")
	}

	// Separator
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Command preview
	b.WriteString("Command preview:\n")
	cmd := m.buildCommand()
	// Word wrap long commands
	if len(cmd) > 58 {
		b.WriteString(dimStyle.Render(cmd[:58]))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  " + cmd[58:]))
	} else {
		b.WriteString(dimStyle.Render(cmd))
	}
	b.WriteString("\n")

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *ServerScreenModel) viewRunning() string {
	var b strings.Builder

	// Header with running indicator
	b.WriteString(headerStyle.Render("SERVER"))
	b.WriteString("                                          ")
	b.WriteString(warningStyle.Render("[RUNNING]"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Server info
	b.WriteString(fmt.Sprintf("Listening: %s:%s      Personality: %s\n",
		m.displayIP(), m.Port, serverPersonalities[m.Personality].Name))
	b.WriteString(fmt.Sprintf("Uptime: %s              Connections: %d active\n",
		formatDuration(m.Uptime), m.ConnectionCount))

	// Progress bar
	b.WriteString("\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	b.WriteString("\n\n")

	// Active connections
	b.WriteString("Active connections:\n")
	if len(m.Connections) == 0 {
		b.WriteString(dimStyle.Render("  (no active connections)"))
		b.WriteString("\n")
	} else {
		for _, conn := range m.Connections {
			b.WriteString(fmt.Sprintf("  %s  session=%s  idle %.1fs\n",
				conn.RemoteAddr, conn.SessionID, conn.IdleTime.Seconds()))
		}
	}

	// Recent requests
	b.WriteString("\n")
	b.WriteString("Recent requests:\n")
	if len(m.RecentRequests) == 0 {
		b.WriteString(dimStyle.Render("  (no requests yet)"))
		b.WriteString("\n")
	} else {
		displayReqs := m.RecentRequests
		if len(displayReqs) > 5 {
			displayReqs = displayReqs[len(displayReqs)-5:]
		}
		for _, req := range displayReqs {
			b.WriteString(fmt.Sprintf("  %s  %s  %s %s\n",
				req.Time.Format("15:04:05"), req.RemoteAddr, req.Service, req.Path))
		}
	}

	// Statistics
	b.WriteString("\n")
	b.WriteString("Statistics:\n")
	b.WriteString(fmt.Sprintf("  Total requests: %d    Errors: %d\n", m.RequestCount, m.ErrorCount))

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *ServerScreenModel) viewCompleted() string {
	var b strings.Builder

	// Header with status indicator
	b.WriteString(headerStyle.Render("SERVER"))
	b.WriteString("                                          ")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render("[FAILED]"))
	} else {
		b.WriteString(successStyle.Render("[STOPPED]"))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Server info
	b.WriteString(fmt.Sprintf("Listen: %s:%s    Personality: %s\n",
		m.displayIP(), m.Port, serverPersonalities[m.Personality].Name))
	b.WriteString(fmt.Sprintf("Uptime: %s\n", formatDuration(m.Uptime)))

	// Status message
	b.WriteString("\n")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render(m.Status))
	} else {
		b.WriteString(successStyle.Render(m.Status))
	}
	b.WriteString("\n")

	// Output section
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")
	b.WriteString("Output:\n")
	if m.Output == "" {
		b.WriteString(dimStyle.Render("  (no output captured)"))
		b.WriteString("\n")
	} else {
		// Show output lines (limit to last 15 lines)
		lines := strings.Split(strings.TrimSpace(m.Output), "\n")
		startIdx := 0
		if len(lines) > 15 {
			startIdx = len(lines) - 15
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ... (%d lines omitted)\n", startIdx)))
		}
		for _, line := range lines[startIdx:] {
			if len(line) > 70 {
				line = line[:67] + "..."
			}
			b.WriteString(fmt.Sprintf("  %s\n", line))
		}
	}

	return borderStyle.Render(b.String())
}

// Footer returns the footer text for the server screen.
func (m *ServerScreenModel) Footer() string {
	if m.InterfaceSelectorActive && m.InterfaceSelector != nil {
		return m.InterfaceSelector.Footer()
	}
	if m.Running {
		return "x: stop    l: full log    f: filter by IP    m: menu"
	}
	if m.Completed {
		return "Enter/Esc: back to config    r: restart    o: open log    m: menu"
	}
	if m.ShowAdvanced {
		return "Tab: next    ←→: select    Enter: start    a: hide adv    p: toggle mode    m: menu"
	}
	if m.focusIndex == serverFieldPcap && m.PcapEnabled {
		return "Space: toggle    i: interface    Enter: start    p: toggle mode    m: menu"
	}
	if m.ProfileMode {
		return "Tab: next    ←→: select    Enter: start    p: config mode    y: copy    m: menu"
	}
	return "Tab: next    ←→: select    Enter: start    p: profile    e: edit    y: copy    m: menu"
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// serverTickMsg is sent periodically while server is running to poll for stats.
type serverTickMsg struct {
	Time time.Time
}

// HandleServerTick processes a server tick message, polling for stats updates.
func (m *ServerScreenModel) HandleServerTick(msg serverTickMsg) (*ServerScreenModel, tea.Cmd) {
	if !m.Running {
		return m, nil
	}

	// Update uptime
	if m.StartTime != nil {
		m.Uptime = time.Since(*m.StartTime)
	}

	// Check for result (command finished)
	if m.state.ServerResultChan != nil {
		select {
		case result, ok := <-m.state.ServerResultChan:
			if ok {
				// Command finished
				m.Running = false
				m.Completed = true
				m.state.ServerRunning = false
				m.Output = result.Output

				// Write artifacts
				args := m.buildCommandArgs()
				resolved := map[string]interface{}{
					"personality": serverPersonalities[m.Personality].Name,
					"listen_ip":   m.ListenIP,
					"port":        m.Port,
				}
				status := "success"
				if result.Err != nil && m.state.ServerCtx.Err() == nil {
					status = "failed"
					m.Status = fmt.Sprintf("FAILED: %v", result.Err)
				} else if m.state.ServerCtx.Err() != nil {
					status = "stopped"
					m.Status = "Server stopped by user"
				} else {
					m.Status = "Server stopped"
				}
				startTime := time.Time{}
				if m.StartTime != nil {
					startTime = *m.StartTime
				}
				summary := RunSummary{
					Status:     status,
					Command:    args,
					StartedAt:  startTime.UTC().Format(time.RFC3339),
					FinishedAt: time.Now().UTC().Format(time.RFC3339),
					ExitCode:   result.ExitCode,
				}
				_ = WriteRunArtifacts(m.RunDir, resolved, args, result.Output, summary)

				m.state.ServerStatsChan = nil
				m.state.ServerResultChan = nil
				return m, nil
			}
		default:
			// No result yet
		}
	}

	// Check for stats updates
	if m.state.ServerStatsChan != nil {
		for {
			select {
			case stats, ok := <-m.state.ServerStatsChan:
				if !ok {
					m.state.ServerStatsChan = nil
					break
				}
				// Update display stats
				m.ConnectionCount = stats.ActiveConnections
				m.RequestCount = stats.TotalRequests
				m.ErrorCount = stats.TotalErrors

				// Update connections list from recent clients
				if len(stats.RecentClients) > 0 {
					m.Connections = make([]ServerConnection, 0, len(stats.RecentClients))
					for _, client := range stats.RecentClients {
						m.Connections = append(m.Connections, ServerConnection{
							RemoteAddr: client,
							SessionID:  "-",
							IdleTime:   0,
						})
					}
				}
				continue
			default:
				// No more stats available
			}
			break
		}
	}

	// Schedule next tick
	return m, tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return serverTickMsg{Time: t}
	})
}
