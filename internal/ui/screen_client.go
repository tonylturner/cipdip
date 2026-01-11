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
)

// ClientScreenModel handles the client configuration screen.
type ClientScreenModel struct {
	state *AppState

	// Form fields
	TargetIP   string
	Port       string
	Scenario   int // Index into flattened scenarios list
	ConfigPath string

	// Advanced options
	ShowAdvanced     bool
	ModeIndex        int    // Index into modePresets
	Duration         string // Custom duration in seconds
	Interval         string // Custom interval in milliseconds
	FirewallVendor   int    // Index into firewallVendors (when firewall scenario selected)
	CIPProfiles      []bool // energy, safety, motion toggles
	ProtocolVariant  int    // Index into protocolVariants
	PcapEnabled           bool
	PcapFile              string
	CaptureInterface      string // Network interface for PCAP (empty = auto-detect)
	AutoDetectedInterface string // The auto-detected interface for display
	MetricsEnabled   bool
	MetricsFile      string

	// Interface selector
	InterfaceSelector       *InterfaceSelectorModel
	InterfaceSelectorActive bool

	// UI state
	focusIndex int // Which field is focused
	Running    bool
	Paused     bool
	Completed  bool   // True after a run finishes (success or failure)
	Status     string
	Output     string // Captured stdout from the run
	RunDir     string // Directory where artifacts were saved

	// Stats when running
	StartTime    *time.Time
	Elapsed      string
	RequestCount int
	SuccessCount int
	ErrorCount   int
	AvgLatency   string
	LastResponse string
	Errors       []string
}

type clientScenario struct {
	Name string
	Desc string
}

// Basic scenarios - always visible
var basicScenarios = []clientScenario{
	{"baseline", "Read-only polling of configured targets"},
	{"mixed", "Alternating reads and writes"},
	{"stress", "High-frequency burst traffic"},
	{"io", "Connected I/O with Forward Open"},
	{"edge", "Protocol edge cases for DPI testing"},
}

// Advanced scenarios - shown in advanced section
var advancedScenarioGroups = []struct {
	Name      string
	Scenarios []clientScenario
}{
	{
		Name: "Edge Cases",
		Scenarios: []clientScenario{
			{"churn", "Connection setup/teardown cycles"},
			{"edge_valid", "Protocol-valid edge cases"},
			{"edge_vendor", "Vendor-specific edge cases"},
		},
	},
	{
		Name: "Vendor Variants",
		Scenarios: []clientScenario{
			{"rockwell", "Rockwell edge pack"},
			{"vendor_variants", "Protocol variant testing"},
			{"mixed_state", "UCMM + I/O interleaving"},
			{"unconnected_send", "UCMM wrapper tests"},
		},
	},
	{
		Name: "Firewall DPI",
		Scenarios: []clientScenario{
			{"firewall", "Firewall DPI test pack"},
		},
	},
}

// Firewall vendor options (used when firewall scenario is selected)
var firewallVendors = []struct {
	Name     string
	Scenario string
	Desc     string
}{
	{"All", "firewall_pack", "All firewall vendor packs"},
	{"Hirschmann", "firewall_hirschmann", "Hirschmann EAGLE"},
	{"Moxa", "firewall_moxa", "Moxa EDR series"},
	{"Dynics", "firewall_dynics", "Dynics firewall"},
}

// Mode presets for duration/interval
type modePreset struct {
	Name     string
	Duration int // seconds
	Interval int // milliseconds
}

var modePresets = []modePreset{
	{"Quick", 30, 250},
	{"Standard", 300, 250},
	{"Extended", 1800, 250},
	{"Custom", 0, 0}, // User-defined
}

// CIP application profiles
var cipProfiles = []string{"energy", "safety", "motion"}

// Protocol variants
var protocolVariants = []struct {
	Name string
	Desc string
}{
	{"strict_odva", "Strict ODVA-compliant (default)"},
	{"rockwell_enbt", "Rockwell ENBT/A variant"},
	{"schneider_m580", "Schneider M580 variant"},
	{"siemens_s7_1200", "Siemens S7-1200 variant"},
}

// allScenarios returns all scenarios (basic + advanced) in a flat list
func allScenarios() []clientScenario {
	all := make([]clientScenario, len(basicScenarios))
	copy(all, basicScenarios)
	for _, g := range advancedScenarioGroups {
		all = append(all, g.Scenarios...)
	}
	return all
}

// isAdvancedScenario returns true if the scenario index is beyond basic scenarios
func isAdvancedScenario(idx int) bool {
	return idx >= len(basicScenarios)
}

const (
	clientFieldIP = iota
	clientFieldPort
	clientFieldScenario
	clientFieldFirewallVendor // Only visible when firewall scenario selected
	clientFieldMode
	// Advanced fields (only visible when ShowAdvanced is true)
	clientFieldDuration
	clientFieldInterval
	clientFieldCIPProfiles
	clientFieldProtocol
	clientFieldPcap
	clientFieldMetrics
	clientFieldCount
)

// NewClientScreenModel creates a new client screen model.
func NewClientScreenModel(state *AppState) *ClientScreenModel {
	return &ClientScreenModel{
		state:       state,
		Port:        "44818",
		ModeIndex:   1, // Standard (5 min)
		Duration:    "300",
		Interval:    "250",
		CIPProfiles: make([]bool, len(cipProfiles)),
		MetricsFile: "metrics.csv",
	}
}

// updateAutoDetectedInterface detects the interface for the current target IP.
func (m *ClientScreenModel) updateAutoDetectedInterface() {
	if m.TargetIP == "" {
		m.AutoDetectedInterface = ""
		return
	}
	iface, err := netdetect.DetectInterfaceForTarget(m.TargetIP)
	if err != nil {
		m.AutoDetectedInterface = "unknown"
	} else {
		// Get the display-friendly name
		m.AutoDetectedInterface = netdetect.GetDisplayNameForInterface(iface)
	}
}

// generatePcapFilename creates a filename based on current settings
func (m *ClientScreenModel) generatePcapFilename() string {
	scenarios := allScenarios()
	scenarioName := scenarios[m.Scenario].Name
	if scenarioName == "firewall" {
		scenarioName = firewallVendors[m.FirewallVendor].Scenario
	}
	modeName := modePresets[m.ModeIndex].Name
	timestamp := time.Now().UTC().Format("2006-01-02T150405Z")
	filename := fmt.Sprintf("client_%s_%s_%s.pcap", scenarioName, modeName, timestamp)
	return filepath.Join(m.state.WorkspaceRoot, "pcaps", filename)
}

// Update handles input for the client screen.
func (m *ClientScreenModel) Update(msg tea.KeyMsg) (*ClientScreenModel, tea.Cmd) {
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

func (m *ClientScreenModel) updateEditing(msg tea.KeyMsg) (*ClientScreenModel, tea.Cmd) {
	scenarios := allScenarios()

	// Handle text input fields first - these consume single characters
	isTextInputField := m.focusIndex == clientFieldIP || m.focusIndex == clientFieldPort
	if isTextInputField {
		switch msg.String() {
		case "tab", "down":
			m.focusIndex = m.nextField(1)
			return m, nil
		case "shift+tab", "up":
			m.focusIndex = m.nextField(-1)
			return m, nil
		case "enter":
			if m.TargetIP != "" {
				return m.startRun()
			}
			return m, nil
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
	case "a":
		// Toggle advanced options
		m.ShowAdvanced = !m.ShowAdvanced
		if !m.ShowAdvanced {
			// Reset focus if on advanced field
			if m.focusIndex > clientFieldMode {
				m.focusIndex = clientFieldMode
			}
			// Reset to basic scenario if advanced scenario was selected
			if isAdvancedScenario(m.Scenario) {
				m.Scenario = 0 // Reset to baseline
			}
		}
	case "enter":
		if m.TargetIP != "" {
			return m.startRun()
		}
	case "e":
		// Open config in editor
		configPath := m.ConfigPath
		if configPath == "" {
			// Create default config path
			configPath = filepath.Join(m.state.WorkspaceRoot, "profiles", "client_config.yaml")
		}
		// Check if file exists, create template if not
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			// Create a template config
			template := `# CIPDIP Client Configuration
# Generated by TUI

adapter:
  name: "Target Device"
  port: 44818

read_targets:
  - name: "Identity"
    service: "get_attribute_single"
    class: 0x01
    instance: 0x01
    attribute: 0x01
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
		// Copy command
		cmd := m.buildCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "backspace":
		m.handleBackspace()
	default:
		// Handle character input for focused field
		if len(msg.String()) == 1 {
			m.handleCharInput(msg.String())
		}
	}

	// Handle field-specific controls
	switch m.focusIndex {
	case clientFieldScenario:
		// Limit to basic scenarios unless in advanced mode
		maxScenario := len(basicScenarios)
		if m.ShowAdvanced {
			maxScenario = len(scenarios)
		}
		switch msg.String() {
		case " ", "right", "l":
			m.Scenario = (m.Scenario + 1) % maxScenario
		case "left", "h":
			m.Scenario = (m.Scenario - 1 + maxScenario) % maxScenario
		}
	case clientFieldFirewallVendor:
		switch msg.String() {
		case " ", "right", "l":
			m.FirewallVendor = (m.FirewallVendor + 1) % len(firewallVendors)
		case "left", "h":
			m.FirewallVendor = (m.FirewallVendor - 1 + len(firewallVendors)) % len(firewallVendors)
		}
	case clientFieldMode:
		switch msg.String() {
		case " ", "right", "l":
			m.ModeIndex = (m.ModeIndex + 1) % len(modePresets)
			m.applyModePreset()
		case "left", "h":
			m.ModeIndex = (m.ModeIndex - 1 + len(modePresets)) % len(modePresets)
			m.applyModePreset()
		}
	case clientFieldCIPProfiles:
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
	case clientFieldProtocol:
		switch msg.String() {
		case " ", "right", "l":
			m.ProtocolVariant = (m.ProtocolVariant + 1) % len(protocolVariants)
		case "left", "h":
			m.ProtocolVariant = (m.ProtocolVariant - 1 + len(protocolVariants)) % len(protocolVariants)
		}
	case clientFieldPcap:
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
	case clientFieldMetrics:
		switch msg.String() {
		case " ":
			m.MetricsEnabled = !m.MetricsEnabled
		}
	}

	return m, nil
}

// nextField returns the next valid field index, skipping hidden fields
func (m *ClientScreenModel) nextField(dir int) int {
	scenarios := allScenarios()
	isFirewall := scenarios[m.Scenario].Name == "firewall"

	// Determine which fields are visible
	visibleFields := []int{clientFieldIP, clientFieldPort, clientFieldScenario}
	if isFirewall && m.ShowAdvanced {
		visibleFields = append(visibleFields, clientFieldFirewallVendor)
	}
	visibleFields = append(visibleFields, clientFieldMode, clientFieldPcap)
	if m.ShowAdvanced {
		if modePresets[m.ModeIndex].Name == "Custom" {
			visibleFields = append(visibleFields, clientFieldDuration, clientFieldInterval)
		}
		visibleFields = append(visibleFields, clientFieldCIPProfiles, clientFieldProtocol, clientFieldMetrics)
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

// applyModePreset sets duration/interval based on selected mode
func (m *ClientScreenModel) applyModePreset() {
	preset := modePresets[m.ModeIndex]
	if preset.Name != "Custom" {
		m.Duration = fmt.Sprintf("%d", preset.Duration)
		m.Interval = fmt.Sprintf("%d", preset.Interval)
	}
}

func (m *ClientScreenModel) updateRunning(msg tea.KeyMsg) (*ClientScreenModel, tea.Cmd) {
	switch msg.String() {
	case "x":
		// Stop run
		if m.state.ClientCancel != nil {
			m.state.ClientCancel()
		}
		m.Running = false
		m.Status = "Run cancelled"
	case " ":
		// Toggle pause
		m.Paused = !m.Paused
		if m.Paused {
			m.Status = "Paused"
		} else {
			m.Status = "Resumed"
		}
	case "l":
		// Toggle full log view
		// TODO: implement log view
	}
	return m, nil
}

func (m *ClientScreenModel) updateCompleted(msg tea.KeyMsg) (*ClientScreenModel, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		// Return to editing mode
		m.Completed = false
		m.Output = ""
		m.Status = ""
	case "r":
		// Re-run with same settings
		m.Completed = false
		return m.startRun()
	case "o":
		// Open artifacts directory
		if m.RunDir != "" {
			if err := OpenEditor(m.RunDir + "/stdout.log"); err != nil {
				m.Status = fmt.Sprintf("Failed to open: %v", err)
			}
		}
	}
	return m, nil
}

func (m *ClientScreenModel) handleBackspace() {
	switch m.focusIndex {
	case clientFieldIP:
		if len(m.TargetIP) > 0 {
			m.TargetIP = m.TargetIP[:len(m.TargetIP)-1]
			// Update auto-detected interface if PCAP is enabled
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		}
	case clientFieldPort:
		if len(m.Port) > 0 {
			m.Port = m.Port[:len(m.Port)-1]
		}
	case clientFieldDuration:
		if len(m.Duration) > 0 {
			m.Duration = m.Duration[:len(m.Duration)-1]
		}
	case clientFieldInterval:
		if len(m.Interval) > 0 {
			m.Interval = m.Interval[:len(m.Interval)-1]
		}
	case clientFieldMetrics:
		if len(m.MetricsFile) > 0 {
			m.MetricsFile = m.MetricsFile[:len(m.MetricsFile)-1]
		}
	}
}

func (m *ClientScreenModel) handleCharInput(ch string) {
	switch m.focusIndex {
	case clientFieldIP:
		// Allow IP characters
		if strings.ContainsAny(ch, "0123456789.") {
			m.TargetIP += ch
			// Update auto-detected interface if PCAP is enabled
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		}
	case clientFieldPort:
		// Allow port numbers
		if strings.ContainsAny(ch, "0123456789") {
			m.Port += ch
		}
	case clientFieldDuration:
		// Allow numbers
		if strings.ContainsAny(ch, "0123456789") {
			m.Duration += ch
		}
	case clientFieldInterval:
		// Allow numbers
		if strings.ContainsAny(ch, "0123456789") {
			m.Interval += ch
		}
	case clientFieldMetrics:
		// Allow filename characters
		if strings.ContainsAny(ch, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-/") {
			m.MetricsFile += ch
		}
	}
}

func (m *ClientScreenModel) startRun() (*ClientScreenModel, tea.Cmd) {
	if m.TargetIP == "" {
		m.Status = "Target IP is required"
		return m, nil
	}

	m.Running = true
	m.Status = "Starting..."
	m.RequestCount = 0
	m.SuccessCount = 0
	m.ErrorCount = 0
	m.Errors = nil
	now := time.Now()
	m.StartTime = &now
	m.Elapsed = "00:00:00"

	// Set up cancellation context
	ctx, cancel := context.WithCancel(context.Background())
	m.state.ClientCtx = ctx
	m.state.ClientCancel = cancel
	m.state.ClientRunning = true

	// Build the command
	scenarios := allScenarios()
	args := m.buildCommandArgs()
	command := CommandSpec{Args: args}

	// Create run directory
	scenarioName := scenarios[m.Scenario].Name
	if scenarioName == "firewall" {
		scenarioName = firewallVendors[m.FirewallVendor].Scenario
	}
	runName := fmt.Sprintf("client_%s", scenarioName)
	runDir, err := CreateRunDir(m.state.WorkspaceRoot, runName)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to create run directory: %v", err)
		m.Running = false
		m.state.ClientRunning = false
		return m, nil
	}
	m.RunDir = runDir

	// Start the streaming command
	statsChan, resultChan, err := StartStreamingCommand(ctx, command)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to start client: %v", err)
		m.Running = false
		m.state.ClientRunning = false
		return m, nil
	}

	// Store channels for polling
	m.state.ClientStatsChan = statsChan
	m.state.ClientResultChan = resultChan

	// Return a tick command to poll for updates
	return m, tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return clientTickMsg{Time: t}
	})
}

func (m *ClientScreenModel) buildCommandArgs() []string {
	scenarios := allScenarios()
	args := []string{"cipdip", "client"}

	if m.TargetIP != "" {
		args = append(args, "--ip", m.TargetIP)
	}
	if m.Port != "" && m.Port != "44818" {
		args = append(args, "--port", m.Port)
	}

	// Scenario - handle firewall vendor mapping
	scenarioName := scenarios[m.Scenario].Name
	if scenarioName == "firewall" {
		scenarioName = firewallVendors[m.FirewallVendor].Scenario
	}
	args = append(args, "--scenario", scenarioName)

	// Duration and interval
	if m.Duration != "" && m.Duration != "300" {
		args = append(args, "--duration-seconds", m.Duration)
	}
	if m.Interval != "" && m.Interval != "250" {
		args = append(args, "--interval-ms", m.Interval)
	}

	// CIP Profiles
	var profiles []string
	for i, enabled := range m.CIPProfiles {
		if enabled {
			profiles = append(profiles, cipProfiles[i])
		}
	}
	if len(profiles) > 0 {
		args = append(args, "--cip-profile", strings.Join(profiles, ","))
	}

	// Protocol variant (only if not default)
	if m.ProtocolVariant > 0 {
		args = append(args, "--protocol-profile", protocolVariants[m.ProtocolVariant].Name)
	}

	// PCAP capture
	if m.PcapEnabled {
		args = append(args, "--pcap", m.generatePcapFilename())
		if m.CaptureInterface != "" {
			args = append(args, "--capture-interface", m.CaptureInterface)
		}
	}

	// Metrics file
	if m.MetricsEnabled && m.MetricsFile != "" {
		args = append(args, "--metrics-file", m.MetricsFile)
	}

	// Config file
	if m.ConfigPath != "" {
		args = append(args, "--config", m.ConfigPath)
	}

	return args
}

func (m *ClientScreenModel) buildCommand() string {
	return strings.Join(m.buildCommandArgs(), " ")
}

// View renders the client screen.
func (m *ClientScreenModel) View() string {
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

func (m *ClientScreenModel) viewEditing() string {
	var b strings.Builder
	scenarios := allScenarios()

	// Header
	header := "CLIENT"
	if m.ShowAdvanced {
		header += "                                          [advanced]"
	} else if m.ConfigPath != "" {
		header += "                                            [config]"
	}
	b.WriteString(headerStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Target IP field
	ipLabel := "Target IP: "
	ipValue := m.TargetIP
	if ipValue == "" {
		ipValue = "_____________"
	}
	if m.focusIndex == clientFieldIP {
		b.WriteString(selectedStyle.Render(ipLabel + ipValue + "█"))
	} else {
		b.WriteString(ipLabel + ipValue)
	}
	b.WriteString("    ")

	// Port field
	portLabel := "Port: "
	portValue := m.Port
	if portValue == "" {
		portValue = "_____"
	}
	if m.focusIndex == clientFieldPort {
		b.WriteString(selectedStyle.Render(portLabel + portValue + "█"))
	} else {
		b.WriteString(portLabel + portValue)
	}
	b.WriteString("\n\n")

	// Scenario selection - basic scenarios only
	b.WriteString("Scenario:\n")
	for i, scenario := range basicScenarios {
		prefix := "  ( ) "
		if i == m.Scenario {
			prefix = "  (•) "
		}
		line := fmt.Sprintf("%s%-12s %s", prefix, scenario.Name, scenario.Desc)
		if m.focusIndex == clientFieldScenario && i == m.Scenario {
			b.WriteString(selectedStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}
	// Show indicator if advanced scenario is selected
	if isAdvancedScenario(m.Scenario) {
		selectedScenario := scenarios[m.Scenario]
		b.WriteString(fmt.Sprintf("  (•) %-12s %s\n", selectedScenario.Name, selectedScenario.Desc))
	}

	// Mode selector
	modeLine := "\nMode: "
	for i, mode := range modePresets {
		if i == m.ModeIndex {
			modeLine += fmt.Sprintf("[%s] ", mode.Name)
		} else {
			modeLine += fmt.Sprintf(" %s  ", mode.Name)
		}
	}
	if m.focusIndex == clientFieldMode {
		b.WriteString(selectedStyle.Render(modeLine))
	} else {
		b.WriteString(modeLine)
	}
	b.WriteString("\n")

	// Show duration/interval summary for non-custom modes
	if modePresets[m.ModeIndex].Name != "Custom" {
		preset := modePresets[m.ModeIndex]
		b.WriteString(dimStyle.Render(fmt.Sprintf("      Duration: %ds, Interval: %dms", preset.Duration, preset.Interval)))
		b.WriteString("\n")
	}

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
	if m.focusIndex == clientFieldPcap {
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

		// Advanced scenarios
		b.WriteString("Advanced Scenarios:\n")
		idx := len(basicScenarios)
		for _, group := range advancedScenarioGroups {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ── %s ──\n", group.Name)))
			for _, scenario := range group.Scenarios {
				prefix := "  ( ) "
				if idx == m.Scenario {
					prefix = "  (•) "
				}
				line := fmt.Sprintf("%s%-16s %s", prefix, scenario.Name, scenario.Desc)
				if m.focusIndex == clientFieldScenario && idx == m.Scenario {
					b.WriteString(selectedStyle.Render(line))
				} else {
					b.WriteString(line)
				}
				b.WriteString("\n")
				idx++
			}
		}

		// Firewall vendor selector (only when firewall scenario selected)
		if scenarios[m.Scenario].Name == "firewall" {
			b.WriteString("\n")
			vendorLine := "  Firewall Vendor: "
			for i, v := range firewallVendors {
				if i == m.FirewallVendor {
					vendorLine += fmt.Sprintf("[%s] ", v.Name)
				} else {
					vendorLine += fmt.Sprintf(" %s  ", v.Name)
				}
			}
			if m.focusIndex == clientFieldFirewallVendor {
				b.WriteString(selectedStyle.Render(vendorLine))
			} else {
				b.WriteString(vendorLine)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")

		// Duration/Interval (only for Custom mode)
		if modePresets[m.ModeIndex].Name == "Custom" {
			durLabel := "Duration (sec): "
			durValue := m.Duration
			if durValue == "" {
				durValue = "___"
			}
			if m.focusIndex == clientFieldDuration {
				b.WriteString(selectedStyle.Render(durLabel + durValue + "█"))
			} else {
				b.WriteString(durLabel + durValue)
			}
			b.WriteString("    ")

			intLabel := "Interval (ms): "
			intValue := m.Interval
			if intValue == "" {
				intValue = "___"
			}
			if m.focusIndex == clientFieldInterval {
				b.WriteString(selectedStyle.Render(intLabel + intValue + "█"))
			} else {
				b.WriteString(intLabel + intValue)
			}
			b.WriteString("\n\n")
		}

		// CIP Profiles
		profileLine := "CIP Profiles: "
		for i, p := range cipProfiles {
			check := " "
			if m.CIPProfiles[i] {
				check = "x"
			}
			profileLine += fmt.Sprintf("[%s] %s  ", check, p)
		}
		profileLine += "  (1/2/3 toggle, space=all)"
		if m.focusIndex == clientFieldCIPProfiles {
			b.WriteString(selectedStyle.Render(profileLine))
		} else {
			b.WriteString(profileLine)
		}
		b.WriteString("\n\n")

		// Protocol variant
		protoLine := "Protocol: "
		for i, p := range protocolVariants {
			if i == m.ProtocolVariant {
				protoLine += fmt.Sprintf("[%s] ", p.Name)
			} else {
				protoLine += fmt.Sprintf(" %s  ", p.Name)
			}
		}
		if m.focusIndex == clientFieldProtocol {
			b.WriteString(selectedStyle.Render(protoLine))
		} else {
			b.WriteString(protoLine)
		}
		b.WriteString("\n\n")

		// Metrics output
		metricsCheck := " "
		if m.MetricsEnabled {
			metricsCheck = "x"
		}
		metricsLine := fmt.Sprintf("Metrics File: [%s] ", metricsCheck)
		if m.MetricsEnabled {
			metricsLine += m.MetricsFile
		} else {
			metricsLine += dimStyle.Render("(disabled)")
		}
		if m.focusIndex == clientFieldMetrics {
			b.WriteString(selectedStyle.Render(metricsLine))
		} else {
			b.WriteString(metricsLine)
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
	if m.TargetIP == "" {
		cmd = strings.Replace(cmd, "--ip ", "--ip ???", 1)
	}
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

func (m *ClientScreenModel) viewRunning() string {
	var b strings.Builder
	scenarios := allScenarios()

	// Header with running indicator
	b.WriteString(headerStyle.Render("CLIENT"))
	b.WriteString("                                          ")
	b.WriteString(warningStyle.Render("[RUNNING]"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Target info
	b.WriteString(fmt.Sprintf("Target: %s:%s    Scenario: %s\n",
		m.TargetIP, m.Port, scenarios[m.Scenario].Name))
	b.WriteString(fmt.Sprintf("Elapsed: %s             Requests: %d\n",
		m.Elapsed, m.RequestCount))

	// Progress bar
	b.WriteString("\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	b.WriteString("\n\n")

	// Statistics
	b.WriteString("Statistics:\n")
	successPct := float64(0)
	if m.RequestCount > 0 {
		successPct = float64(m.SuccessCount) / float64(m.RequestCount) * 100
	}
	b.WriteString(fmt.Sprintf("  Success:     %d  (%.2f%%)\n", m.SuccessCount, successPct))
	errorPct := float64(0)
	if m.RequestCount > 0 {
		errorPct = float64(m.ErrorCount) / float64(m.RequestCount) * 100
	}
	b.WriteString(fmt.Sprintf("  Errors:      %d  (%.2f%%)\n", m.ErrorCount, errorPct))
	b.WriteString(fmt.Sprintf("  Latency:     %s\n", m.AvgLatency))

	// Last response
	if m.LastResponse != "" {
		b.WriteString("\n")
		b.WriteString("Last response:\n")
		b.WriteString(fmt.Sprintf("  %s\n", m.LastResponse))
	}

	// Recent errors
	if len(m.Errors) > 0 {
		b.WriteString("\n")
		b.WriteString("Errors:\n")
		displayErrors := m.Errors
		if len(displayErrors) > 5 {
			displayErrors = displayErrors[len(displayErrors)-5:]
		}
		for _, err := range displayErrors {
			b.WriteString(errorStyle.Render(fmt.Sprintf("  %s\n", err)))
		}
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *ClientScreenModel) viewCompleted() string {
	var b strings.Builder
	scenarios := allScenarios()

	// Header with status indicator
	b.WriteString(headerStyle.Render("CLIENT"))
	b.WriteString("                                          ")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render("[FAILED]"))
	} else {
		b.WriteString(successStyle.Render("[DONE]"))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Target info
	b.WriteString(fmt.Sprintf("Target: %s:%s    Scenario: %s\n",
		m.TargetIP, m.Port, scenarios[m.Scenario].Name))
	b.WriteString(fmt.Sprintf("Elapsed: %s\n", m.Elapsed))

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
		// Show output lines (limit to last 15 lines to fit in view)
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

// Footer returns the footer text for the client screen.
func (m *ClientScreenModel) Footer() string {
	if m.InterfaceSelectorActive && m.InterfaceSelector != nil {
		return m.InterfaceSelector.Footer()
	}
	if m.Running {
		return "x: stop    Space: pause/resume    l: show full log    m: menu"
	}
	if m.Completed {
		return "Enter/Esc: back to config    r: re-run    o: open artifacts    m: menu"
	}
	if m.ShowAdvanced {
		return "Tab: next    ←→: select    Enter: run    a: hide adv    e: edit    m: menu"
	}
	if m.focusIndex == clientFieldPcap && m.PcapEnabled {
		return "Space: toggle    i: interface    Enter: run    a: advanced    m: menu"
	}
	return "Tab: next    ←→: select    Enter: run    a: advanced    e: edit    y: copy    m: menu"
}

// clientTickMsg is sent periodically while client is running to poll for stats.
type clientTickMsg struct {
	Time time.Time
}

// HandleClientTick processes a client tick message, polling for stats updates.
func (m *ClientScreenModel) HandleClientTick(msg clientTickMsg) (*ClientScreenModel, tea.Cmd) {
	if !m.Running {
		return m, nil
	}

	// Update elapsed time
	if m.StartTime != nil {
		elapsed := time.Since(*m.StartTime)
		h := int(elapsed.Hours())
		min := int(elapsed.Minutes()) % 60
		s := int(elapsed.Seconds()) % 60
		m.Elapsed = fmt.Sprintf("%02d:%02d:%02d", h, min, s)
	}

	// Check for result (command finished)
	if m.state.ClientResultChan != nil {
		select {
		case result, ok := <-m.state.ClientResultChan:
			if ok {
				// Command finished
				m.Running = false
				m.Completed = true
				m.state.ClientRunning = false
				m.Output = result.Output

				// Write artifacts
				scenarios := allScenarios()
				scenarioName := scenarios[m.Scenario].Name
				if scenarioName == "firewall" {
					scenarioName = firewallVendors[m.FirewallVendor].Scenario
				}
				args := m.buildCommandArgs()
				resolved := map[string]interface{}{
					"scenario": scenarioName,
					"target":   m.TargetIP,
					"port":     m.Port,
				}
				status := "success"
				if result.Err != nil && m.state.ClientCtx.Err() == nil {
					status = "failed"
					errMsg := extractErrorFromOutput(result.Output)
					if errMsg == "" {
						errMsg = result.Err.Error()
					}
					m.Status = fmt.Sprintf("FAILED: %s", errMsg)
				} else if m.state.ClientCtx.Err() != nil {
					status = "stopped"
					m.Status = "Run cancelled by user"
				} else {
					m.Status = "Run completed successfully"
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

				m.state.ClientStatsChan = nil
				m.state.ClientResultChan = nil
				return m, nil
			}
		default:
			// No result yet
		}
	}

	// Check for stats updates
	if m.state.ClientStatsChan != nil {
		for {
			select {
			case stats, ok := <-m.state.ClientStatsChan:
				if !ok {
					m.state.ClientStatsChan = nil
					break
				}
				// Update display stats
				m.RequestCount = stats.TotalRequests
				m.SuccessCount = stats.SuccessfulRequests
				m.ErrorCount = stats.FailedRequests
				continue
			default:
				// No more stats available
			}
			break
		}
	}

	// Schedule next tick
	return m, tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return clientTickMsg{Time: t}
	})
}
