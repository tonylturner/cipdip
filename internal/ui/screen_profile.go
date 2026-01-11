package ui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/netdetect"
	"github.com/tturner/cipdip/internal/profile"
)

// ProfileScreenModel handles the profile-based client configuration screen.
type ProfileScreenModel struct {
	state *AppState

	// Form fields
	TargetIP string
	Port     string

	// Profile selection
	Profiles      []profile.ProfileInfo
	ProfileIndex  int
	RoleIndex     int
	AvailableRoles []string

	// Mode preset
	ModeIndex int
	Duration  string
	Interval  string // Not used for profiles (controlled by role) but kept for custom override

	// Output options
	OutputDirEnabled bool
	OutputDir        string

	// PCAP options (same pattern as client screen)
	PcapEnabled           bool
	PcapFile              string
	CaptureInterface      string
	AutoDetectedInterface string

	// Interface selector
	InterfaceSelector       *InterfaceSelectorModel
	InterfaceSelectorActive bool

	// Metrics
	MetricsEnabled bool
	MetricsFile    string

	// UI state
	focusIndex int
	Running    bool
	Paused     bool
	Completed  bool
	Status     string
	Output     string
	RunDir     string

	// Stats when running
	StartTime    *time.Time
	Elapsed      string
	RequestCount int
	SuccessCount int
	ErrorCount   int
	AvgLatency   string
	LastResponse string
	Errors       []string

	// Navigation
	NavigateToClient bool
}

// Profile mode presets
var profileModePresets = []modePreset{
	{"Quick", 60, 0},      // 1 minute
	{"Standard", 300, 0},  // 5 minutes
	{"Extended", 1800, 0}, // 30 minutes
	{"Custom", 0, 0},
}

const (
	profileFieldIP = iota
	profileFieldPort
	profileFieldProfile
	profileFieldRole
	profileFieldMode
	profileFieldDuration
	profileFieldOutputDir
	profileFieldPcap
	profileFieldMetrics
	profileFieldCount
)

// NewProfileScreenModel creates a new profile screen model.
func NewProfileScreenModel(state *AppState) *ProfileScreenModel {
	m := &ProfileScreenModel{
		state:            state,
		Port:             "44818",
		ModeIndex:        1, // Standard (5 min)
		Duration:         "300",
		OutputDirEnabled: true,
		MetricsFile:      "metrics.csv",
	}
	m.loadProfiles()
	return m
}

// loadProfiles loads available profiles from the profiles directory.
func (m *ProfileScreenModel) loadProfiles() {
	profiles, err := profile.ListProfilesDefault()
	if err != nil || len(profiles) == 0 {
		// Try alternate location
		profiles, _ = profile.ListProfiles("profiles")
	}
	m.Profiles = profiles
	if len(profiles) > 0 {
		m.updateRolesForProfile()
	}
}

// updateRolesForProfile updates available roles when profile changes.
func (m *ProfileScreenModel) updateRolesForProfile() {
	if m.ProfileIndex >= len(m.Profiles) {
		m.AvailableRoles = nil
		return
	}

	// Load full profile to get roles
	p, err := profile.LoadProfileByName(m.Profiles[m.ProfileIndex].Name)
	if err != nil {
		m.AvailableRoles = nil
		return
	}

	m.AvailableRoles = make([]string, 0, len(p.Roles))
	for name := range p.Roles {
		m.AvailableRoles = append(m.AvailableRoles, name)
	}

	// Reset role index if out of bounds
	if m.RoleIndex >= len(m.AvailableRoles) {
		m.RoleIndex = 0
	}
}

// updateAutoDetectedInterface detects the interface for the current target IP.
func (m *ProfileScreenModel) updateAutoDetectedInterface() {
	if m.TargetIP == "" {
		m.AutoDetectedInterface = ""
		return
	}
	iface, err := netdetect.DetectInterfaceForTarget(m.TargetIP)
	if err != nil {
		m.AutoDetectedInterface = "unknown"
	} else {
		m.AutoDetectedInterface = netdetect.GetDisplayNameForInterface(iface)
	}
}

// generatePcapFilename creates a filename based on current settings.
func (m *ProfileScreenModel) generatePcapFilename() string {
	profileName := "unknown"
	roleName := "unknown"
	if m.ProfileIndex < len(m.Profiles) {
		profileName = strings.ReplaceAll(m.Profiles[m.ProfileIndex].Name, " ", "_")
		profileName = strings.ToLower(profileName)
	}
	if m.RoleIndex < len(m.AvailableRoles) {
		roleName = m.AvailableRoles[m.RoleIndex]
	}
	modeName := profileModePresets[m.ModeIndex].Name
	timestamp := time.Now().UTC().Format("2006-01-02T150405Z")
	filename := fmt.Sprintf("profile_%s_%s_%s_%s.pcap", profileName, roleName, modeName, timestamp)
	return filepath.Join(m.state.WorkspaceRoot, "pcaps", filename)
}

// generateOutputDir creates an output directory path.
func (m *ProfileScreenModel) generateOutputDir() string {
	profileName := "unknown"
	roleName := "unknown"
	if m.ProfileIndex < len(m.Profiles) {
		profileName = strings.ReplaceAll(m.Profiles[m.ProfileIndex].Name, " ", "_")
		profileName = strings.ToLower(profileName)
	}
	if m.RoleIndex < len(m.AvailableRoles) {
		roleName = m.AvailableRoles[m.RoleIndex]
	}
	timestamp := time.Now().UTC().Format("20060102-150405")
	return filepath.Join(m.state.WorkspaceRoot, "output", fmt.Sprintf("%s_%s_%s", profileName, roleName, timestamp))
}

// Update handles input for the profile screen.
func (m *ProfileScreenModel) Update(msg tea.KeyMsg) (*ProfileScreenModel, tea.Cmd) {
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

func (m *ProfileScreenModel) updateEditing(msg tea.KeyMsg) (*ProfileScreenModel, tea.Cmd) {
	// Handle text input fields
	isTextInputField := m.focusIndex == profileFieldIP || m.focusIndex == profileFieldPort ||
		m.focusIndex == profileFieldDuration
	if isTextInputField {
		switch msg.String() {
		case "tab", "down":
			m.focusIndex = m.nextField(1)
			return m, nil
		case "shift+tab", "up":
			m.focusIndex = m.nextField(-1)
			return m, nil
		case "enter":
			if m.TargetIP != "" && len(m.Profiles) > 0 {
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
	case "s":
		// Switch to scenario mode
		m.NavigateToClient = true
		return m, nil
	case "enter":
		if m.TargetIP != "" && len(m.Profiles) > 0 {
			return m.startRun()
		}
	case "y":
		// Copy command
		cmd := m.buildCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "r":
		// Refresh profiles
		m.loadProfiles()
		m.Status = fmt.Sprintf("Loaded %d profiles", len(m.Profiles))
	case "backspace":
		m.handleBackspace()
	default:
		if len(msg.String()) == 1 {
			m.handleCharInput(msg.String())
		}
	}

	// Handle field-specific controls
	switch m.focusIndex {
	case profileFieldProfile:
		switch msg.String() {
		case " ", "right", "l":
			if len(m.Profiles) > 0 {
				m.ProfileIndex = (m.ProfileIndex + 1) % len(m.Profiles)
				m.updateRolesForProfile()
			}
		case "left", "h":
			if len(m.Profiles) > 0 {
				m.ProfileIndex = (m.ProfileIndex - 1 + len(m.Profiles)) % len(m.Profiles)
				m.updateRolesForProfile()
			}
		}
	case profileFieldRole:
		switch msg.String() {
		case " ", "right", "l":
			if len(m.AvailableRoles) > 0 {
				m.RoleIndex = (m.RoleIndex + 1) % len(m.AvailableRoles)
			}
		case "left", "h":
			if len(m.AvailableRoles) > 0 {
				m.RoleIndex = (m.RoleIndex - 1 + len(m.AvailableRoles)) % len(m.AvailableRoles)
			}
		}
	case profileFieldMode:
		switch msg.String() {
		case " ", "right", "l":
			m.ModeIndex = (m.ModeIndex + 1) % len(profileModePresets)
			m.applyModePreset()
		case "left", "h":
			m.ModeIndex = (m.ModeIndex - 1 + len(profileModePresets)) % len(profileModePresets)
			m.applyModePreset()
		}
	case profileFieldOutputDir:
		switch msg.String() {
		case " ":
			m.OutputDirEnabled = !m.OutputDirEnabled
		}
	case profileFieldPcap:
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
	case profileFieldMetrics:
		switch msg.String() {
		case " ":
			m.MetricsEnabled = !m.MetricsEnabled
		}
	}

	return m, nil
}

func (m *ProfileScreenModel) nextField(dir int) int {
	visibleFields := []int{
		profileFieldIP,
		profileFieldPort,
		profileFieldProfile,
		profileFieldRole,
		profileFieldMode,
	}

	// Duration only visible for Custom mode
	if profileModePresets[m.ModeIndex].Name == "Custom" {
		visibleFields = append(visibleFields, profileFieldDuration)
	}

	visibleFields = append(visibleFields, profileFieldOutputDir, profileFieldPcap)

	// Metrics field only visible when output-dir is disabled
	if !m.OutputDirEnabled {
		visibleFields = append(visibleFields, profileFieldMetrics)
	}

	// Find current position
	currentPos := 0
	for i, f := range visibleFields {
		if f == m.focusIndex {
			currentPos = i
			break
		}
	}

	newPos := (currentPos + dir + len(visibleFields)) % len(visibleFields)
	return visibleFields[newPos]
}

func (m *ProfileScreenModel) applyModePreset() {
	preset := profileModePresets[m.ModeIndex]
	if preset.Name != "Custom" {
		m.Duration = fmt.Sprintf("%d", preset.Duration)
	}
}

func (m *ProfileScreenModel) updateRunning(msg tea.KeyMsg) (*ProfileScreenModel, tea.Cmd) {
	switch msg.String() {
	case "x":
		if m.state.ClientCancel != nil {
			m.state.ClientCancel()
		}
		m.Running = false
		m.Status = "Run cancelled"
	case " ":
		m.Paused = !m.Paused
		if m.Paused {
			m.Status = "Paused"
		} else {
			m.Status = "Resumed"
		}
	}
	return m, nil
}

func (m *ProfileScreenModel) updateCompleted(msg tea.KeyMsg) (*ProfileScreenModel, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.Completed = false
		m.Output = ""
		m.Status = ""
	case "r":
		m.Completed = false
		return m.startRun()
	case "o":
		if m.RunDir != "" {
			if err := OpenEditor(m.RunDir + "/stdout.log"); err != nil {
				m.Status = fmt.Sprintf("Failed to open: %v", err)
			}
		}
	}
	return m, nil
}

func (m *ProfileScreenModel) handleBackspace() {
	switch m.focusIndex {
	case profileFieldIP:
		if len(m.TargetIP) > 0 {
			m.TargetIP = m.TargetIP[:len(m.TargetIP)-1]
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		}
	case profileFieldPort:
		if len(m.Port) > 0 {
			m.Port = m.Port[:len(m.Port)-1]
		}
	case profileFieldDuration:
		if len(m.Duration) > 0 {
			m.Duration = m.Duration[:len(m.Duration)-1]
		}
	}
}

func (m *ProfileScreenModel) handleCharInput(ch string) {
	switch m.focusIndex {
	case profileFieldIP:
		if strings.ContainsAny(ch, "0123456789.") {
			m.TargetIP += ch
			if m.PcapEnabled {
				m.updateAutoDetectedInterface()
			}
		}
	case profileFieldPort:
		if strings.ContainsAny(ch, "0123456789") {
			m.Port += ch
		}
	case profileFieldDuration:
		if strings.ContainsAny(ch, "0123456789") {
			m.Duration += ch
		}
	}
}

func (m *ProfileScreenModel) startRun() (*ProfileScreenModel, tea.Cmd) {
	if m.TargetIP == "" {
		m.Status = "Target IP is required"
		return m, nil
	}
	if len(m.Profiles) == 0 {
		m.Status = "No profiles available"
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
	args := m.buildCommandArgs()
	command := CommandSpec{Args: args}

	// Create run directory
	profileName := "profile"
	if m.ProfileIndex < len(m.Profiles) {
		profileName = strings.ReplaceAll(m.Profiles[m.ProfileIndex].Name, " ", "_")
	}
	runName := fmt.Sprintf("profile_%s", profileName)
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
		m.Status = fmt.Sprintf("Failed to start: %v", err)
		m.Running = false
		m.state.ClientRunning = false
		return m, nil
	}

	m.state.ClientStatsChan = statsChan
	m.state.ClientResultChan = resultChan

	return m, tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return profileTickMsg{Time: t}
	})
}

func (m *ProfileScreenModel) buildCommandArgs() []string {
	args := []string{"cipdip", "client"}

	if m.TargetIP != "" {
		args = append(args, "--ip", m.TargetIP)
	}
	if m.Port != "" && m.Port != "44818" {
		args = append(args, "--port", m.Port)
	}

	// Profile and role
	if m.ProfileIndex < len(m.Profiles) {
		args = append(args, "--profile", m.Profiles[m.ProfileIndex].Name)
	}
	if m.RoleIndex < len(m.AvailableRoles) {
		args = append(args, "--role", m.AvailableRoles[m.RoleIndex])
	}

	// Duration
	if m.Duration != "" && m.Duration != "300" {
		args = append(args, "--duration-seconds", m.Duration)
	}

	// Output directory
	if m.OutputDirEnabled {
		args = append(args, "--output-dir", m.generateOutputDir())
	}

	// PCAP capture
	if m.PcapEnabled {
		args = append(args, "--pcap", m.generatePcapFilename())
		if m.CaptureInterface != "" {
			args = append(args, "--capture-interface", m.CaptureInterface)
		}
	}

	// Metrics file (only if output-dir is NOT enabled, since output-dir includes metrics automatically)
	if m.MetricsEnabled && m.MetricsFile != "" && !m.OutputDirEnabled {
		metricsPath := m.MetricsFile
		if !filepath.IsAbs(metricsPath) {
			metricsPath = filepath.Join(m.state.WorkspaceRoot, "metrics", m.MetricsFile)
		}
		args = append(args, "--metrics-file", metricsPath)
	}

	return args
}

func (m *ProfileScreenModel) buildCommand() string {
	return strings.Join(m.buildCommandArgs(), " ")
}

// View renders the profile screen.
func (m *ProfileScreenModel) View() string {
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

func (m *ProfileScreenModel) viewEditing() string {
	var b strings.Builder

	// Header with mode indicator
	b.WriteString(headerStyle.Render("CLIENT - PROFILE MODE"))
	b.WriteString("                       ")
	b.WriteString(dimStyle.Render("[s]cenario ▸"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Target IP field
	ipLabel := "Target IP: "
	ipValue := m.TargetIP
	if ipValue == "" {
		ipValue = "_____________"
	}
	if m.focusIndex == profileFieldIP {
		b.WriteString(selectedStyle.Render(ipLabel + ipValue + "|"))
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
	if m.focusIndex == profileFieldPort {
		b.WriteString(selectedStyle.Render(portLabel + portValue + "|"))
	} else {
		b.WriteString(portLabel + portValue)
	}
	b.WriteString("\n\n")

	// Profile selection
	b.WriteString("Profile:\n")
	if len(m.Profiles) == 0 {
		b.WriteString(dimStyle.Render("  (no profiles found - check profiles/ directory)"))
		b.WriteString("\n")
	} else {
		for i, p := range m.Profiles {
			prefix := "  ( ) "
			if i == m.ProfileIndex {
				prefix = "  (*) "
			}
			line := fmt.Sprintf("%s%-26s %s", prefix, p.Name, p.Description)
			if m.focusIndex == profileFieldProfile && i == m.ProfileIndex {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}
	}

	// Role selection
	b.WriteString("\nRole:\n")
	if len(m.AvailableRoles) == 0 {
		b.WriteString(dimStyle.Render("  (select a profile first)"))
		b.WriteString("\n")
	} else {
		// Load profile to get role descriptions
		var roleDescs map[string]string
		if m.ProfileIndex < len(m.Profiles) {
			if p, err := profile.LoadProfileByName(m.Profiles[m.ProfileIndex].Name); err == nil {
				roleDescs = make(map[string]string)
				for name, role := range p.Roles {
					roleDescs[name] = fmt.Sprintf("%s poll, batch %d", role.PollInterval, role.BatchSize)
				}
			}
		}
		for i, roleName := range m.AvailableRoles {
			prefix := "  ( ) "
			if i == m.RoleIndex {
				prefix = "  (*) "
			}
			desc := ""
			if roleDescs != nil {
				desc = roleDescs[roleName]
			}
			line := fmt.Sprintf("%s%-12s %s", prefix, roleName, desc)
			if m.focusIndex == profileFieldRole && i == m.RoleIndex {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}
	}

	// Mode selector
	modeLine := "\nMode: "
	for i, mode := range profileModePresets {
		if i == m.ModeIndex {
			modeLine += fmt.Sprintf("[%s] ", mode.Name)
		} else {
			modeLine += fmt.Sprintf(" %s  ", mode.Name)
		}
	}
	if m.focusIndex == profileFieldMode {
		b.WriteString(selectedStyle.Render(modeLine))
	} else {
		b.WriteString(modeLine)
	}
	b.WriteString("\n")

	// Duration for non-custom modes
	if profileModePresets[m.ModeIndex].Name != "Custom" {
		preset := profileModePresets[m.ModeIndex]
		b.WriteString(dimStyle.Render(fmt.Sprintf("      Duration: %ds (poll interval from role)", preset.Duration)))
		b.WriteString("\n")
	} else {
		// Custom duration input
		durLabel := "      Duration (sec): "
		durValue := m.Duration
		if durValue == "" {
			durValue = "___"
		}
		if m.focusIndex == profileFieldDuration {
			b.WriteString(selectedStyle.Render(durLabel + durValue + "|"))
		} else {
			b.WriteString(durLabel + durValue)
		}
		b.WriteString("\n")
	}

	// Output directory
	b.WriteString("\n")
	outputCheck := " "
	if m.OutputDirEnabled {
		outputCheck = "x"
	}
	outputLine := fmt.Sprintf("Output Directory: [%s] ", outputCheck)
	if m.OutputDirEnabled {
		outputLine += dimStyle.Render(m.generateOutputDir())
	} else {
		outputLine += dimStyle.Render("(disabled)")
	}
	if m.focusIndex == profileFieldOutputDir {
		b.WriteString(selectedStyle.Render(outputLine))
	} else {
		b.WriteString(outputLine)
	}
	b.WriteString("\n")

	// PCAP capture
	pcapCheck := " "
	if m.PcapEnabled {
		pcapCheck = "x"
	}
	pcapLine := fmt.Sprintf("PCAP Capture:     [%s] ", pcapCheck)
	if m.PcapEnabled {
		pcapLine += filepath.Base(m.generatePcapFilename())
		ifaceDisplay := "auto"
		if m.CaptureInterface != "" {
			ifaceDisplay = m.CaptureInterface
		} else if m.AutoDetectedInterface != "" {
			ifaceDisplay = m.AutoDetectedInterface + " (auto)"
		}
		pcapLine += fmt.Sprintf("  [i]nterface: %s", ifaceDisplay)
	} else {
		pcapLine += dimStyle.Render("(disabled)")
	}
	if m.focusIndex == profileFieldPcap {
		b.WriteString(selectedStyle.Render(pcapLine))
	} else {
		b.WriteString(pcapLine)
	}
	b.WriteString("\n")

	// Metrics - when output-dir is enabled, metrics are included automatically
	if m.OutputDirEnabled {
		metricsLine := "Metrics File:     " + dimStyle.Render("(included in output dir)")
		b.WriteString(metricsLine)
		b.WriteString("\n")
	} else {
		metricsCheck := " "
		if m.MetricsEnabled {
			metricsCheck = "x"
		}
		metricsLine := fmt.Sprintf("Metrics File:     [%s] ", metricsCheck)
		if m.MetricsEnabled {
			metricsLine += m.MetricsFile
		} else {
			metricsLine += dimStyle.Render("(disabled)")
		}
		if m.focusIndex == profileFieldMetrics {
			b.WriteString(selectedStyle.Render(metricsLine))
		} else {
			b.WriteString(metricsLine)
		}
		b.WriteString("\n")
	}

	// Separator
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 60))
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
		remaining := cmd[58:]
		for len(remaining) > 56 {
			b.WriteString(dimStyle.Render("  " + remaining[:56]))
			b.WriteString("\n")
			remaining = remaining[56:]
		}
		if len(remaining) > 0 {
			b.WriteString(dimStyle.Render("  " + remaining))
		}
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

func (m *ProfileScreenModel) viewRunning() string {
	var b strings.Builder

	profileName := "unknown"
	roleName := "unknown"
	if m.ProfileIndex < len(m.Profiles) {
		profileName = m.Profiles[m.ProfileIndex].Name
	}
	if m.RoleIndex < len(m.AvailableRoles) {
		roleName = m.AvailableRoles[m.RoleIndex]
	}

	b.WriteString(headerStyle.Render("CLIENT - PROFILE MODE"))
	b.WriteString("                           ")
	b.WriteString(warningStyle.Render("[RUNNING]"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 60))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("Target: %s:%s\n", m.TargetIP, m.Port))
	b.WriteString(fmt.Sprintf("Profile: %s  Role: %s\n", profileName, roleName))
	b.WriteString(fmt.Sprintf("Elapsed: %s             Requests: %d\n", m.Elapsed, m.RequestCount))

	b.WriteString("\n")
	b.WriteString("----------------------------------------------------")
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

	if m.LastResponse != "" {
		b.WriteString("\n")
		b.WriteString("Last response:\n")
		b.WriteString(fmt.Sprintf("  %s\n", m.LastResponse))
	}

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

	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *ProfileScreenModel) viewCompleted() string {
	var b strings.Builder

	profileName := "unknown"
	roleName := "unknown"
	if m.ProfileIndex < len(m.Profiles) {
		profileName = m.Profiles[m.ProfileIndex].Name
	}
	if m.RoleIndex < len(m.AvailableRoles) {
		roleName = m.AvailableRoles[m.RoleIndex]
	}

	b.WriteString(headerStyle.Render("CLIENT - PROFILE MODE"))
	b.WriteString("                           ")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render("[FAILED]"))
	} else {
		b.WriteString(successStyle.Render("[DONE]"))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 60))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("Target: %s:%s\n", m.TargetIP, m.Port))
	b.WriteString(fmt.Sprintf("Profile: %s  Role: %s\n", profileName, roleName))
	b.WriteString(fmt.Sprintf("Elapsed: %s\n", m.Elapsed))

	b.WriteString("\n")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render(m.Status))
	} else {
		b.WriteString(successStyle.Render(m.Status))
	}
	b.WriteString("\n")

	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", 60))
	b.WriteString("\n")
	b.WriteString("Output:\n")
	if m.Output == "" {
		b.WriteString(dimStyle.Render("  (no output captured)"))
		b.WriteString("\n")
	} else {
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

// Footer returns the footer text for the profile screen.
func (m *ProfileScreenModel) Footer() string {
	if m.InterfaceSelectorActive && m.InterfaceSelector != nil {
		return m.InterfaceSelector.Footer()
	}
	if m.Running {
		return "x: stop    Space: pause/resume    m: menu"
	}
	if m.Completed {
		return "Enter/Esc: back    r: re-run    o: open artifacts    m: menu"
	}
	if m.focusIndex == profileFieldPcap && m.PcapEnabled {
		return "Space: toggle    i: interface    Enter: run    s: scenario    m: menu"
	}
	return "Tab: next    ←→: select    Enter: run    r: refresh    s: scenario    m: menu"
}

// profileTickMsg is sent periodically while profile run is active.
type profileTickMsg struct {
	Time time.Time
}

// HandleProfileTick processes a profile tick message.
func (m *ProfileScreenModel) HandleProfileTick(msg profileTickMsg) (*ProfileScreenModel, tea.Cmd) {
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

	// Check for result
	if m.state.ClientResultChan != nil {
		select {
		case result, ok := <-m.state.ClientResultChan:
			if ok {
				m.Running = false
				m.Completed = true
				m.state.ClientRunning = false
				m.Output = result.Output

				// Write artifacts
				profileName := "profile"
				roleName := "unknown"
				if m.ProfileIndex < len(m.Profiles) {
					profileName = m.Profiles[m.ProfileIndex].Name
				}
				if m.RoleIndex < len(m.AvailableRoles) {
					roleName = m.AvailableRoles[m.RoleIndex]
				}
				args := m.buildCommandArgs()
				resolved := map[string]interface{}{
					"profile": profileName,
					"role":    roleName,
					"target":  m.TargetIP,
					"port":    m.Port,
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
				m.RequestCount = stats.TotalRequests
				m.SuccessCount = stats.SuccessfulRequests
				m.ErrorCount = stats.FailedRequests
				continue
			default:
			}
			break
		}
	}

	return m, tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return profileTickMsg{Time: t}
	})
}
