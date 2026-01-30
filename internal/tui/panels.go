package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tturner/cipdip/internal/cip/catalog"
	"github.com/tturner/cipdip/internal/netdetect"
	"github.com/tturner/cipdip/internal/profile"
	"github.com/tturner/cipdip/internal/ui"
)

// PanelMode represents the state of a panel.
type PanelMode int

const (
	PanelIdle PanelMode = iota
	PanelConfig
	PanelRunning
	PanelResult
)

// Panel is the interface for all dashboard panels.
type Panel interface {
	Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd)
	View(width int, focused bool) string
	Mode() PanelMode
	Name() string
}

// filterOutputForDisplay removes JSON stats lines and cleans up output for display.
// It filters out lines that are JSON stats updates (meant for machine parsing)
// and removes excessive blank lines.
func filterOutputForDisplay(output string) string {
	lines := strings.Split(output, "\n")
	var filtered []string
	blankCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip JSON stats lines (they start with {"stats": or {"type":"stats"})
		if strings.HasPrefix(trimmed, `{"stats":`) || strings.Contains(trimmed, `"type":"stats"`) {
			continue
		}

		// Skip empty JSON objects
		if trimmed == "{}" || trimmed == "[]" {
			continue
		}

		// Collapse multiple blank lines into one
		if trimmed == "" {
			blankCount++
			if blankCount > 1 {
				continue
			}
		} else {
			blankCount = 0
		}

		filtered = append(filtered, line)
	}

	// Trim leading/trailing blank lines
	result := strings.TrimSpace(strings.Join(filtered, "\n"))
	return result
}

// --------------------------------------------------------------------------
// ClientPanel
// --------------------------------------------------------------------------

// ClientPanel handles the client operation panel.
type ClientPanel struct {
	mode         PanelMode
	focusedField int
	styles       Styles

	// Mode selection
	useProfile   bool // Profile mode vs scenario mode
	profileIndex int
	profiles     []profile.ProfileInfo

	// Role selection (for profile mode)
	roleIndex int
	roles     []string

	// Config fields
	targetIP string
	port     string
	scenario int
	duration string
	interval string // milliseconds

	// Mode presets
	modePreset int // 0=Quick, 1=Standard, 2=Extended, 3=Custom

	// Advanced options
	showAdvanced    bool
	cipEnergy       bool
	cipSafety       bool
	cipMotion       bool
	protocolVariant int // 0=strict_odva, 1=rockwell_enbt, 2=schneider_m580, 3=siemens_s7_1200

	// PCAP capture
	pcapEnabled           bool
	pcapInterface         string // User-selected interface (empty = auto)
	autoDetectedInterface string // Auto-detected interface for display

	// Config file
	configFile string

	// Command preview
	showPreview bool

	// Firewall options (when firewall scenario selected)
	firewallVendor int

	// Target filtering
	targetTags string // Comma-separated list of tags to filter targets

	// Running stats
	stats         StatsUpdate
	statsHistory  []float64
	startTime     *time.Time
	lastResponse  string
	recentErrors  []string
	avgLatency    float64
	successRate   float64

	// Log view
	showLog    bool
	logLines   []string
	logScroll  int
	maxLogLines int

	// Run control
	runCtx    context.Context
	runCancel context.CancelFunc
	runDir    string // Directory for run artifacts

	// Result
	result *CommandResult
}

var clientScenarios = []string{
	"baseline", "stress", "io", "mixed", "churn",
	"edge_valid", "edge_vendor", "rockwell", "vendor_variants",
	"mixed_state", "unconnected_send", "dpi_explicit",
	"firewall_hirschmann", "firewall_moxa", "firewall_dynics", "firewall_pack",
	"pccc", "modbus", "modbus_pipeline",
	"evasion_segment", "evasion_fuzz", "evasion_anomaly", "evasion_timing",
}
var protocolVariants = []string{"strict_odva", "rockwell_enbt", "schneider_m580", "siemens_s7_1200"}
var firewallVendors = []string{"All", "Hirschmann EAGLE", "Moxa EDR", "Dynics"}

// clientModePresetLabels returns display labels for mode presets
func clientModePresetLabels() []string {
	presets := ui.ModePresets
	labels := make([]string, len(presets))
	for i, p := range presets {
		if p.Name == "Custom" {
			labels[i] = "Custom"
		} else if p.Duration >= 60 {
			labels[i] = fmt.Sprintf("%s (%dm)", p.Name, p.Duration/60)
		} else {
			labels[i] = fmt.Sprintf("%s (%ds)", p.Name, p.Duration)
		}
	}
	return labels
}

// NewClientPanel creates a new client panel.
func NewClientPanel(styles Styles) *ClientPanel {
	cp := &ClientPanel{
		mode:         PanelIdle,
		styles:       styles,
		targetIP:     "192.168.1.100",
		port:         "44818",
		scenario:     0,
		duration:     "300",
		interval:     "250",
		modePreset:   1, // Standard
		recentErrors: make([]string, 0),
		maxLogLines:  100,
		logLines:     make([]string, 0),
	}
	cp.loadProfiles()
	cp.updateAutoDetectedInterface()
	return cp
}

// loadProfiles loads available profiles from the profiles directory.
func (p *ClientPanel) loadProfiles() {
	profiles, err := profile.ListProfilesDefault()
	if err != nil || len(profiles) == 0 {
		// Try alternate location
		profiles, _ = profile.ListProfiles("profiles")
	}
	p.profiles = profiles
	if len(profiles) > 0 {
		p.updateRolesForProfile()
	}
}

// updateRolesForProfile updates available roles when profile changes.
func (p *ClientPanel) updateRolesForProfile() {
	if p.profileIndex >= len(p.profiles) {
		p.roles = nil
		return
	}

	// Load full profile to get roles
	prof, err := profile.LoadProfileByName(p.profiles[p.profileIndex].Name)
	if err != nil {
		p.roles = nil
		return
	}

	p.roles = prof.RoleNames()

	// Reset role index if out of bounds
	if p.roleIndex >= len(p.roles) {
		p.roleIndex = 0
	}
}

// updateAutoDetectedInterface detects the interface for the current target IP.
func (p *ClientPanel) updateAutoDetectedInterface() {
	if p.targetIP == "" {
		p.autoDetectedInterface = ""
		return
	}
	iface, err := netdetect.DetectInterfaceForTarget(p.targetIP)
	if err != nil {
		p.autoDetectedInterface = "unknown"
	} else {
		p.autoDetectedInterface = netdetect.GetDisplayNameForInterface(iface)
	}
}

// generatePcapFilename creates a filename based on current settings.
func (p *ClientPanel) generatePcapFilename() string {
	var modeName string
	if p.useProfile && p.profileIndex < len(p.profiles) {
		modeName = strings.ReplaceAll(p.profiles[p.profileIndex].Name, " ", "_")
		modeName = strings.ToLower(modeName)
		if p.roleIndex < len(p.roles) {
			modeName += "_" + p.roles[p.roleIndex]
		}
	} else {
		modeName = clientScenarios[p.scenario]
	}
	presetName := strings.ToLower(ui.ModePresets[p.modePreset].Name)
	timestamp := time.Now().UTC().Format("2006-01-02T150405Z")
	filename := fmt.Sprintf("client_%s_%s_%s.pcap", modeName, presetName, timestamp)
	return filepath.Join("pcaps", filename)
}

func (p *ClientPanel) Mode() PanelMode { return p.mode }
func (p *ClientPanel) Name() string    { return "client" }

// BuildRunConfig creates a ClientRunConfig from the current panel settings.
func (p *ClientPanel) BuildRunConfig(workspaceRoot string) ClientRunConfig {
	port, _ := strconv.Atoi(p.port)
	if port == 0 {
		port = 44818
	}

	duration, _ := strconv.Atoi(p.duration)
	if duration == 0 {
		duration = 300 // 5 minutes default
	}

	interval, _ := strconv.Atoi(p.interval)
	if interval == 0 {
		interval = 250
	}

	cfg := ClientRunConfig{
		TargetIP:   p.targetIP,
		Port:       port,
		DurationS:  duration,
		IntervalMs: interval,
	}

	if p.useProfile && p.profileIndex < len(p.profiles) {
		cfg.Profile = p.profiles[p.profileIndex].Name
		if p.roleIndex < len(p.roles) {
			cfg.Role = p.roles[p.roleIndex]
		} else {
			cfg.Role = "default"
		}
	} else {
		cfg.Scenario = clientScenarios[p.scenario]
	}

	if p.targetTags != "" {
		cfg.TargetTags = p.targetTags
	}

	if p.pcapEnabled {
		cfg.PCAPFile = p.generatePcapFilename()
		if p.pcapInterface != "" {
			cfg.Interface = p.pcapInterface
		}
	}

	if workspaceRoot != "" {
		cfg.OutputDir = workspaceRoot
	}

	return cfg
}

func (p *ClientPanel) Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd) {
	if !focused {
		return p, nil
	}

	switch p.mode {
	case PanelIdle:
		return p.updateIdle(msg)
	case PanelConfig:
		return p.updateConfig(msg)
	case PanelRunning:
		return p.updateRunning(msg)
	case PanelResult:
		return p.updateResult(msg)
	}
	return p, nil
}

func (p *ClientPanel) updateIdle(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "enter", "c":
		p.mode = PanelConfig
		p.focusedField = 0
	}
	return p, nil
}

func (p *ClientPanel) updateConfig(msg tea.KeyMsg) (Panel, tea.Cmd) {
	// Basic fields: IP, port, scenario/profile, (role if profile mode), mode preset, PCAP
	maxField := 5 // IP, port, scenario, mode preset, PCAP
	if p.useProfile {
		maxField = 6 // Add role field
	}
	if p.showAdvanced {
		maxField += 8 // Add: duration, interval, CIP profiles x3, protocol, firewall, target tags
	}

	switch msg.String() {
	case "esc":
		if p.showAdvanced {
			p.showAdvanced = false
		} else {
			p.mode = PanelIdle
		}
	case "enter":
		if p.targetIP == "" {
			return p, nil // Need a target IP
		}
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.stats = StatsUpdate{}
		p.statsHistory = nil
		p.recentErrors = nil
		// Create cancel context for this run
		p.runCtx, p.runCancel = context.WithCancel(context.Background())
		// Return command to signal model to start client
		return p, func() tea.Msg {
			return startClientRunMsg{config: p.BuildRunConfig("")}
		}
	case "a":
		p.showAdvanced = !p.showAdvanced
		baseFields := 4
		if p.useProfile {
			baseFields = 5
		}
		if !p.showAdvanced && p.focusedField > baseFields {
			p.focusedField = 0
		}
	case "p":
		p.useProfile = !p.useProfile
		p.focusedField = 0
		if p.useProfile && len(p.profiles) > 0 {
			p.updateRolesForProfile()
		}
	case "v":
		// Toggle command preview
		p.showPreview = !p.showPreview
	case "r":
		// Refresh profiles
		p.loadProfiles()
	case "tab":
		p.focusedField = (p.focusedField + 1) % maxField
	case "shift+tab":
		p.focusedField = (p.focusedField - 1 + maxField) % maxField
	case "up":
		p.handleUpKey()
	case "down":
		p.handleDownKey()
	case " ":
		p.handleSpaceKey()
	case "backspace":
		p.handleBackspace()
	default:
		if len(msg.String()) == 1 {
			p.handleChar(msg.String())
		}
	}
	return p, nil
}

func (p *ClientPanel) handleUpKey() {
	switch p.focusedField {
	case 2: // scenario/profile
		if p.useProfile {
			if p.profileIndex > 0 {
				p.profileIndex--
				p.updateRolesForProfile()
			}
		} else {
			if p.scenario > 0 {
				p.scenario--
			}
		}
	case 3: // role (profile mode) or mode preset (scenario mode)
		if p.useProfile {
			if p.roleIndex > 0 {
				p.roleIndex--
			}
		} else {
			if p.modePreset > 0 {
				p.modePreset--
				p.applyModePreset()
			}
		}
	case 4: // mode preset (profile mode only)
		if p.useProfile && p.modePreset > 0 {
			p.modePreset--
			p.applyModePreset()
		}
	case 10: // protocol variant (shifted for profile mode)
		if p.protocolVariant > 0 {
			p.protocolVariant--
		}
	case 12: // firewall vendor (shifted for profile mode)
		if p.firewallVendor > 0 {
			p.firewallVendor--
		}
	}
}

func (p *ClientPanel) handleDownKey() {
	switch p.focusedField {
	case 2: // scenario/profile
		if p.useProfile {
			if p.profileIndex < len(p.profiles)-1 {
				p.profileIndex++
				p.updateRolesForProfile()
			}
		} else {
			if p.scenario < len(clientScenarios)-1 {
				p.scenario++
			}
		}
	case 3: // role (profile mode) or mode preset (scenario mode)
		if p.useProfile {
			if p.roleIndex < len(p.roles)-1 {
				p.roleIndex++
			}
		} else {
			if p.modePreset < len(ui.ModePresets)-1 {
				p.modePreset++
				p.applyModePreset()
			}
		}
	case 4: // mode preset (profile mode only)
		if p.useProfile && p.modePreset < len(ui.ModePresets)-1 {
			p.modePreset++
			p.applyModePreset()
		}
	case 10: // protocol variant (shifted for profile mode)
		if p.protocolVariant < len(protocolVariants)-1 {
			p.protocolVariant++
		}
	case 12: // firewall vendor (shifted for profile mode)
		if p.firewallVendor < len(firewallVendors)-1 {
			p.firewallVendor++
		}
	}
}

func (p *ClientPanel) handleSpaceKey() {
	// Field offset for profile mode (role adds 1 to all indices)
	advOffset := 0
	if p.useProfile {
		advOffset = 1
	}

	// PCAP field is at index 4 (or 5 with profile mode)
	pcapFieldIdx := 4 + advOffset

	switch p.focusedField {
	case pcapFieldIdx: // PCAP enabled (always visible)
		p.pcapEnabled = !p.pcapEnabled
		if p.pcapEnabled {
			p.updateAutoDetectedInterface()
		}
	case 7 + advOffset: // CIP Energy (advanced)
		p.cipEnergy = !p.cipEnergy
	case 8 + advOffset: // CIP Safety (advanced)
		p.cipSafety = !p.cipSafety
	case 9 + advOffset: // CIP Motion (advanced)
		p.cipMotion = !p.cipMotion
	}
}

func (p *ClientPanel) applyModePreset() {
	presets := ui.ModePresets
	if p.modePreset >= 0 && p.modePreset < len(presets) {
		preset := presets[p.modePreset]
		if preset.Name != "Custom" {
			p.duration = strconv.Itoa(preset.Duration)
			p.interval = strconv.Itoa(preset.Interval)
		}
	}
}

func (p *ClientPanel) handleBackspace() {
	// Field offset for profile mode
	advOffset := 0
	if p.useProfile {
		advOffset = 1
	}
	switch p.focusedField {
	case 0: // Target IP
		if len(p.targetIP) > 0 {
			p.targetIP = p.targetIP[:len(p.targetIP)-1]
			if p.pcapEnabled {
				p.updateAutoDetectedInterface()
			}
		}
	case 1: // Port
		if len(p.port) > 0 {
			p.port = p.port[:len(p.port)-1]
		}
	case 5 + advOffset: // Duration (in advanced mode)
		if len(p.duration) > 0 {
			p.duration = p.duration[:len(p.duration)-1]
		}
	case 6 + advOffset: // Interval (in advanced mode)
		if len(p.interval) > 0 {
			p.interval = p.interval[:len(p.interval)-1]
		}
	case 12 + advOffset: // Target tags (in advanced mode)
		if len(p.targetTags) > 0 {
			p.targetTags = p.targetTags[:len(p.targetTags)-1]
		}
	}
}

func (p *ClientPanel) handleChar(ch string) {
	// Field offset for profile mode
	advOffset := 0
	if p.useProfile {
		advOffset = 1
	}
	switch p.focusedField {
	case 0: // Target IP
		if ch == "." || (ch >= "0" && ch <= "9") {
			p.targetIP += ch
			if p.pcapEnabled {
				p.updateAutoDetectedInterface()
			}
		}
	case 1: // Port
		if ch >= "0" && ch <= "9" {
			p.port += ch
		}
	case 5 + advOffset: // Duration (advanced)
		if ch >= "0" && ch <= "9" {
			p.duration += ch
			p.modePreset = 3 // Switch to Custom
		}
	case 6 + advOffset: // Interval (advanced)
		if ch >= "0" && ch <= "9" {
			p.interval += ch
			p.modePreset = 3 // Switch to Custom
		}
	case 12 + advOffset: // Target tags (in advanced mode)
		// Allow letters, numbers, commas, underscores, hyphens for tag list
		if (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") ||
			(ch >= "0" && ch <= "9") || ch == "," || ch == "_" || ch == "-" {
			p.targetTags += ch
		}
	}
}

func (p *ClientPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "x":
		// Cancel the running operation
		if p.runCancel != nil {
			p.runCancel()
		}
		p.mode = PanelResult
		elapsed := time.Since(*p.startTime)
		p.result = &CommandResult{
			Output:   fmt.Sprintf("Stopped by user after %v", elapsed.Round(time.Second)),
			ExitCode: 1,
		}
	case "l":
		// Toggle log view
		p.showLog = !p.showLog
		p.logScroll = 0
	case "up", "k":
		// Scroll log up
		if p.showLog && p.logScroll > 0 {
			p.logScroll--
		}
	case "down", "j":
		// Scroll log down
		if p.showLog && p.logScroll < len(p.logLines)-10 {
			p.logScroll++
		}
	case "g":
		// Go to top of log
		if p.showLog {
			p.logScroll = 0
		}
	case "G":
		// Go to bottom of log
		if p.showLog && len(p.logLines) > 10 {
			p.logScroll = len(p.logLines) - 10
		}
	}
	return p, nil
}

func (p *ClientPanel) updateResult(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		p.mode = PanelIdle
		p.result = nil
	case "r":
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.stats = StatsUpdate{}
		p.statsHistory = nil
	}
	return p, nil
}

func (p *ClientPanel) View(width int, focused bool) string {
	return p.ViewContent(width, focused)
}

// ViewContent returns the panel content without a box wrapper.
func (p *ClientPanel) ViewContent(width int, focused bool) string {
	switch p.mode {
	case PanelConfig:
		return p.viewConfigContent(width, focused)
	case PanelRunning:
		return p.viewRunningContent(width, focused)
	case PanelResult:
		return p.viewResultContent(width, focused)
	default:
		return p.viewIdleContent(width, focused)
	}
}

// Title returns the panel title based on current mode.
func (p *ClientPanel) Title() string {
	switch p.mode {
	case PanelConfig:
		return "CLIENT (Config)"
	case PanelRunning:
		return "CLIENT (Running)"
	case PanelResult:
		return "CLIENT (Result)"
	default:
		return "CLIENT"
	}
}

func (p *ClientPanel) viewIdleContent(width int, focused bool) string {
	s := p.styles
	var modeInfo string
	if p.useProfile && p.profileIndex < len(p.profiles) {
		prof := p.profiles[p.profileIndex]
		role := "default"
		if p.roleIndex < len(p.roles) {
			role = p.roles[p.roleIndex]
		}
		modeInfo = fmt.Sprintf("Profile: %s (%s)", s.Dim.Render(prof.Name), s.Dim.Render(role))
	} else {
		modeInfo = fmt.Sprintf("Scenario: %s", s.Dim.Render(clientScenarios[p.scenario]))
	}
	content := []string{
		fmt.Sprintf("Target: %s", s.Dim.Render(p.targetIP)),
		modeInfo,
		"Status: " + s.Dim.Render("idle"),
		"",
	}
	if focused {
		content = append(content, s.KeyBinding.Render("[Enter]")+" Configure  "+s.KeyBinding.Render("[a]")+" Advanced")
	} else {
		content = append(content, s.Dim.Render("[c] Configure"))
	}
	return strings.Join(content, "\n")
}

func (p *ClientPanel) viewConfigContent(width int, focused bool) string {
	s := p.styles

	// Calculate column widths for two-column layout
	colWidth := (width - 4) / 2 // Gap of 4 between columns
	if colWidth < 30 {
		colWidth = 30
	}

	// Mode tabs header
	var scenarioTab, profileTab string
	if p.useProfile {
		scenarioTab = s.Dim.Render(" Scenario ")
		profileTab = s.Info.Render("[Profile]")
	} else {
		scenarioTab = s.Info.Render("[Scenario]")
		profileTab = s.Dim.Render(" Profile ")
	}
	header := scenarioTab + " " + profileTab + "    " + s.KeyBinding.Render("[p]") + s.Dim.Render(" switch  ") + s.KeyBinding.Render("[a]") + s.Dim.Render(" advanced")

	// Build left column: connection settings + scenario/profile
	var leftCol []string

	// Target IP field
	if p.focusedField == 0 {
		leftCol = append(leftCol, s.Selected.Render("Target IP")+": "+p.targetIP+s.Cursor.Render("█"))
	} else {
		leftCol = append(leftCol, s.Dim.Render("Target IP")+": "+p.targetIP)
	}

	// Port field
	if p.focusedField == 1 {
		leftCol = append(leftCol, s.Selected.Render("Port")+": "+p.port+s.Cursor.Render("█"))
	} else {
		leftCol = append(leftCol, s.Dim.Render("Port")+": "+p.port)
	}

	leftCol = append(leftCol, "")

	// Scenario or Profile selection
	if p.useProfile {
		leftCol = append(leftCol, s.Header.Render("Profile:")+"  "+s.Dim.Render("[r] refresh"))
		if len(p.profiles) == 0 {
			leftCol = append(leftCol, s.Dim.Render("  (no profiles found)"))
		} else {
			for i, prof := range p.profiles {
				radio := "( )"
				if i == p.profileIndex {
					radio = s.Success.Render("(●)")
				}
				// Show personality type
				pType := "logix"
				if prof.Personality == "adapter" {
					pType = "i/o"
				} else if prof.Personality == "pccc" {
					pType = "pccc"
				}
				label := fmt.Sprintf("%-18s [%s]", prof.Name, pType)
				style := s.Dim
				if p.focusedField == 2 && i == p.profileIndex {
					style = s.Selected
				}
				leftCol = append(leftCol, " "+radio+" "+style.Render(label))
			}
		}

		// Role selection (only shown in profile mode)
		leftCol = append(leftCol, "")
		leftCol = append(leftCol, s.Header.Render("Role:"))
		if len(p.roles) == 0 {
			leftCol = append(leftCol, s.Dim.Render("  (select a profile first)"))
		} else {
			for i, roleName := range p.roles {
				radio := "( )"
				if i == p.roleIndex {
					radio = s.Success.Render("(●)")
				}
				style := s.Dim
				if p.focusedField == 3 && i == p.roleIndex {
					style = s.Selected
				}
				leftCol = append(leftCol, " "+radio+" "+style.Render(roleName))
			}
		}
	} else {
		leftCol = append(leftCol, s.Header.Render("Scenario:"))
		for i, sc := range clientScenarios {
			radio := "( )"
			if i == p.scenario {
				radio = s.Success.Render("(●)")
			}
			style := s.Dim
			if p.focusedField == 2 && i == p.scenario {
				style = s.Selected
			}
			leftCol = append(leftCol, " "+radio+" "+style.Render(sc))
		}
	}

	// Build right column: duration preset + advanced
	var rightCol []string

	// Adjust field index for mode preset based on profile mode
	modePresetField := 3
	if p.useProfile {
		modePresetField = 4
	}

	rightCol = append(rightCol, s.Header.Render("Duration Preset:"))
	presetLabels := clientModePresetLabels()
	for i, preset := range presetLabels {
		radio := "( )"
		if i == p.modePreset {
			radio = s.Success.Render("(●)")
		}
		style := s.Dim
		if p.focusedField == modePresetField && i == p.modePreset {
			style = s.Selected
		}
		rightCol = append(rightCol, " "+radio+" "+style.Render(preset))
	}

	// Advanced options in right column
	if p.showAdvanced {
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Advanced:"))

		// Field offset for profile mode (role adds 1 to all indices)
		// Basic fields: IP(0), Port(1), Scenario/Profile(2), Role?(3), ModePreset(3/4), PCAP(4/5)
		// Advanced starts at 5 (or 6 with profile)
		advOffset := 0
		if p.useProfile {
			advOffset = 1
		}

		// Duration (advanced field 0)
		if p.focusedField == 5+advOffset {
			rightCol = append(rightCol, s.Selected.Render("Duration")+": "+p.duration+"s"+s.Cursor.Render("█"))
		} else {
			rightCol = append(rightCol, s.Dim.Render("Duration")+": "+p.duration+"s")
		}

		// Interval (advanced field 1)
		if p.focusedField == 6+advOffset {
			rightCol = append(rightCol, s.Selected.Render("Interval")+": "+p.interval+"ms"+s.Cursor.Render("█"))
		} else {
			rightCol = append(rightCol, s.Dim.Render("Interval")+": "+p.interval+"ms")
		}

		// CIP Profiles on one line (advanced fields 2,3,4)
		rightCol = append(rightCol, "")
		rightCol = append(rightCol,
			p.renderCheckbox("Energy", p.cipEnergy, p.focusedField == 7+advOffset, s)+" "+
				p.renderCheckbox("Safety", p.cipSafety, p.focusedField == 8+advOffset, s)+" "+
				p.renderCheckbox("Motion", p.cipMotion, p.focusedField == 9+advOffset, s))

		// Protocol variant (advanced field 5)
		if p.focusedField == 10+advOffset {
			rightCol = append(rightCol, s.Selected.Render("Protocol")+": "+s.Info.Render(protocolVariants[p.protocolVariant])+" ▼")
		} else {
			rightCol = append(rightCol, s.Dim.Render("Protocol")+": "+protocolVariants[p.protocolVariant])
		}

		// Firewall vendor (advanced field 6, if firewall scenario)
		if clientScenarios[p.scenario] == "firewall" {
			if p.focusedField == 11+advOffset {
				rightCol = append(rightCol, s.Selected.Render("FW Vendor")+": "+s.Warning.Render(firewallVendors[p.firewallVendor])+" ▼")
			} else {
				rightCol = append(rightCol, s.Dim.Render("FW Vendor")+": "+firewallVendors[p.firewallVendor])
			}
		}

		// Target tags filter (advanced field 7)
		rightCol = append(rightCol, "")
		tagsDisplay := p.targetTags
		if tagsDisplay == "" {
			tagsDisplay = "(all)"
		}
		if p.focusedField == 12+advOffset {
			rightCol = append(rightCol, s.Selected.Render("Target Tags")+": "+p.targetTags+s.Cursor.Render("█"))
		} else {
			rightCol = append(rightCol, s.Dim.Render("Target Tags")+": "+tagsDisplay)
		}
	}

	// Merge columns side by side
	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// Pad columns to same length
	maxRows := len(leftCol)
	if len(rightCol) > maxRows {
		maxRows = len(rightCol)
	}
	for len(leftCol) < maxRows {
		leftCol = append(leftCol, "")
	}
	for len(rightCol) < maxRows {
		rightCol = append(rightCol, "")
	}

	// Join columns
	for i := 0; i < maxRows; i++ {
		left := leftCol[i]
		right := rightCol[i]
		// Pad left column to fixed width
		leftWidth := lipgloss.Width(left)
		if leftWidth < colWidth {
			left += strings.Repeat(" ", colWidth-leftWidth)
		}
		lines = append(lines, left+"  "+right)
	}

	// PCAP capture section (always visible)
	lines = append(lines, "")
	lines = append(lines, s.Dim.Render("───────────────────────────────────────────────────────────"))

	// Determine PCAP field index
	pcapFieldIdx := 4 // After scenario/profile + mode preset
	if p.useProfile {
		pcapFieldIdx = 5 // +1 for role field
	}

	pcapCheck := "[ ]"
	if p.pcapEnabled {
		pcapCheck = s.Success.Render("[x]")
	}
	pcapLine := fmt.Sprintf("%s PCAP Capture", pcapCheck)
	if p.pcapEnabled {
		pcapFile := filepath.Base(p.generatePcapFilename())
		ifaceDisplay := p.autoDetectedInterface
		if p.pcapInterface != "" {
			ifaceDisplay = p.pcapInterface
		} else if ifaceDisplay == "" {
			ifaceDisplay = "auto"
		} else {
			ifaceDisplay += " (auto)"
		}
		pcapLine += fmt.Sprintf(": %s  %s %s", s.Dim.Render(pcapFile), s.Dim.Render("iface:"), s.Info.Render(ifaceDisplay))
	}
	if p.focusedField == pcapFieldIdx {
		lines = append(lines, s.Selected.Render(pcapLine))
	} else {
		lines = append(lines, pcapLine)
	}

	// Command preview section
	if p.showPreview {
		lines = append(lines, "")
		lines = append(lines, s.Header.Render("Command Preview:"))
		cfg := p.BuildRunConfig("")
		args := cfg.BuildCommandArgs()
		cmdStr := strings.Join(args, " ")
		// Wrap long command
		if len(cmdStr) > 80 {
			lines = append(lines, s.Dim.Render(cmdStr[:80]))
			lines = append(lines, s.Dim.Render("  "+cmdStr[80:]))
		} else {
			lines = append(lines, s.Dim.Render(cmdStr))
		}
	}

	lines = append(lines, "")
	previewHint := s.KeyBinding.Render("[v]") + " Preview"
	if p.showPreview {
		previewHint = s.KeyBinding.Render("[v]") + " Hide Preview"
	}
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Start  "+s.KeyBinding.Render("[Tab]")+" Next  "+previewHint+"  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return strings.Join(lines, "\n")
}

func (p *ClientPanel) renderCheckbox(label string, checked bool, focused bool, s Styles) string {
	box := "[ ]"
	if checked {
		box = s.Success.Render("[✓]")
	}
	if focused {
		return box + " " + s.Selected.Render(label)
	}
	return box + " " + s.Dim.Render(label)
}

func (p *ClientPanel) viewRunningContent(width int, focused bool) string {
	s := p.styles

	elapsed := time.Since(*p.startTime)

	// Parse duration for progress display
	durationSec, _ := strconv.Atoi(p.duration)
	if durationSec == 0 {
		durationSec = 300
	}
	totalDuration := time.Duration(durationSec) * time.Second
	remaining := totalDuration - elapsed
	if remaining < 0 {
		remaining = 0
	}

	// Calculate progress percentage
	progress := float64(elapsed) / float64(totalDuration) * 100
	if progress > 100 {
		progress = 100
	}

	// If showing log view, display log output
	if p.showLog {
		return p.viewLogContent(width, elapsed, durationSec, progress)
	}

	// Calculate success rate
	successRate := 0.0
	if p.stats.TotalRequests > 0 {
		successRate = float64(p.stats.SuccessfulRequests) / float64(p.stats.TotalRequests) * 100
	}

	scenarioName := clientScenarios[p.scenario]
	if p.useProfile && p.profileIndex < len(p.profiles) {
		prof := p.profiles[p.profileIndex]
		role := "default"
		if p.roleIndex < len(p.roles) {
			role = p.roles[p.roleIndex]
		}
		scenarioName = fmt.Sprintf("%s (%s)", prof.Name, role)
	}

	lines := []string{
		s.Running.Render("● RUNNING"),
		"",
		fmt.Sprintf("Target:   %s:%s", p.targetIP, p.port),
		fmt.Sprintf("Mode:     %s", scenarioName),
		fmt.Sprintf("Progress: %s / %s (%.0f%%)", formatDuration(elapsed.Seconds()), formatDuration(float64(durationSec)), progress),
		fmt.Sprintf("Remain:   %s", formatDuration(remaining.Seconds())),
		"",
	}

	// Stats in a grid layout
	statsLine1 := fmt.Sprintf("Requests: %-8d  Success: %s",
		p.stats.TotalRequests,
		s.Success.Render(fmt.Sprintf("%-6d", p.stats.SuccessfulRequests)))
	statsLine2 := fmt.Sprintf("Rate:     %.1f%%     Errors:  %s",
		successRate,
		s.Error.Render(fmt.Sprintf("%-6d", p.stats.TotalErrors)))
	lines = append(lines, statsLine1)
	lines = append(lines, statsLine2)

	// Average latency
	if p.avgLatency > 0 {
		lines = append(lines, fmt.Sprintf("Latency:  %.2fms", p.avgLatency))
	}

	// Last response
	if p.lastResponse != "" {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Last: ")+p.lastResponse)
	}

	// Mini sparkline
	if len(p.statsHistory) > 0 {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Req/s: ")+renderMiniSparkline(p.statsHistory, width-10, s))
	}

	// Recent errors
	if len(p.recentErrors) > 0 {
		lines = append(lines, "")
		lines = append(lines, s.Error.Render("Recent Errors:"))
		for i, err := range p.recentErrors {
			if i >= 3 {
				break
			}
			lines = append(lines, "  "+s.Dim.Render(err))
		}
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Esc/x]")+" Stop  "+s.KeyBinding.Render("[l]")+" Log  "+s.KeyBinding.Render("[Space]")+" Pause")

	return strings.Join(lines, "\n")
}

// viewLogContent displays the log output view.
func (p *ClientPanel) viewLogContent(width int, elapsed time.Duration, durationSec int, progress float64) string {
	s := p.styles

	lines := []string{
		s.Running.Render("● RUNNING") + " " + s.Dim.Render("(Log View)"),
		"",
		fmt.Sprintf("Progress: %s / %s (%.0f%%)", formatDuration(elapsed.Seconds()), formatDuration(float64(durationSec)), progress),
		"",
		s.Header.Render("─── Output Log ───"),
	}

	// Calculate how many lines we can show
	maxDisplayLines := 15
	if len(p.logLines) == 0 {
		lines = append(lines, s.Dim.Render("  (no output yet)"))
	} else {
		// Get visible portion of log
		startIdx := p.logScroll
		endIdx := startIdx + maxDisplayLines
		if endIdx > len(p.logLines) {
			endIdx = len(p.logLines)
		}
		if startIdx >= len(p.logLines) {
			startIdx = 0
			if len(p.logLines) < maxDisplayLines {
				endIdx = len(p.logLines)
			} else {
				endIdx = maxDisplayLines
			}
		}

		for i := startIdx; i < endIdx; i++ {
			line := p.logLines[i]
			// Truncate long lines
			if len(line) > width-4 {
				line = line[:width-7] + "..."
			}
			lines = append(lines, "  "+s.Dim.Render(line))
		}

		// Show scroll position
		if len(p.logLines) > maxDisplayLines {
			scrollInfo := fmt.Sprintf("  [%d-%d of %d lines]", startIdx+1, endIdx, len(p.logLines))
			lines = append(lines, s.Dim.Render(scrollInfo))
		}
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Esc/x]")+" Stop  "+s.KeyBinding.Render("[l]")+" Stats  "+s.KeyBinding.Render("[↑↓]")+" Scroll")

	return strings.Join(lines, "\n")
}

func (p *ClientPanel) viewResultContent(width int, focused bool) string {
	s := p.styles

	status := s.Success.Render("✓ Completed")
	if p.result != nil && p.result.ExitCode != 0 {
		if p.result.Err != nil && p.result.Err == context.Canceled {
			status = s.Warning.Render("⊘ Stopped")
		} else {
			status = s.Error.Render("✗ Failed")
		}
	}

	lines := []string{
		status,
		"",
	}

	// Show output message if available (filtered to remove JSON stats)
	if p.result != nil && p.result.Output != "" {
		cleanOutput := filterOutputForDisplay(p.result.Output)
		if cleanOutput != "" {
			lines = append(lines, s.Dim.Render(cleanOutput))
			lines = append(lines, "")
		}
	}

	lines = append(lines,
		fmt.Sprintf("Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Success: %s", s.Success.Render(fmt.Sprintf("%d", p.stats.SuccessfulRequests))),
		fmt.Sprintf("Errors: %s", s.Error.Render(fmt.Sprintf("%d", p.stats.TotalErrors))),
		"",
		s.KeyBinding.Render("[Enter/Esc]") + " Dismiss  " + s.KeyBinding.Render("[r]") + " Re-run",
	)

	return strings.Join(lines, "\n")
}

func (p *ClientPanel) renderBox(title, content string, width int, focused bool, accentColor lipgloss.Color) string {
	borderColor := DefaultTheme.Border
	if focused {
		borderColor = accentColor
	}

	innerWidth := width - 4
	titleBar := p.renderTitleBar(title, innerWidth)

	contentLines := strings.Split(content, "\n")
	var paddedLines []string
	for _, line := range contentLines {
		lineWidth := lipgloss.Width(line)
		if lineWidth < innerWidth {
			line += strings.Repeat(" ", innerWidth-lineWidth)
		}
		paddedLines = append(paddedLines, line)
	}

	var result strings.Builder
	result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("╭") + titleBar + lipgloss.NewStyle().Foreground(borderColor).Render("╮") + "\n")
	for _, line := range paddedLines {
		result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("│ ") + line + lipgloss.NewStyle().Foreground(borderColor).Render(" │") + "\n")
	}
	result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("╰" + strings.Repeat("─", innerWidth) + "╯"))

	return result.String()
}

func (p *ClientPanel) renderTitleBar(title string, width int) string {
	titleText := " " + title + " "
	titleLen := lipgloss.Width(titleText)
	remaining := width - titleLen - 1
	if remaining < 0 {
		remaining = 0
	}
	return lipgloss.NewStyle().Foreground(DefaultTheme.Border).Render("─") +
		p.styles.Header.Render(titleText) +
		lipgloss.NewStyle().Foreground(DefaultTheme.Border).Render(strings.Repeat("─", remaining))
}

// UpdateStats updates the panel with new stats.
func (p *ClientPanel) UpdateStats(stats StatsUpdate) {
	p.stats = stats
	p.statsHistory = append(p.statsHistory, float64(stats.TotalRequests))
	if len(p.statsHistory) > 30 {
		p.statsHistory = p.statsHistory[1:]
	}
}

// SetResult sets the result and transitions to result mode.
func (p *ClientPanel) SetResult(result CommandResult) {
	p.result = &result
	p.mode = PanelResult
}

// AddLogLine adds a line to the log buffer.
func (p *ClientPanel) AddLogLine(line string) {
	p.logLines = append(p.logLines, line)
	if len(p.logLines) > p.maxLogLines {
		p.logLines = p.logLines[len(p.logLines)-p.maxLogLines:]
	}
}

// ClearLog clears the log buffer.
func (p *ClientPanel) ClearLog() {
	p.logLines = make([]string, 0)
	p.logScroll = 0
	p.showLog = false
}

// --------------------------------------------------------------------------
// ServerPanel
// --------------------------------------------------------------------------

// ServerPanel handles the server operation panel.
type ServerPanel struct {
	mode         PanelMode
	focusedField int
	styles       Styles

	// Mode selection
	useProfile   bool
	profileIndex int
	profiles     []profile.ProfileInfo

	// Config fields
	listenAddr  string
	port        string
	personality int
	opMode      int // Operating mode

	// Advanced options
	showAdvanced       bool
	cipEnergy          bool
	cipSafety          bool
	cipMotion          bool
	udpIO              bool
	udpPort            string
	multicastIO        bool
	multicastGroup     string
	multicastInterface string

	// Fault injection (advanced)
	faultEnabled         bool
	latencyBaseMs        string
	latencyJitterMs      string
	dropResponseEveryN   string
	closeConnEveryN      string

	// Session policy (advanced)
	maxSessions      string
	maxSessionsPerIP string
	sessionTimeoutMs string

	// Identity customization (advanced)
	vendorID    string
	deviceType  string
	productCode string
	productName string

	// Modbus configuration (advanced)
	modbusEnabled   bool
	modbusCIPTunnel bool
	modbusPort      string

	// PCAP capture
	pcapEnabled           bool
	pcapInterface         string // User-selected interface (empty = auto)
	autoDetectedInterface string // Auto-detected interface for display

	// Command preview
	showPreview bool

	// Running stats
	stats         StatsUpdate
	connections   []string
	recentReqs    []string
	statsHistory  []float64
	startTime     *time.Time
	endTime       *time.Time // Recorded when server stops

	// Run control
	runCtx    context.Context
	runCancel context.CancelFunc
	runDir    string // Directory for run artifacts

	// Result
	result *CommandResult

	// Log viewer
	viewingLog bool
	logScroll  int
}

var serverPersonalities = []string{"adapter", "logix_like", "pccc", "minimal"}
var serverOpModes = []string{"baseline", "realistic", "dpi-torture", "perf"}

// NewServerPanel creates a new server panel.
func NewServerPanel(styles Styles) *ServerPanel {
	sp := &ServerPanel{
		mode:           PanelIdle,
		styles:         styles,
		listenAddr:     "0.0.0.0",
		port:           "44818",
		udpPort:        "2222",
		multicastGroup: "239.192.1.0",
		recentReqs:     make([]string, 0),
		// Fault injection defaults
		latencyBaseMs:      "0",
		latencyJitterMs:    "0",
		dropResponseEveryN: "0",
		closeConnEveryN:    "0",
		// Session policy defaults
		maxSessions:      "256",
		maxSessionsPerIP: "64",
		sessionTimeoutMs: "60000",
		// Identity defaults (empty = use defaults)
		vendorID:    "",
		deviceType:  "",
		productCode: "",
		productName: "",
		// Modbus defaults
		modbusPort: "502",
	}
	sp.loadProfiles()
	sp.updateAutoDetectedInterface()
	return sp
}

// loadProfiles loads available profiles from the profiles directory.
func (p *ServerPanel) loadProfiles() {
	profiles, err := profile.ListProfilesDefault()
	if err != nil || len(profiles) == 0 {
		profiles, _ = profile.ListProfiles("profiles")
	}
	p.profiles = profiles

	// Set personality based on first profile if available
	if len(profiles) > 0 && p.useProfile {
		if profiles[0].Personality == "adapter" {
			p.personality = 0
		} else if profiles[0].Personality == "logix_like" {
			p.personality = 1
		} else if profiles[0].Personality == "pccc" {
			p.personality = 2
		}
	}
}

// updateAutoDetectedInterface detects the interface for the listen address.
func (p *ServerPanel) updateAutoDetectedInterface() {
	iface, err := netdetect.DetectInterfaceForListen(p.listenAddr)
	if err != nil {
		p.autoDetectedInterface = "unknown"
	} else {
		p.autoDetectedInterface = netdetect.GetDisplayNameForInterface(iface)
	}
}

// generatePcapFilename creates a filename based on current settings.
func (p *ServerPanel) generatePcapFilename() string {
	personality := serverPersonalities[p.personality]
	opMode := serverOpModes[p.opMode]
	timestamp := time.Now().UTC().Format("2006-01-02T150405Z")
	filename := fmt.Sprintf("server_%s_%s_%s.pcap", personality, opMode, timestamp)
	return filepath.Join("pcaps", filename)
}

// BuildRunConfig creates a ServerRunConfig from the current panel settings.
func (p *ServerPanel) BuildRunConfig(workspaceRoot string) ServerRunConfig {
	port, _ := strconv.Atoi(p.port)
	if port == 0 {
		port = 44818
	}

	cfg := ServerRunConfig{
		ListenAddr:  p.listenAddr,
		Port:        port,
		Personality: serverPersonalities[p.personality],
	}

	if p.useProfile && p.profileIndex < len(p.profiles) {
		cfg.Profile = p.profiles[p.profileIndex].Name
	}

	if p.udpIO {
		cfg.EnableUDPIO = true
		udpPort, _ := strconv.Atoi(p.udpPort)
		cfg.UDPPort = udpPort
	}

	if p.multicastIO {
		cfg.MulticastGroup = p.multicastGroup
		cfg.MulticastInterface = p.multicastInterface
	}

	if p.pcapEnabled {
		cfg.PCAPFile = p.generatePcapFilename()
		if p.pcapInterface != "" {
			cfg.Interface = p.pcapInterface
		}
	}

	if workspaceRoot != "" {
		cfg.OutputDir = workspaceRoot
	}

	// Fault injection
	cfg.FaultEnabled = p.faultEnabled
	if p.faultEnabled {
		cfg.LatencyBaseMs, _ = strconv.Atoi(p.latencyBaseMs)
		cfg.LatencyJitterMs, _ = strconv.Atoi(p.latencyJitterMs)
		cfg.DropResponseEveryN, _ = strconv.Atoi(p.dropResponseEveryN)
		cfg.CloseConnEveryN, _ = strconv.Atoi(p.closeConnEveryN)
	}

	// Session policy
	cfg.MaxSessions, _ = strconv.Atoi(p.maxSessions)
	cfg.MaxSessionsPerIP, _ = strconv.Atoi(p.maxSessionsPerIP)
	cfg.SessionTimeoutMs, _ = strconv.Atoi(p.sessionTimeoutMs)

	// Identity customization
	cfg.VendorID, _ = strconv.Atoi(p.vendorID)
	cfg.DeviceType, _ = strconv.Atoi(p.deviceType)
	cfg.ProductCode, _ = strconv.Atoi(p.productCode)
	cfg.ProductName = p.productName

	// Modbus configuration
	cfg.ModbusEnabled = p.modbusEnabled
	cfg.ModbusCIPTunnel = p.modbusCIPTunnel
	if p.modbusEnabled {
		cfg.ModbusPort, _ = strconv.Atoi(p.modbusPort)
	}

	return cfg
}

func (p *ServerPanel) Mode() PanelMode { return p.mode }
func (p *ServerPanel) Name() string    { return "server" }

func (p *ServerPanel) Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd) {
	if !focused {
		return p, nil
	}

	switch p.mode {
	case PanelIdle:
		return p.updateIdle(msg)
	case PanelConfig:
		return p.updateConfig(msg)
	case PanelRunning:
		return p.updateRunning(msg)
	case PanelResult:
		return p.updateResult(msg)
	}
	return p, nil
}

func (p *ServerPanel) updateIdle(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "enter", "s":
		p.mode = PanelConfig
		p.focusedField = 0
	}
	return p, nil
}

func (p *ServerPanel) updateConfig(msg tea.KeyMsg) (Panel, tea.Cmd) {
	// Basic fields: listen, port, personality, op mode, PCAP
	maxField := 5
	if p.showAdvanced {
		// Advanced fields:
		// 5-7: CIP profiles (Energy, Safety, Motion)
		// 8-9: UDP I/O, UDP port
		// 10-12: Multicast I/O, Group, Interface
		// 13-17: Fault injection (enabled, latency base/jitter, drop every N, close every N)
		// 18-20: Session policy (max sessions, per IP, timeout)
		// 21-24: Identity (vendor, device, product code, product name)
		// 25-27: Modbus (enabled, CIP tunnel, port)
		maxField = 28
	}

	switch msg.String() {
	case "esc":
		if p.showAdvanced {
			p.showAdvanced = false
		} else {
			p.mode = PanelIdle
		}
	case "enter":
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.stats = StatsUpdate{}
		p.statsHistory = nil
		p.recentReqs = nil
		// Create cancel context for this run
		p.runCtx, p.runCancel = context.WithCancel(context.Background())
		// Return command to signal model to start server
		return p, func() tea.Msg {
			return startServerRunMsg{config: p.BuildRunConfig("")}
		}
	case "a":
		p.showAdvanced = !p.showAdvanced
		if !p.showAdvanced && p.focusedField > 5 {
			p.focusedField = 0
		}
	case "p":
		p.useProfile = !p.useProfile
		p.focusedField = 0
		if p.useProfile && p.profileIndex < len(p.profiles) {
			// Set personality based on selected profile
			if p.profiles[p.profileIndex].Personality == "adapter" {
				p.personality = 0
			} else if p.profiles[p.profileIndex].Personality == "logix_like" {
				p.personality = 1
			} else if p.profiles[p.profileIndex].Personality == "pccc" {
				p.personality = 2
			}
		}
	case "r":
		// Refresh profiles
		p.loadProfiles()
	case "v":
		// Toggle command preview
		p.showPreview = !p.showPreview
	case "tab":
		p.focusedField = (p.focusedField + 1) % maxField
	case "shift+tab":
		p.focusedField = (p.focusedField - 1 + maxField) % maxField
	case "up":
		switch p.focusedField {
		case 2: // personality/profile
			if p.useProfile {
				if p.profileIndex > 0 {
					p.profileIndex--
					// Update personality based on selected profile
					if p.profiles[p.profileIndex].Personality == "adapter" {
						p.personality = 0
					} else if p.profiles[p.profileIndex].Personality == "logix_like" {
						p.personality = 1
					} else if p.profiles[p.profileIndex].Personality == "pccc" {
						p.personality = 2
					}
				}
			} else {
				if p.personality > 0 {
					p.personality--
				}
			}
		case 3: // op mode
			if p.opMode > 0 {
				p.opMode--
			}
		}
	case "down":
		switch p.focusedField {
		case 2:
			if p.useProfile {
				if p.profileIndex < len(p.profiles)-1 {
					p.profileIndex++
					// Update personality based on selected profile
					if p.profiles[p.profileIndex].Personality == "adapter" {
						p.personality = 0
					} else if p.profiles[p.profileIndex].Personality == "logix_like" {
						p.personality = 1
					} else if p.profiles[p.profileIndex].Personality == "pccc" {
						p.personality = 2
					}
				}
			} else {
				if p.personality < len(serverPersonalities)-1 {
					p.personality++
				}
			}
		case 3:
			if p.opMode < len(serverOpModes)-1 {
				p.opMode++
			}
		}
	case " ":
		switch p.focusedField {
		case 4: // PCAP (basic field)
			p.pcapEnabled = !p.pcapEnabled
			if p.pcapEnabled {
				p.updateAutoDetectedInterface()
			}
		case 5: // CIP Energy (advanced)
			p.cipEnergy = !p.cipEnergy
		case 6: // CIP Safety (advanced)
			p.cipSafety = !p.cipSafety
		case 7: // CIP Motion (advanced)
			p.cipMotion = !p.cipMotion
		case 8: // UDP I/O (advanced)
			p.udpIO = !p.udpIO
		case 10: // Multicast I/O (advanced)
			p.multicastIO = !p.multicastIO
		case 13: // Fault Enabled (advanced)
			p.faultEnabled = !p.faultEnabled
		case 25: // Modbus Enabled (advanced)
			p.modbusEnabled = !p.modbusEnabled
		case 26: // Modbus CIP Tunnel (advanced)
			p.modbusCIPTunnel = !p.modbusCIPTunnel
		}
	case "backspace":
		p.handleBackspace()
	default:
		if len(msg.String()) == 1 {
			p.handleChar(msg.String())
		}
	}
	return p, nil
}

func (p *ServerPanel) handleBackspace() {
	switch p.focusedField {
	case 0:
		if len(p.listenAddr) > 0 {
			p.listenAddr = p.listenAddr[:len(p.listenAddr)-1]
			if p.pcapEnabled {
				p.updateAutoDetectedInterface()
			}
		}
	case 1:
		if len(p.port) > 0 {
			p.port = p.port[:len(p.port)-1]
		}
	case 9: // UDP port (advanced)
		if len(p.udpPort) > 0 {
			p.udpPort = p.udpPort[:len(p.udpPort)-1]
		}
	case 11: // Multicast Group (advanced)
		if len(p.multicastGroup) > 0 {
			p.multicastGroup = p.multicastGroup[:len(p.multicastGroup)-1]
		}
	case 12: // Multicast Interface (advanced)
		if len(p.multicastInterface) > 0 {
			p.multicastInterface = p.multicastInterface[:len(p.multicastInterface)-1]
		}
	// Fault injection fields
	case 14: // Latency Base Ms
		if len(p.latencyBaseMs) > 0 {
			p.latencyBaseMs = p.latencyBaseMs[:len(p.latencyBaseMs)-1]
		}
	case 15: // Latency Jitter Ms
		if len(p.latencyJitterMs) > 0 {
			p.latencyJitterMs = p.latencyJitterMs[:len(p.latencyJitterMs)-1]
		}
	case 16: // Drop Response Every N
		if len(p.dropResponseEveryN) > 0 {
			p.dropResponseEveryN = p.dropResponseEveryN[:len(p.dropResponseEveryN)-1]
		}
	case 17: // Close Conn Every N
		if len(p.closeConnEveryN) > 0 {
			p.closeConnEveryN = p.closeConnEveryN[:len(p.closeConnEveryN)-1]
		}
	// Session policy fields
	case 18: // Max Sessions
		if len(p.maxSessions) > 0 {
			p.maxSessions = p.maxSessions[:len(p.maxSessions)-1]
		}
	case 19: // Max Sessions Per IP
		if len(p.maxSessionsPerIP) > 0 {
			p.maxSessionsPerIP = p.maxSessionsPerIP[:len(p.maxSessionsPerIP)-1]
		}
	case 20: // Session Timeout Ms
		if len(p.sessionTimeoutMs) > 0 {
			p.sessionTimeoutMs = p.sessionTimeoutMs[:len(p.sessionTimeoutMs)-1]
		}
	// Identity fields
	case 21: // Vendor ID
		if len(p.vendorID) > 0 {
			p.vendorID = p.vendorID[:len(p.vendorID)-1]
		}
	case 22: // Device Type
		if len(p.deviceType) > 0 {
			p.deviceType = p.deviceType[:len(p.deviceType)-1]
		}
	case 23: // Product Code
		if len(p.productCode) > 0 {
			p.productCode = p.productCode[:len(p.productCode)-1]
		}
	case 24: // Product Name
		if len(p.productName) > 0 {
			p.productName = p.productName[:len(p.productName)-1]
		}
	// Modbus fields
	case 27: // Modbus Port
		if len(p.modbusPort) > 0 {
			p.modbusPort = p.modbusPort[:len(p.modbusPort)-1]
		}
	}
}

func (p *ServerPanel) handleChar(ch string) {
	isDigit := ch >= "0" && ch <= "9"
	switch p.focusedField {
	case 0:
		if ch == "." || isDigit {
			p.listenAddr += ch
			if p.pcapEnabled {
				p.updateAutoDetectedInterface()
			}
		}
	case 1:
		if isDigit {
			p.port += ch
		}
	case 9: // UDP port (advanced)
		if isDigit {
			p.udpPort += ch
		}
	case 11: // Multicast Group (advanced)
		if ch == "." || isDigit {
			p.multicastGroup += ch
		}
	case 12: // Multicast Interface (advanced)
		p.multicastInterface += ch
	// Fault injection fields (numeric)
	case 14: // Latency Base Ms
		if isDigit {
			p.latencyBaseMs += ch
		}
	case 15: // Latency Jitter Ms
		if isDigit {
			p.latencyJitterMs += ch
		}
	case 16: // Drop Response Every N
		if isDigit {
			p.dropResponseEveryN += ch
		}
	case 17: // Close Conn Every N
		if isDigit {
			p.closeConnEveryN += ch
		}
	// Session policy fields (numeric)
	case 18: // Max Sessions
		if isDigit {
			p.maxSessions += ch
		}
	case 19: // Max Sessions Per IP
		if isDigit {
			p.maxSessionsPerIP += ch
		}
	case 20: // Session Timeout Ms
		if isDigit {
			p.sessionTimeoutMs += ch
		}
	// Identity fields
	case 21: // Vendor ID (numeric)
		if isDigit {
			p.vendorID += ch
		}
	case 22: // Device Type (numeric)
		if isDigit {
			p.deviceType += ch
		}
	case 23: // Product Code (numeric)
		if isDigit {
			p.productCode += ch
		}
	case 24: // Product Name (text)
		p.productName += ch
	// Modbus fields
	case 27: // Modbus Port (numeric)
		if isDigit {
			p.modbusPort += ch
		}
	}
}

func (p *ServerPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "x":
		// Cancel the running server
		if p.runCancel != nil {
			p.runCancel()
		}
		now := time.Now()
		p.endTime = &now
		p.mode = PanelResult
		elapsed := time.Since(*p.startTime)
		p.result = &CommandResult{
			Output:   fmt.Sprintf("Server stopped after %v", elapsed.Round(time.Second)),
			ExitCode: 0,
		}
	}
	return p, nil
}

func (p *ServerPanel) updateResult(msg tea.KeyMsg) (Panel, tea.Cmd) {
	if p.viewingLog {
		// Log viewer mode
		switch msg.String() {
		case "esc", "q":
			p.viewingLog = false
			p.logScroll = 0
		case "up", "k":
			if p.logScroll > 0 {
				p.logScroll--
			}
		case "down", "j":
			p.logScroll++
		case "pgup":
			p.logScroll -= 10
			if p.logScroll < 0 {
				p.logScroll = 0
			}
		case "pgdown":
			p.logScroll += 10
		case "home":
			p.logScroll = 0
		case "end":
			if p.result != nil {
				lines := strings.Split(p.result.Output, "\n")
				p.logScroll = len(lines) - 10
				if p.logScroll < 0 {
					p.logScroll = 0
				}
			}
		}
		return p, nil
	}

	switch msg.String() {
	case "esc", "enter":
		p.mode = PanelIdle
		p.result = nil
		p.viewingLog = false
	case "r":
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.endTime = nil // Clear from previous run
		p.stats = StatsUpdate{}
		p.statsHistory = nil
		p.viewingLog = false
	case "l":
		if p.result != nil && p.result.Output != "" {
			p.viewingLog = true
			p.logScroll = 0
		}
	}
	return p, nil
}

func (p *ServerPanel) View(width int, focused bool) string {
	return p.ViewContent(width, focused)
}

// ViewContent returns the panel content without a box wrapper.
func (p *ServerPanel) ViewContent(width int, focused bool) string {
	switch p.mode {
	case PanelConfig:
		return p.viewConfigContent(width, focused)
	case PanelRunning:
		return p.viewRunningContent(width, focused)
	case PanelResult:
		if p.viewingLog {
			return p.viewLogContent(width, focused)
		}
		return p.viewResultContent(width, focused)
	default:
		return p.viewIdleContent(width, focused)
	}
}

func (p *ServerPanel) viewLogContent(width int, focused bool) string {
	s := p.styles

	if p.result == nil || p.result.Output == "" {
		return s.Dim.Render("No log output available.\n\n") +
			s.KeyBinding.Render("[Esc]") + " Back"
	}

	lines := strings.Split(p.result.Output, "\n")
	totalLines := len(lines)

	// Calculate visible lines (leave room for header and footer)
	visibleLines := 15
	if p.logScroll > totalLines-visibleLines {
		p.logScroll = totalLines - visibleLines
	}
	if p.logScroll < 0 {
		p.logScroll = 0
	}

	endIdx := p.logScroll + visibleLines
	if endIdx > totalLines {
		endIdx = totalLines
	}

	var content []string
	content = append(content, s.Header.Render("Server Log")+" "+s.Dim.Render(fmt.Sprintf("(%d-%d of %d)", p.logScroll+1, endIdx, totalLines)))
	content = append(content, "")

	for i := p.logScroll; i < endIdx; i++ {
		line := lines[i]
		// Truncate lines that are too wide
		maxWidth := width - 4
		if len(line) > maxWidth {
			line = line[:maxWidth-3] + "..."
		}
		// Highlight error lines
		if strings.Contains(strings.ToLower(line), "error") || strings.Contains(strings.ToLower(line), "failed") {
			content = append(content, s.Error.Render(line))
		} else if strings.Contains(strings.ToLower(line), "warn") {
			content = append(content, s.Warning.Render(line))
		} else {
			content = append(content, s.Dim.Render(line))
		}
	}

	content = append(content, "")
	content = append(content, s.KeyBinding.Render("[↑/↓]")+" Scroll  "+s.KeyBinding.Render("[PgUp/PgDn]")+" Page  "+s.KeyBinding.Render("[Esc]")+" Back")

	return strings.Join(content, "\n")
}

// Title returns the panel title based on current mode.
func (p *ServerPanel) Title() string {
	switch p.mode {
	case PanelConfig:
		return "SERVER (Config)"
	case PanelRunning:
		return "SERVER (Listening)"
	case PanelResult:
		if p.viewingLog {
			return "SERVER (Logs)"
		}
		return "SERVER (Stopped)"
	default:
		return "SERVER"
	}
}

func (p *ServerPanel) viewIdleContent(width int, focused bool) string {
	s := p.styles
	var modeInfo string
	if p.useProfile && p.profileIndex < len(p.profiles) {
		prof := p.profiles[p.profileIndex]
		modeInfo = fmt.Sprintf("Profile: %s (%s)", s.Dim.Render(prof.Name), s.Dim.Render(prof.Personality))
	} else {
		modeInfo = fmt.Sprintf("Personality: %s", s.Dim.Render(serverPersonalities[p.personality]))
	}
	content := []string{
		fmt.Sprintf("Listen: %s:%s", s.Dim.Render(p.listenAddr), s.Dim.Render(p.port)),
		modeInfo,
		"Status: " + s.Dim.Render("stopped"),
		"",
	}
	if focused {
		content = append(content, s.KeyBinding.Render("[Enter]")+" Configure  "+s.KeyBinding.Render("[a]")+" Advanced")
	} else {
		content = append(content, s.Dim.Render("[s] Configure"))
	}
	return strings.Join(content, "\n")
}

func (p *ServerPanel) viewConfigContent(width int, focused bool) string {
	s := p.styles

	// Calculate column widths for two-column layout
	colWidth := (width - 4) / 2
	if colWidth < 30 {
		colWidth = 30
	}

	// Mode tabs header
	var personalityTab, profileTab string
	if p.useProfile {
		personalityTab = s.Dim.Render(" Personality ")
		profileTab = s.Info.Render("[Profile]")
	} else {
		personalityTab = s.Info.Render("[Personality]")
		profileTab = s.Dim.Render(" Profile ")
	}
	header := personalityTab + " " + profileTab + "    " + s.KeyBinding.Render("[p]") + s.Dim.Render(" switch  ") + s.KeyBinding.Render("[a]") + s.Dim.Render(" advanced")

	// Build left column: listen settings + personality/profile
	var leftCol []string

	// Listen addr field
	if p.focusedField == 0 {
		leftCol = append(leftCol, s.Selected.Render("Listen")+": "+p.listenAddr+s.Cursor.Render("█"))
	} else {
		leftCol = append(leftCol, s.Dim.Render("Listen")+": "+p.listenAddr)
	}

	// Port field
	if p.focusedField == 1 {
		leftCol = append(leftCol, s.Selected.Render("Port")+": "+p.port+s.Cursor.Render("█"))
	} else {
		leftCol = append(leftCol, s.Dim.Render("Port")+": "+p.port)
	}

	leftCol = append(leftCol, "")

	// Personality or Profile selection
	if p.useProfile {
		leftCol = append(leftCol, s.Header.Render("Profile:")+"  "+s.Dim.Render("[r] refresh"))
		if len(p.profiles) == 0 {
			leftCol = append(leftCol, s.Dim.Render("  (no profiles found)"))
		} else {
			for i, prof := range p.profiles {
				radio := "( )"
				if i == p.profileIndex {
					radio = s.Success.Render("(●)")
				}
				// Show personality type
				pType := "logix"
				if prof.Personality == "adapter" {
					pType = "i/o"
				} else if prof.Personality == "pccc" {
					pType = "pccc"
				}
				label := fmt.Sprintf("%-18s [%s]", prof.Name, pType)
				style := s.Dim
				if p.focusedField == 2 && i == p.profileIndex {
					style = s.Selected
				}
				leftCol = append(leftCol, " "+radio+" "+style.Render(label))
			}
		}
	} else {
		leftCol = append(leftCol, s.Header.Render("Personality:"))
		for i, pers := range serverPersonalities {
			radio := "( )"
			if i == p.personality {
				radio = s.Success.Render("(●)")
			}
			style := s.Dim
			if p.focusedField == 2 && i == p.personality {
				style = s.Selected
			}
			leftCol = append(leftCol, " "+radio+" "+style.Render(pers))
		}
	}

	// Build right column: operating mode + advanced
	var rightCol []string

	rightCol = append(rightCol, s.Header.Render("Operating Mode:"))
	for i, mode := range serverOpModes {
		radio := "( )"
		if i == p.opMode {
			radio = s.Success.Render("(●)")
		}
		style := s.Dim
		if p.focusedField == 3 && i == p.opMode {
			style = s.Selected
		}
		rightCol = append(rightCol, " "+radio+" "+style.Render(mode))
	}

	// Advanced options in right column
	if p.showAdvanced {
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Advanced:"))

		// CIP Profiles on one line (advanced fields 0,1,2)
		rightCol = append(rightCol,
			p.renderCheckbox("Energy", p.cipEnergy, p.focusedField == 5, s)+" "+
				p.renderCheckbox("Safety", p.cipSafety, p.focusedField == 6, s)+" "+
				p.renderCheckbox("Motion", p.cipMotion, p.focusedField == 7, s))

		// UDP I/O (advanced fields 3,4)
		rightCol = append(rightCol, p.renderCheckbox("UDP I/O", p.udpIO, p.focusedField == 8, s))
		if p.udpIO {
			if p.focusedField == 9 {
				rightCol = append(rightCol, "  "+s.Selected.Render("UDP Port")+": "+p.udpPort+s.Cursor.Render("█"))
			} else {
				rightCol = append(rightCol, "  "+s.Dim.Render("UDP Port")+": "+p.udpPort)
			}
		}

		// Multicast I/O (advanced fields 10,11,12)
		rightCol = append(rightCol, p.renderCheckbox("Multicast I/O", p.multicastIO, p.focusedField == 10, s))
		if p.multicastIO {
			if p.focusedField == 11 {
				rightCol = append(rightCol, "  "+s.Selected.Render("Group")+": "+p.multicastGroup+s.Cursor.Render("█"))
			} else {
				rightCol = append(rightCol, "  "+s.Dim.Render("Group")+": "+p.multicastGroup)
			}
			if p.focusedField == 12 {
				rightCol = append(rightCol, "  "+s.Selected.Render("Interface")+": "+p.multicastInterface+s.Cursor.Render("█"))
			} else {
				iface := p.multicastInterface
				if iface == "" {
					iface = "(auto)"
				}
				rightCol = append(rightCol, "  "+s.Dim.Render("Interface")+": "+iface)
			}
		}

		// Fault Injection (advanced fields 13-17)
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Fault Injection:"))
		rightCol = append(rightCol, p.renderCheckbox("Enable Faults", p.faultEnabled, p.focusedField == 13, s))
		if p.faultEnabled {
			rightCol = append(rightCol, p.renderTextField("Latency Base (ms)", p.latencyBaseMs, p.focusedField == 14, s))
			rightCol = append(rightCol, p.renderTextField("Latency Jitter (ms)", p.latencyJitterMs, p.focusedField == 15, s))
			rightCol = append(rightCol, p.renderTextField("Drop Every N", p.dropResponseEveryN, p.focusedField == 16, s))
			rightCol = append(rightCol, p.renderTextField("Close Every N", p.closeConnEveryN, p.focusedField == 17, s))
		}

		// Session Policy (advanced fields 18-20)
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Session Policy:"))
		rightCol = append(rightCol, p.renderTextField("Max Sessions", p.maxSessions, p.focusedField == 18, s))
		rightCol = append(rightCol, p.renderTextField("Max Per IP", p.maxSessionsPerIP, p.focusedField == 19, s))
		rightCol = append(rightCol, p.renderTextField("Timeout (ms)", p.sessionTimeoutMs, p.focusedField == 20, s))

		// Identity Customization (advanced fields 21-24)
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Identity Object:"))
		rightCol = append(rightCol, p.renderTextField("Vendor ID", p.vendorID, p.focusedField == 21, s))
		rightCol = append(rightCol, p.renderTextField("Device Type", p.deviceType, p.focusedField == 22, s))
		rightCol = append(rightCol, p.renderTextField("Product Code", p.productCode, p.focusedField == 23, s))
		rightCol = append(rightCol, p.renderTextField("Product Name", p.productName, p.focusedField == 24, s))

		// Modbus Configuration (advanced fields 25-27)
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Modbus:"))
		rightCol = append(rightCol, p.renderCheckbox("Enable Modbus", p.modbusEnabled, p.focusedField == 25, s))
		if p.modbusEnabled {
			rightCol = append(rightCol, p.renderCheckbox("CIP Tunnel (0x44)", p.modbusCIPTunnel, p.focusedField == 26, s))
			rightCol = append(rightCol, p.renderTextField("TCP Port", p.modbusPort, p.focusedField == 27, s))
		}
	}

	// Merge columns side by side
	var lines []string
	lines = append(lines, header)
	lines = append(lines, "")

	// Pad columns to same length
	maxRows := len(leftCol)
	if len(rightCol) > maxRows {
		maxRows = len(rightCol)
	}
	for len(leftCol) < maxRows {
		leftCol = append(leftCol, "")
	}
	for len(rightCol) < maxRows {
		rightCol = append(rightCol, "")
	}

	// Join columns
	for i := 0; i < maxRows; i++ {
		left := leftCol[i]
		right := rightCol[i]
		// Pad left column to fixed width
		leftWidth := lipgloss.Width(left)
		if leftWidth < colWidth {
			left += strings.Repeat(" ", colWidth-leftWidth)
		}
		lines = append(lines, left+"  "+right)
	}

	// PCAP capture section (always visible)
	lines = append(lines, "")
	lines = append(lines, s.Dim.Render("───────────────────────────────────────────────────────────"))

	pcapCheck := "[ ]"
	if p.pcapEnabled {
		pcapCheck = s.Success.Render("[x]")
	}
	pcapLine := fmt.Sprintf("%s PCAP Capture", pcapCheck)
	if p.pcapEnabled {
		pcapFile := filepath.Base(p.generatePcapFilename())
		ifaceDisplay := p.autoDetectedInterface
		if p.pcapInterface != "" {
			ifaceDisplay = p.pcapInterface
		} else if ifaceDisplay == "" {
			ifaceDisplay = "auto"
		} else {
			ifaceDisplay += " (auto)"
		}
		pcapLine += fmt.Sprintf(": %s  %s %s", s.Dim.Render(pcapFile), s.Dim.Render("iface:"), s.Info.Render(ifaceDisplay))
	}
	if p.focusedField == 4 {
		lines = append(lines, s.Selected.Render(pcapLine))
	} else {
		lines = append(lines, pcapLine)
	}

	// Command preview section
	if p.showPreview {
		lines = append(lines, "")
		lines = append(lines, s.Header.Render("Command Preview:"))
		cfg := p.BuildRunConfig("")
		args := cfg.BuildCommandArgs()
		cmdStr := strings.Join(args, " ")
		// Wrap long command
		if len(cmdStr) > 80 {
			lines = append(lines, s.Dim.Render(cmdStr[:80]))
			lines = append(lines, s.Dim.Render("  "+cmdStr[80:]))
		} else {
			lines = append(lines, s.Dim.Render(cmdStr))
		}
	}

	lines = append(lines, "")
	previewHint := s.KeyBinding.Render("[v]") + " Preview"
	if p.showPreview {
		previewHint = s.KeyBinding.Render("[v]") + " Hide Preview"
	}
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Start  "+s.KeyBinding.Render("[Tab]")+" Next  "+previewHint+"  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return strings.Join(lines, "\n")
}

func (p *ServerPanel) renderCheckbox(label string, checked bool, focused bool, s Styles) string {
	box := "[ ]"
	if checked {
		box = s.Success.Render("[✓]")
	}
	if focused {
		return box + " " + s.Selected.Render(label)
	}
	return box + " " + s.Dim.Render(label)
}

func (p *ServerPanel) renderTextField(label string, value string, focused bool, s Styles) string {
	displayVal := value
	if displayVal == "" {
		displayVal = "(default)"
	}
	if focused {
		return "  " + s.Selected.Render(label) + ": " + value + s.Cursor.Render("█")
	}
	return "  " + s.Dim.Render(label) + ": " + displayVal
}

func (p *ServerPanel) viewRunningContent(width int, focused bool) string {
	s := p.styles

	elapsed := time.Since(*p.startTime)

	personalityName := serverPersonalities[p.personality]
	if p.useProfile && p.profileIndex < len(p.profiles) {
		prof := p.profiles[p.profileIndex]
		personalityName = fmt.Sprintf("%s (%s)", prof.Name, prof.Personality)
	}

	lines := []string{
		s.Running.Render("● LISTENING"),
		"",
		fmt.Sprintf("Address:     %s:%s", p.listenAddr, p.port),
		fmt.Sprintf("Personality: %s", personalityName),
		fmt.Sprintf("Mode:        %s", serverOpModes[p.opMode]),
		fmt.Sprintf("Uptime:      %s", formatDuration(elapsed.Seconds())),
		"",
	}

	// Stats
	lines = append(lines, fmt.Sprintf("Connections: %-6d  Requests: %d", p.stats.ActiveConnections, p.stats.TotalRequests))
	lines = append(lines, fmt.Sprintf("Errors:      %s", s.Error.Render(fmt.Sprintf("%d", p.stats.TotalErrors))))

	// UDP I/O status if enabled
	if p.udpIO {
		lines = append(lines, fmt.Sprintf("UDP I/O:     %s", s.Info.Render("port "+p.udpPort)))
	}

	// Multicast status if enabled
	if p.multicastIO {
		lines = append(lines, fmt.Sprintf("Multicast:   %s", s.Info.Render(p.multicastGroup)))
	}

	// Recent requests
	if len(p.recentReqs) > 0 {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Recent Requests:"))
		for i, req := range p.recentReqs {
			if i >= 4 {
				break
			}
			lines = append(lines, "  "+s.Dim.Render(req))
		}
	}

	// Mini sparkline
	if len(p.statsHistory) > 0 {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Req/s: ")+renderMiniSparkline(p.statsHistory, width-10, s))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Esc/x]")+" Stop")

	return strings.Join(lines, "\n")
}

func (p *ServerPanel) viewResultContent(width int, focused bool) string {
	s := p.styles

	var uptime string
	if p.startTime != nil && p.endTime != nil {
		// Show final duration (start to end), not continuing to count
		uptime = formatDuration(p.endTime.Sub(*p.startTime).Seconds())
	} else if p.startTime != nil {
		// Fallback if endTime not set
		uptime = formatDuration(time.Since(*p.startTime).Seconds())
	}

	// Determine status based on result
	status := s.Dim.Render("■ Stopped")
	if p.result != nil {
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ Failed (exit " + fmt.Sprintf("%d", p.result.ExitCode) + ")")
		} else if p.result.Err != nil {
			status = s.Warning.Render("⊘ Stopped")
		}
	}

	lines := []string{
		status,
		"",
		fmt.Sprintf("Uptime: %s", uptime),
		fmt.Sprintf("Total Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Total Connections: %d", p.stats.TotalConnections),
	}

	// Show error/output if available
	if p.result != nil {
		if p.result.Err != nil {
			lines = append(lines, "")
			lines = append(lines, s.Error.Render("Error: "+p.result.Err.Error()))
		}
		if p.result.Output != "" {
			lines = append(lines, "")
			// Show last few lines of output (most relevant for errors)
			output := filterOutputForDisplay(p.result.Output)
			if output != "" {
				outputLines := strings.Split(output, "\n")
				// Show last 5 lines max
				if len(outputLines) > 5 {
					outputLines = outputLines[len(outputLines)-5:]
				}
				lines = append(lines, s.Dim.Render("Output:"))
				for _, ol := range outputLines {
					if ol != "" {
						// Truncate long lines
						if len(ol) > 60 {
							ol = ol[:57] + "..."
						}
						lines = append(lines, "  "+s.Dim.Render(ol))
					}
				}
			}
		}
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter/Esc]")+" Dismiss  "+s.KeyBinding.Render("[r]")+" Restart  "+s.KeyBinding.Render("[l]")+" View Log")

	return strings.Join(lines, "\n")
}

func (p *ServerPanel) renderBox(title, content string, width int, focused bool, accentColor lipgloss.Color) string {
	borderColor := DefaultTheme.Border
	if focused {
		borderColor = accentColor
	}

	innerWidth := width - 4
	titleBar := p.renderTitleBar(title, innerWidth)

	contentLines := strings.Split(content, "\n")
	var paddedLines []string
	for _, line := range contentLines {
		lineWidth := lipgloss.Width(line)
		if lineWidth < innerWidth {
			line += strings.Repeat(" ", innerWidth-lineWidth)
		}
		paddedLines = append(paddedLines, line)
	}

	var result strings.Builder
	result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("╭") + titleBar + lipgloss.NewStyle().Foreground(borderColor).Render("╮") + "\n")
	for _, line := range paddedLines {
		result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("│ ") + line + lipgloss.NewStyle().Foreground(borderColor).Render(" │") + "\n")
	}
	result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("╰" + strings.Repeat("─", innerWidth) + "╯"))

	return result.String()
}

func (p *ServerPanel) renderTitleBar(title string, width int) string {
	titleText := " " + title + " "
	titleLen := lipgloss.Width(titleText)
	remaining := width - titleLen - 1
	if remaining < 0 {
		remaining = 0
	}
	return lipgloss.NewStyle().Foreground(DefaultTheme.Border).Render("─") +
		p.styles.Header.Render(titleText) +
		lipgloss.NewStyle().Foreground(DefaultTheme.Border).Render(strings.Repeat("─", remaining))
}

// UpdateStats updates the panel with new stats.
func (p *ServerPanel) UpdateStats(stats StatsUpdate) {
	p.stats = stats
	p.statsHistory = append(p.statsHistory, float64(stats.TotalRequests))
	if len(p.statsHistory) > 30 {
		p.statsHistory = p.statsHistory[1:]
	}
}

// SetResult sets the result and transitions to result mode.
func (p *ServerPanel) SetResult(result CommandResult) {
	p.result = &result
	now := time.Now()
	p.endTime = &now
	p.mode = PanelResult
}

// --------------------------------------------------------------------------
// PCAPPanel - Enhanced with Diff, Viewer, Visual Metrics
// --------------------------------------------------------------------------

// PCAPPanel handles the PCAP tools panel with enhanced features.
type PCAPPanel struct {
	mode         PanelMode
	modeIndex    int // 0=Summary, 1=Report, 2=Coverage, 3=Replay, 4=Rewrite, 5=Dump, 6=Diff
	selectedFile int
	files        []string // Full paths to PCAP files
	fileNames    []string // Display names (just filename)
	fileSizes    []int64  // File sizes in bytes
	styles       Styles
	focusedField int

	// File browser state
	browserActive bool
	browserPath   string   // Current directory in browser
	browserItems  []string // Items in current directory
	browserIndex  int      // Selected item in browser

	// For diff mode
	diffFile1     int
	diffFile2     int
	diffSelectIdx int // 0=file1, 1=file2

	// For replay mode
	replayTargetIP   string
	replayRewriteIP  bool
	replayRewriteMAC bool
	replayTiming     bool
	replayAppOnly    bool

	// For dump mode
	dumpServiceCode string

	// For viewer mode
	viewerOffset int
	selectedPkt  int
	packets      []PacketInfo

	// Display options
	showVisual bool // Toggle between visual and text metrics

	// Directory mode (for Report/Coverage)
	useDirectory bool
	directory    string

	// Analysis results
	analysis     *PCAPAnalysis
	diffAnalysis *PCAPDiffAnalysis

	// Command result
	result       *CommandResult
	resultScroll int // Scroll offset for result view
	resultLines  []string // Parsed/formatted result lines

	// Track last analyzed file
	lastAnalyzedPath string
}

// PCAPAnalysis holds results from PCAP analysis.
type PCAPAnalysis struct {
	Filename       string
	TotalPackets   int
	ENIPPackets    int
	CIPRequests    int
	CIPResponses   int
	UniqueServices int
	Duration       time.Duration
	BytesTotal     int64
	AvgPacketSize  int
	PacketsPerSec  float64
	TopServices    []ServiceCount
	ErrorCount     int
}

// PCAPDiffAnalysis holds diff comparison results.
type PCAPDiffAnalysis struct {
	File1          string
	File2          string
	File1Packets   int
	File2Packets   int
	CommonServices int
	OnlyInFile1    []string
	OnlyInFile2    []string
	ServiceDiffs   []ServiceDiff
}

// ServiceCount tracks service usage.
type ServiceCount struct {
	Name  string
	Code  int
	Count int
}

// ServiceDiff shows differences between files.
type ServiceDiff struct {
	Service    string
	File1Count int
	File2Count int
	Diff       int
}

// PacketInfo represents a single packet for the viewer.
type PacketInfo struct {
	Number    int
	Timestamp string
	Protocol  string
	Length    int
	Service   string
	Direction string // "REQ" or "RSP"
	Status    string // "OK", "ERR"
	Summary   string
}

var pcapModes = []string{"Summary", "Report", "Coverage", "Replay", "Rewrite", "Dump", "Diff", "Multi-Proto", "Validate"}

// NewPCAPPanel creates a new PCAP panel.
func NewPCAPPanel(styles Styles) *PCAPPanel {
	p := &PCAPPanel{
		mode:       PanelIdle,
		styles:     styles,
		files:      []string{},
		fileNames:  []string{},
		showVisual: true,
		packets:    generateSamplePackets(),
	}
	p.RefreshFiles("")
	return p
}

// RefreshFiles scans for PCAP files in known locations.
func (p *PCAPPanel) RefreshFiles(workspaceRoot string) {
	p.files = []string{}
	p.fileNames = []string{}
	p.fileSizes = []int64{}

	// Directories to scan for PCAP files
	var searchDirs []string

	// Add workspace pcaps if available
	if workspaceRoot != "" {
		searchDirs = append(searchDirs, filepath.Join(workspaceRoot, "pcaps"))
		// Also check repo root relative to workspace
		repoRoot := filepath.Dir(filepath.Dir(workspaceRoot))
		searchDirs = append(searchDirs, filepath.Join(repoRoot, "pcaps"))
	}

	// Add common relative paths
	searchDirs = append(searchDirs, "pcaps", "pcaps/stress", "pcaps/validation_generated")

	// Try to find pcaps relative to executable
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		searchDirs = append(searchDirs,
			filepath.Join(exeDir, "pcaps"),
			filepath.Join(exeDir, "..", "pcaps"),
		)
	}

	seen := make(map[string]bool)
	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pcap") {
				continue
			}
			fullPath := filepath.Join(dir, e.Name())
			// Normalize path to avoid duplicates
			if absPath, err := filepath.Abs(fullPath); err == nil {
				fullPath = absPath
			}
			if seen[fullPath] {
				continue
			}
			seen[fullPath] = true
			p.files = append(p.files, fullPath)
			p.fileNames = append(p.fileNames, e.Name())
			// Get file size
			var size int64
			if info, err := os.Stat(fullPath); err == nil {
				size = info.Size()
			}
			p.fileSizes = append(p.fileSizes, size)
		}
	}

	// If no files found, add placeholder
	if len(p.files) == 0 {
		p.files = []string{}
		p.fileNames = []string{"(no pcap files found)"}
		return
	}

	// Select last analyzed file if available, otherwise default to ENIP.pcap
	p.selectedFile = 0
	for i, path := range p.files {
		if p.lastAnalyzedPath != "" && path == p.lastAnalyzedPath {
			p.selectedFile = i
			return
		}
	}
	// Default to ENIP.pcap if found
	for i, name := range p.fileNames {
		if name == "ENIP.pcap" {
			p.selectedFile = i
			return
		}
	}
}

func generateSamplePackets() []PacketInfo {
	return []PacketInfo{
		{1, "00:00.001", "CIP", 78, "GetAttr", "REQ", "OK", "Identity.1.1"},
		{2, "00:00.003", "CIP", 124, "GetAttr", "RSP", "OK", "Vendor=0x0001"},
		{3, "00:00.015", "CIP", 82, "FwdOpen", "REQ", "OK", "T->O RPI=10ms"},
		{4, "00:00.018", "CIP", 96, "FwdOpen", "RSP", "OK", "ConnID=0x1234"},
		{5, "00:00.025", "CIP", 64, "ReadTag", "REQ", "OK", "Tag=Counter"},
		{6, "00:00.027", "CIP", 72, "ReadTag", "RSP", "OK", "Value=42"},
		{7, "00:00.035", "CIP", 68, "WriteTag", "REQ", "OK", "Tag=Output"},
		{8, "00:00.038", "CIP", 56, "WriteTag", "RSP", "OK", "Success"},
		{9, "00:00.050", "CIP", 64, "ReadTag", "REQ", "OK", "Tag=Status"},
		{10, "00:00.052", "CIP", 72, "ReadTag", "RSP", "ERR", "Path Error"},
	}
}

func (p *PCAPPanel) Mode() PanelMode { return p.mode }
func (p *PCAPPanel) Name() string    { return "pcap" }

func (p *PCAPPanel) getMaxFields() int {
	switch p.modeIndex {
	case 3: // Replay - file, target IP, 4 checkboxes
		return 6
	case 5: // Dump - file, service code
		return 2
	case 6: // Diff - handled separately
		return 2
	default: // Summary, Report, Coverage, Rewrite - just file selection
		return 1
	}
}

func (p *PCAPPanel) resetModeSelections() {
	if p.modeIndex == 6 { // Diff mode
		p.diffFile1 = 0
		p.diffFile2 = 1
		p.diffSelectIdx = 0
	}
}

// Title returns the panel title based on current mode.
func (p *PCAPPanel) Title() string {
	switch p.mode {
	case PanelConfig:
		return "PCAP (" + pcapModes[p.modeIndex] + ")"
	case PanelRunning:
		return "PCAP (Analyzing)"
	case PanelResult:
		return "PCAP Results"
	default:
		return "PCAP"
	}
}

func (p *PCAPPanel) Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd) {
	if !focused {
		return p, nil
	}

	switch p.mode {
	case PanelIdle:
		return p.updateIdle(msg)
	case PanelConfig:
		return p.updateConfig(msg)
	case PanelRunning:
		return p.updateRunning(msg)
	case PanelResult:
		return p.updateResult(msg)
	}
	return p, nil
}

func (p *PCAPPanel) updateIdle(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "enter", "p":
		p.mode = PanelConfig
	}
	return p, nil
}

func (p *PCAPPanel) updateConfig(msg tea.KeyMsg) (Panel, tea.Cmd) {
	// Handle browser mode separately
	if p.browserActive {
		return p.updateBrowser(msg)
	}

	// Get max fields for current mode
	maxField := p.getMaxFields()

	switch msg.String() {
	case "b":
		// Open file browser
		p.openBrowser()
		return p, nil
	case "esc":
		p.mode = PanelIdle
	case "enter":
		cmd := p.runAnalysis()
		return p, cmd
	case "[", "left":
		// Previous mode
		p.modeIndex = (p.modeIndex - 1 + len(pcapModes)) % len(pcapModes)
		p.focusedField = 0
		p.resetModeSelections()
	case "]", "right":
		// Next mode
		p.modeIndex = (p.modeIndex + 1) % len(pcapModes)
		p.focusedField = 0
		p.resetModeSelections()
	case "tab":
		// In diff mode, tab switches between file1 and file2 selection
		if p.modeIndex == 6 {
			p.diffSelectIdx = (p.diffSelectIdx + 1) % 2
		} else if maxField > 1 {
			p.focusedField = (p.focusedField + 1) % maxField
		}
	case "shift+tab":
		// In diff mode, shift+tab also switches between file1 and file2
		if p.modeIndex == 6 {
			p.diffSelectIdx = (p.diffSelectIdx + 1) % 2
		} else if maxField > 1 && p.focusedField > 0 {
			p.focusedField--
		}
	case "up":
		if p.modeIndex == 6 { // Diff mode
			if p.diffSelectIdx == 0 && p.diffFile1 > 0 {
				p.diffFile1--
			} else if p.diffSelectIdx == 1 && p.diffFile2 > 0 {
				p.diffFile2--
			}
		} else if p.focusedField == 0 {
			if p.selectedFile > 0 {
				p.selectedFile--
			}
		}
	case "down":
		if p.modeIndex == 6 { // Diff mode
			if p.diffSelectIdx == 0 && p.diffFile1 < len(p.files)-1 {
				p.diffFile1++
			} else if p.diffSelectIdx == 1 && p.diffFile2 < len(p.files)-1 {
				p.diffFile2++
			}
		} else if p.focusedField == 0 {
			if p.selectedFile < len(p.files)-1 {
				p.selectedFile++
			}
		}
	case " ":
		// Space toggles checkboxes in replay mode
		if p.modeIndex == 3 {
			switch p.focusedField {
			case 2:
				p.replayRewriteIP = !p.replayRewriteIP
			case 3:
				p.replayRewriteMAC = !p.replayRewriteMAC
			case 4:
				p.replayTiming = !p.replayTiming
			case 5:
				p.replayAppOnly = !p.replayAppOnly
			}
		}
	case "backspace":
		if p.modeIndex == 3 && p.focusedField == 1 { // Replay target IP
			if len(p.replayTargetIP) > 0 {
				p.replayTargetIP = p.replayTargetIP[:len(p.replayTargetIP)-1]
			}
		} else if p.modeIndex == 5 && p.focusedField == 1 { // Dump service code
			if len(p.dumpServiceCode) > 0 {
				p.dumpServiceCode = p.dumpServiceCode[:len(p.dumpServiceCode)-1]
			}
		}
	default:
		if len(msg.String()) == 1 {
			ch := msg.String()
			if p.modeIndex == 3 && p.focusedField == 1 { // Replay target IP
				if ch == "." || (ch >= "0" && ch <= "9") {
					p.replayTargetIP += ch
				}
			} else if p.modeIndex == 5 && p.focusedField == 1 { // Dump service code
				if ch == "x" || ch == "X" || (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F") {
					p.dumpServiceCode += ch
				}
			}
		}
	}
	return p, nil
}

func (p *PCAPPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
	}
	return p, nil
}

func (p *PCAPPanel) updateResult(msg tea.KeyMsg) (Panel, tea.Cmd) {
	maxScroll := len(p.resultLines) - 20
	if maxScroll < 0 {
		maxScroll = 0
	}

	switch msg.String() {
	case "esc", "enter":
		// Track last analyzed file before clearing
		if len(p.files) > p.selectedFile {
			p.lastAnalyzedPath = p.files[p.selectedFile]
		}
		p.mode = PanelIdle
		p.analysis = nil
		p.diffAnalysis = nil
		p.result = nil
		p.resultLines = nil
		p.resultScroll = 0
	case "v":
		// Toggle visual/text mode
		p.showVisual = !p.showVisual
	case "up", "k":
		// Scroll up
		if p.resultScroll > 0 {
			p.resultScroll--
		} else if p.modeIndex == 2 && p.selectedPkt > 0 { // Viewer mode
			p.selectedPkt--
		}
	case "down", "j":
		// Scroll down
		if p.resultScroll < maxScroll {
			p.resultScroll++
		} else if p.modeIndex == 2 && p.selectedPkt < len(p.packets)-1 { // Viewer mode
			p.selectedPkt++
		}
	case "pageup", "ctrl+u":
		p.resultScroll -= 10
		if p.resultScroll < 0 {
			p.resultScroll = 0
		}
		if p.modeIndex == 2 {
			p.selectedPkt -= 5
			if p.selectedPkt < 0 {
				p.selectedPkt = 0
			}
		}
	case "pagedown", "ctrl+d":
		p.resultScroll += 10
		if p.resultScroll > maxScroll {
			p.resultScroll = maxScroll
		}
		if p.modeIndex == 2 {
			p.selectedPkt += 5
			if p.selectedPkt >= len(p.packets) {
				p.selectedPkt = len(p.packets) - 1
			}
		}
	case "g":
		// Go to top
		p.resultScroll = 0
	case "G":
		// Go to bottom
		p.resultScroll = maxScroll
	}
	return p, nil
}

// openBrowser initializes the file browser at the workspace pcaps directory.
func (p *PCAPPanel) openBrowser() {
	p.browserActive = true
	p.browserIndex = 0

	// Start in workspace pcaps dir, fallback to /pcaps or current dir
	startDir := "pcaps"
	if len(p.files) > 0 {
		// Use directory of first file
		startDir = filepath.Dir(p.files[0])
	}

	p.browserPath = startDir
	p.refreshBrowserItems()
}

// refreshBrowserItems loads directory contents for the browser.
func (p *PCAPPanel) refreshBrowserItems() {
	p.browserItems = []string{}

	// Add parent directory option
	p.browserItems = append(p.browserItems, "..")

	entries, err := os.ReadDir(p.browserPath)
	if err != nil {
		return
	}

	// Add directories first
	for _, e := range entries {
		if e.IsDir() {
			p.browserItems = append(p.browserItems, e.Name()+"/")
		}
	}

	// Then add .pcap files
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".pcap") {
			p.browserItems = append(p.browserItems, e.Name())
		}
	}
}

// updateBrowser handles input in file browser mode.
func (p *PCAPPanel) updateBrowser(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		p.browserActive = false
	case "up":
		if p.browserIndex > 0 {
			p.browserIndex--
		}
	case "down":
		if p.browserIndex < len(p.browserItems)-1 {
			p.browserIndex++
		}
	case "enter":
		if p.browserIndex < len(p.browserItems) {
			item := p.browserItems[p.browserIndex]
			if item == ".." {
				// Go up one directory
				p.browserPath = filepath.Dir(p.browserPath)
				p.browserIndex = 0
				p.refreshBrowserItems()
			} else if strings.HasSuffix(item, "/") {
				// Enter directory
				p.browserPath = filepath.Join(p.browserPath, strings.TrimSuffix(item, "/"))
				p.browserIndex = 0
				p.refreshBrowserItems()
			} else {
				// Select file
				fullPath := filepath.Join(p.browserPath, item)
				if absPath, err := filepath.Abs(fullPath); err == nil {
					fullPath = absPath
				}
				// Add to files list if not already present
				found := false
				for i, f := range p.files {
					if f == fullPath {
						p.selectedFile = i
						found = true
						break
					}
				}
				if !found {
					p.files = append(p.files, fullPath)
					p.fileNames = append(p.fileNames, item)
					// Get file size
					var size int64
					if info, err := os.Stat(fullPath); err == nil {
						size = info.Size()
					}
					p.fileSizes = append(p.fileSizes, size)
					p.selectedFile = len(p.files) - 1
				}
				p.browserActive = false
			}
		}
	case "pageup":
		p.browserIndex -= 10
		if p.browserIndex < 0 {
			p.browserIndex = 0
		}
	case "pagedown":
		p.browserIndex += 10
		if p.browserIndex >= len(p.browserItems) {
			p.browserIndex = len(p.browserItems) - 1
		}
	}
	return p, nil
}

func (p *PCAPPanel) runAnalysis() tea.Cmd {
	// Validate we have a file selected
	if len(p.files) == 0 {
		p.mode = PanelResult
		p.result = &CommandResult{
			Output:   "No PCAP files available",
			ExitCode: 1,
		}
		return nil
	}

	p.mode = PanelRunning

	// Return a command that will start the PCAP operation
	return func() tea.Msg {
		cfg := p.BuildPCAPRunConfig("")
		return startPCAPRunMsg{config: cfg}
	}
}

func (p *PCAPPanel) View(width int, focused bool) string {
	return p.ViewContent(width, focused)
}

// ViewContent returns the panel content without a box wrapper.
func (p *PCAPPanel) ViewContent(width int, focused bool) string {
	switch p.mode {
	case PanelConfig:
		return p.viewConfigContent(width, focused)
	case PanelRunning:
		return p.viewRunningContent(width, focused)
	case PanelResult:
		return p.viewResultContent(width, focused)
	default:
		return p.viewIdleContent(width, focused)
	}
}

// getFileName returns the display name for a file at index.
func (p *PCAPPanel) getFileName(idx int) string {
	if idx < len(p.fileNames) {
		return p.fileNames[idx]
	}
	if idx < len(p.files) {
		return filepath.Base(p.files[idx])
	}
	return "(unknown)"
}

// getFileSize returns formatted file size for a file at index.
func (p *PCAPPanel) getFileSize(idx int) string {
	if idx >= len(p.fileSizes) {
		return ""
	}
	size := p.fileSizes[idx]
	switch {
	case size >= 1024*1024*1024:
		return fmt.Sprintf("%.1fG", float64(size)/(1024*1024*1024))
	case size >= 1024*1024:
		return fmt.Sprintf("%.1fM", float64(size)/(1024*1024))
	case size >= 1024:
		return fmt.Sprintf("%.1fK", float64(size)/1024)
	default:
		return fmt.Sprintf("%dB", size)
	}
}

// getFileEntry returns filename with size for display (name padded, size right-aligned).
func (p *PCAPPanel) getFileEntry(idx int, width int) string {
	name := p.getFileName(idx)
	size := p.getFileSize(idx)

	// Calculate padding (leave room for size + some spacing)
	sizeWidth := len(size) + 2
	maxNameWidth := width - sizeWidth - 4
	if maxNameWidth < 10 {
		maxNameWidth = 10
	}

	// Truncate name if needed
	if len(name) > maxNameWidth {
		name = name[:maxNameWidth-3] + "..."
	}

	padding := width - len(name) - len(size) - 4
	if padding < 1 {
		padding = 1
	}

	return name + strings.Repeat(" ", padding) + p.styles.Dim.Render(size)
}

// viewBrowserContent renders the file browser view.
func (p *PCAPPanel) viewBrowserContent(width int) string {
	s := p.styles
	var lines []string

	lines = append(lines, s.Header.Render("Browse for PCAP file"))
	lines = append(lines, "")

	// Show current path
	pathDisplay := p.browserPath
	if len(pathDisplay) > width-10 {
		pathDisplay = "..." + pathDisplay[len(pathDisplay)-(width-13):]
	}
	lines = append(lines, s.Dim.Render("Path: ")+s.Info.Render(pathDisplay))
	lines = append(lines, "")

	// Show directory contents (scrollable)
	maxVisible := 12
	startIdx := 0
	if p.browserIndex >= maxVisible {
		startIdx = p.browserIndex - maxVisible + 1
	}

	for i := startIdx; i < len(p.browserItems) && i < startIdx+maxVisible; i++ {
		item := p.browserItems[i]
		cursor := "  "
		if i == p.browserIndex {
			cursor = s.Selected.Render("> ")
		}

		// Style directories differently
		if strings.HasSuffix(item, "/") {
			lines = append(lines, cursor+s.Info.Render(item))
		} else if item == ".." {
			lines = append(lines, cursor+s.Dim.Render(item+" (parent)"))
		} else {
			// Show file size for pcap files
			fullPath := filepath.Join(p.browserPath, item)
			var sizeStr string
			if info, err := os.Stat(fullPath); err == nil {
				size := info.Size()
				switch {
				case size >= 1024*1024:
					sizeStr = fmt.Sprintf("%.1fM", float64(size)/(1024*1024))
				case size >= 1024:
					sizeStr = fmt.Sprintf("%.1fK", float64(size)/1024)
				default:
					sizeStr = fmt.Sprintf("%dB", size)
				}
			}
			// Pad name and show size
			name := item
			maxNameLen := width - 12
			if len(name) > maxNameLen {
				name = name[:maxNameLen-3] + "..."
			}
			lines = append(lines, cursor+fmt.Sprintf("%-*s %s", maxNameLen, name, s.Dim.Render(sizeStr)))
		}
	}

	// Show scroll indicator if needed
	if len(p.browserItems) > maxVisible {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render(fmt.Sprintf("  %d/%d items", p.browserIndex+1, len(p.browserItems))))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Select  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewIdleContent(width int, focused bool) string {
	s := p.styles
	content := []string{
		fmt.Sprintf("Mode: %s", s.Dim.Render(pcapModes[p.modeIndex])),
		fmt.Sprintf("Files: %d available", len(p.files)),
	}
	if len(p.files) > 0 {
		content = append(content, fmt.Sprintf("Selected: %s", s.Dim.Render(p.getFileName(p.selectedFile))))
	}
	content = append(content, "")
	if focused {
		content = append(content, s.KeyBinding.Render("[Enter]")+" Open")
	} else {
		content = append(content, s.Dim.Render("[p] Open"))
	}
	return strings.Join(content, "\n")
}

func (p *PCAPPanel) viewConfigContent(width int, focused bool) string {
	s := p.styles
	var lines []string

	// Show file browser if active
	if p.browserActive {
		return p.viewBrowserContent(width)
	}

	// Mode tabs (show first few, indicate more)
	var modeTabs []string
	for i, mode := range pcapModes {
		if i == p.modeIndex {
			modeTabs = append(modeTabs, s.Selected.Render("["+mode+"]"))
		} else {
			modeTabs = append(modeTabs, s.Dim.Render(mode))
		}
	}
	lines = append(lines, strings.Join(modeTabs, " "))
	lines = append(lines, "")

	switch p.modeIndex {
	case 0: // Summary
		lines = append(lines, s.Header.Render("Analyze single PCAP file:"))
		lines = append(lines, "")
		for i := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+p.getFileEntry(i, width-4))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("[b] Browse for file"))

	case 1: // Report
		lines = append(lines, s.Header.Render("Generate directory report:"))
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Directory: ")+s.Info.Render(p.directory))
		if p.directory == "" {
			lines = append(lines, s.Dim.Render("  (uses pcaps/ by default)"))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Output: reports/pcap_report.md"))

	case 2: // Coverage
		lines = append(lines, s.Header.Render("Generate CIP service coverage:"))
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Directory: ")+s.Info.Render(p.directory))
		if p.directory == "" {
			lines = append(lines, s.Dim.Render("  (uses pcaps/ by default)"))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Output: reports/pcap_coverage.md"))

	case 3: // Replay
		lines = append(lines, s.Header.Render("Replay PCAP to target:"))
		lines = append(lines, "")
		// File selection
		for i := range p.files {
			cursor := "  "
			if i == p.selectedFile && p.focusedField == 0 {
				cursor = s.Selected.Render("> ")
			} else if i == p.selectedFile {
				cursor = s.Success.Render("● ")
			}
			lines = append(lines, cursor+p.getFileEntry(i, width-4))
		}
		lines = append(lines, "")
		// Target IP
		label := "Target IP"
		value := p.replayTargetIP
		if p.focusedField == 1 {
			lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render("█"))
		} else {
			lines = append(lines, s.Dim.Render(label)+": "+value)
		}
		// Options
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Options:"))
		lines = append(lines, "  "+p.renderPCAPCheckbox("Rewrite IP", p.replayRewriteIP, p.focusedField == 2, s))
		lines = append(lines, "  "+p.renderPCAPCheckbox("Rewrite MAC", p.replayRewriteMAC, p.focusedField == 3, s))
		lines = append(lines, "  "+p.renderPCAPCheckbox("Preserve timing", p.replayTiming, p.focusedField == 4, s))
		lines = append(lines, "  "+p.renderPCAPCheckbox("App-layer only", p.replayAppOnly, p.focusedField == 5, s))

	case 4: // Rewrite
		lines = append(lines, s.Header.Render("Rewrite PCAP IPs/MACs:"))
		lines = append(lines, "")
		for i := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+p.getFileName(i))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Output: {filename}_rewritten.pcap"))

	case 5: // Dump
		lines = append(lines, s.Header.Render("Hex dump by service code:"))
		lines = append(lines, "")
		// File selection
		for i := range p.files {
			cursor := "  "
			if i == p.selectedFile && p.focusedField == 0 {
				cursor = s.Selected.Render("> ")
			} else if i == p.selectedFile {
				cursor = s.Success.Render("● ")
			}
			lines = append(lines, cursor+p.getFileName(i))
		}
		lines = append(lines, "")
		// Service code
		label := "Service Code"
		value := p.dumpServiceCode
		if value == "" {
			value = "0x0E"
		}
		if p.focusedField == 1 {
			lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render("█"))
		} else {
			lines = append(lines, s.Dim.Render(label)+": "+value)
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Common: 0x0E=GetAttr, 0x52=UnconnSend, 0x54=FwdOpen"))

	case 6: // Diff
		lines = append(lines, s.Header.Render("Compare two PCAP files:"))
		lines = append(lines, "")

		// Two column file selectors
		col1Title := "File 1"
		col2Title := "File 2"
		if p.diffSelectIdx == 0 {
			col1Title = s.Selected.Render("File 1 *")
		} else {
			col2Title = s.Selected.Render("File 2 *")
		}
		lines = append(lines, fmt.Sprintf("  %-20s  %s", col1Title, col2Title))
		lines = append(lines, "  "+strings.Repeat("─", 18)+"  "+strings.Repeat("─", 18))

		for i := 0; i < len(p.files); i++ {
			left := "  "
			right := "  "
			if i == p.diffFile1 {
				if p.diffSelectIdx == 0 {
					left = s.Selected.Render("> ")
				} else {
					left = s.Success.Render("● ")
				}
			}
			if i == p.diffFile2 {
				if p.diffSelectIdx == 1 {
					right = s.Selected.Render("> ")
				} else {
					right = s.Success.Render("● ")
				}
			}
			fileName := p.getFileName(i)
			fileSize := p.getFileSize(i)
			// Truncate filename if needed
			if len(fileName) > 14 {
				fileName = fileName[:11] + "..."
			}
			entry := fmt.Sprintf("%-14s %s", fileName, s.Dim.Render(fileSize))
			lines = append(lines, fmt.Sprintf("%s%-22s  %s%-22s", left, entry, right, entry))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("[b] Browse  [←/→] Switch  [↑/↓] Select"))

	case 7: // Multi-Proto
		lines = append(lines, s.Header.Render("Multi-protocol analysis:"))
		lines = append(lines, "")
		for i := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+p.getFileEntry(i, width-4))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("[b] Browse for file"))
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Analyzes: ENIP, Modbus TCP, DH+"))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[←/→]")+" Mode  "+s.KeyBinding.Render("[Tab]")+" Field  "+s.KeyBinding.Render("[Enter]")+" Run  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) renderPCAPCheckbox(label string, checked bool, focused bool, s Styles) string {
	box := "[ ]"
	if checked {
		box = s.Success.Render("[✓]")
	}
	if focused {
		return box + " " + s.Selected.Render(label)
	}
	return box + " " + s.Dim.Render(label)
}

func (p *PCAPPanel) viewRunningContent(width int, focused bool) string {
	s := p.styles
	lines := []string{
		s.Running.Render("● ANALYZING..."),
		"",
		"Processing packets...",
		"",
		ProgressBar("Progress", 67, width-10, s),
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewResultContent(width int, focused bool) string {
	switch p.modeIndex {
	case 0: // Summary
		return p.viewSummaryResultContent(width, focused)
	case 1, 2: // Report, Coverage
		return p.viewReportResultContent(width, focused)
	case 3: // Replay
		return p.viewReplayResultContent(width, focused)
	case 4: // Rewrite
		return p.viewRewriteResultContent(width, focused)
	case 5: // Dump
		return p.viewDumpResultContent(width, focused)
	case 6: // Diff
		return p.viewDiffResultContent(width, focused)
	case 7: // Multi-Proto
		return p.viewSummaryResultContent(width, focused)
	default:
		return p.viewSummaryResultContent(width, focused)
	}
}

func (p *PCAPPanel) viewReportResultContent(width int, focused bool) string {
	s := p.styles
	modeName := pcapModes[p.modeIndex]

	// If we have command result, show that
	if p.result != nil {
		var lines []string
		status := s.Success.Render("✓ " + modeName + " Complete")
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ " + modeName + " Failed")
		}
		lines = append(lines, status)
		lines = append(lines, "")

		if p.result.Output != "" {
			cleanOutput := filterOutputForDisplay(p.result.Output)
			if cleanOutput != "" {
				lines = append(lines, s.Dim.Render(cleanOutput))
			}
		}

		lines = append(lines, "")
		lines = append(lines, s.KeyBinding.Render("[Esc]")+" Close")
		return strings.Join(lines, "\n")
	}

	outputFile := "reports/pcap_report.md"
	if p.modeIndex == 2 {
		outputFile = "reports/pcap_coverage.md"
	}

	lines := []string{
		s.Success.Render("✓ " + modeName + " Generated"),
		"",
		s.Dim.Render("Output: ") + s.Info.Render(outputFile),
		"",
		s.Dim.Render("Press [o] to open in editor"),
		"",
		s.KeyBinding.Render("[o]") + " Open  " + s.KeyBinding.Render("[Esc]") + " Close",
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewReplayResultContent(width int, focused bool) string {
	s := p.styles

	// If we have command result, show that
	if p.result != nil {
		var lines []string
		status := s.Success.Render("✓ Replay Complete")
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ Replay Failed")
		}
		lines = append(lines, status)
		lines = append(lines, "")

		if p.result.Output != "" {
			cleanOutput := filterOutputForDisplay(p.result.Output)
			if cleanOutput != "" {
				lines = append(lines, s.Dim.Render(cleanOutput))
			}
		}

		lines = append(lines, "")
		lines = append(lines, s.KeyBinding.Render("[Esc]")+" Close")
		return strings.Join(lines, "\n")
	}

	selectedFileName := p.getFileName(p.selectedFile)
	lines := []string{
		s.Success.Render("✓ Replay Complete"),
		"",
		fmt.Sprintf("Target:  %s", p.replayTargetIP),
		fmt.Sprintf("File:    %s", selectedFileName),
		"",
		s.KeyBinding.Render("[Esc]") + " Close",
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewRewriteResultContent(width int, focused bool) string {
	s := p.styles

	// If we have command result, show that
	if p.result != nil {
		var lines []string
		status := s.Success.Render("✓ Rewrite Complete")
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ Rewrite Failed")
		}
		lines = append(lines, status)
		lines = append(lines, "")

		if p.result.Output != "" {
			cleanOutput := filterOutputForDisplay(p.result.Output)
			if cleanOutput != "" {
				lines = append(lines, s.Dim.Render(cleanOutput))
			}
		}

		lines = append(lines, "")
		lines = append(lines, s.KeyBinding.Render("[Esc]")+" Close")
		return strings.Join(lines, "\n")
	}

	selectedFileName := p.getFileName(p.selectedFile)
	outputFile := strings.TrimSuffix(selectedFileName, ".pcap") + "_rewritten.pcap"

	lines := []string{
		s.Success.Render("✓ Rewrite Complete"),
		"",
		s.Dim.Render("Input:  ") + selectedFileName,
		s.Dim.Render("Output: ") + s.Info.Render(outputFile),
		"",
		s.KeyBinding.Render("[Esc]") + " Close",
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewDumpResultContent(width int, focused bool) string {
	s := p.styles
	serviceCode := p.dumpServiceCode
	if serviceCode == "" {
		serviceCode = "all"
	}

	// If we have command result, show that
	if p.result != nil {
		var lines []string
		status := s.Success.Render("✓ Dump Complete")
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ Dump Failed")
		}
		lines = append(lines, status)
		lines = append(lines, "")

		if p.result.Output != "" {
			cleanOutput := filterOutputForDisplay(p.result.Output)
			if cleanOutput != "" {
				lines = append(lines, s.Dim.Render(cleanOutput))
			}
		}

		lines = append(lines, "")
		lines = append(lines, s.KeyBinding.Render("[Esc]")+" Close")
		return strings.Join(lines, "\n")
	}

	selectedFileName := p.getFileName(p.selectedFile)
	lines := []string{
		s.Success.Render("✓ Dump for service " + serviceCode),
		"",
		s.Dim.Render("File: ") + selectedFileName,
		"",
		s.KeyBinding.Render("[Esc]") + " Close",
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewSummaryResultContent(width int, focused bool) string {
	s := p.styles
	maxVisibleLines := 20 // Max lines to show before scrolling

	// If we have command result, show that with nice formatting
	if p.result != nil {
		// Parse and format result if not already done
		if len(p.resultLines) == 0 && p.result.Output != "" {
			p.resultLines = p.formatPCAPOutput(p.result.Output)
		}

		var lines []string

		// Status header
		status := s.Success.Render("✓ Analysis Complete")
		fileName := p.getFileName(p.selectedFile)
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ Analysis Failed")
		}
		lines = append(lines, status+"  "+s.Dim.Render(fileName))
		lines = append(lines, s.Dim.Render(strings.Repeat("─", width-4)))

		// Show formatted output with scrolling
		if len(p.resultLines) > 0 {
			visibleLines := p.resultLines
			totalLines := len(visibleLines)

			// Apply scroll offset
			start := p.resultScroll
			if start > totalLines-maxVisibleLines {
				start = totalLines - maxVisibleLines
			}
			if start < 0 {
				start = 0
			}

			end := start + maxVisibleLines
			if end > totalLines {
				end = totalLines
			}

			visibleLines = p.resultLines[start:end]
			lines = append(lines, visibleLines...)

			// Scroll indicator
			if totalLines > maxVisibleLines {
				scrollPct := float64(start) / float64(totalLines-maxVisibleLines) * 100
				scrollInfo := fmt.Sprintf(" [%d-%d of %d] %.0f%%", start+1, end, totalLines, scrollPct)
				lines = append(lines, "")
				lines = append(lines, s.Dim.Render(scrollInfo))
			}
		}

		lines = append(lines, "")
		helpLine := s.KeyBinding.Render("[↑/↓]") + " Scroll  " +
			s.KeyBinding.Render("[g/G]") + " Top/Bot  " +
			s.KeyBinding.Render("[Esc]") + " Close"
		lines = append(lines, helpLine)
		return strings.Join(lines, "\n")
	}

	// Fallback to old analysis struct if available
	if p.analysis == nil {
		return p.viewIdleContent(width, focused)
	}

	a := p.analysis
	var lines []string

	lines = append(lines, s.Success.Render("✓ Analysis: ")+a.Filename)
	lines = append(lines, "")

	if p.showVisual {
		// Visual metrics with bars
		lines = append(lines, p.renderMetricBar("Packets", float64(a.TotalPackets), 2000, width-4, s))
		lines = append(lines, p.renderMetricBar("CIP Req", float64(a.CIPRequests), 500, width-4, s))
		lines = append(lines, p.renderMetricBar("CIP Rsp", float64(a.CIPResponses), 500, width-4, s))
		lines = append(lines, p.renderMetricBar("Errors", float64(a.ErrorCount), 50, width-4, s))
		lines = append(lines, "")

		// Top services as mini bar chart
		lines = append(lines, s.Header.Render("Top Services:"))
		maxCount := 0
		for _, svc := range a.TopServices {
			if svc.Count > maxCount {
				maxCount = svc.Count
			}
		}
		for _, svc := range a.TopServices[:3] {
			barLen := (svc.Count * 20) / maxCount
			bar := s.Info.Render(strings.Repeat("█", barLen)) + strings.Repeat("░", 20-barLen)
			lines = append(lines, fmt.Sprintf("  %-12s %s %d", svc.Name, bar, svc.Count))
		}
	} else {
		// Text metrics
		lines = append(lines, fmt.Sprintf("Total Packets:  %d", a.TotalPackets))
		lines = append(lines, fmt.Sprintf("ENIP Packets:   %d", a.ENIPPackets))
		lines = append(lines, fmt.Sprintf("CIP Requests:   %d", a.CIPRequests))
		lines = append(lines, fmt.Sprintf("CIP Responses:  %d", a.CIPResponses))
		lines = append(lines, fmt.Sprintf("Unique Services: %d", a.UniqueServices))
		lines = append(lines, fmt.Sprintf("Duration:       %s", a.Duration))
		lines = append(lines, fmt.Sprintf("Bytes Total:    %d", a.BytesTotal))
		lines = append(lines, fmt.Sprintf("Avg Packet:     %d bytes", a.AvgPacketSize))
		lines = append(lines, fmt.Sprintf("Packets/sec:    %.1f", a.PacketsPerSec))
		lines = append(lines, fmt.Sprintf("Errors:         %d", a.ErrorCount))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[v]")+" Toggle View  "+s.KeyBinding.Render("[Esc]")+" Close")

	return strings.Join(lines, "\n")
}

// formatPCAPOutput formats the raw PCAP summary output with colors and structure.
func (p *PCAPPanel) formatPCAPOutput(output string) []string {
	s := p.styles
	var lines []string
	currentSection := ""

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			lines = append(lines, "")
			continue
		}

		// Detect section headers
		if strings.HasSuffix(line, ":") && !strings.Contains(line, "  ") {
			currentSection = strings.TrimSuffix(line, ":")
			lines = append(lines, s.Header.Render(line))
			continue
		}

		// Format based on content
		trimmed := strings.TrimSpace(line)

		// Key: value pairs
		if strings.Contains(trimmed, ":") && !strings.HasPrefix(trimmed, "0x") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Color code based on key/value
				valueStyle := s.Base
				if strings.Contains(strings.ToLower(key), "error") || strings.Contains(strings.ToLower(key), "failed") {
					if value != "0" {
						valueStyle = s.Error
					}
				} else if strings.Contains(strings.ToLower(key), "packet") || strings.Contains(strings.ToLower(key), "request") {
					valueStyle = s.Info
				} else if strings.Contains(strings.ToLower(key), "vendor") || strings.Contains(strings.ToLower(key), "product") {
					valueStyle = s.Success
				}

				indent := "  "
				if !strings.HasPrefix(line, " ") {
					indent = ""
				}
				lines = append(lines, indent+s.Dim.Render(key+":")+valueStyle.Render(" "+value))
				continue
			}
		}

		// Service/command counts (indented items)
		if strings.HasPrefix(line, "  ") && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				count := strings.TrimSpace(parts[1])
				// Color based on section
				nameStyle := s.Base
				if currentSection == "Command Counts" {
					nameStyle = s.Info
				} else if currentSection == "CIP Service Counts" {
					nameStyle = s.Success
				}
				lines = append(lines, "  "+nameStyle.Render(name)+": "+s.Dim.Render(count))
				continue
			}
		}

		// Default: preserve line with dim style for indented
		if strings.HasPrefix(line, "  ") {
			lines = append(lines, s.Dim.Render(line))
		} else {
			lines = append(lines, line)
		}
	}

	return lines
}

func (p *PCAPPanel) viewDiffResultContent(width int, focused bool) string {
	s := p.styles

	// If we have command result, show that
	if p.result != nil {
		var lines []string
		status := s.Success.Render("✓ Diff Complete")
		if p.result.ExitCode != 0 {
			status = s.Error.Render("✗ Diff Failed")
		}
		lines = append(lines, status)
		lines = append(lines, "")

		if p.result.Output != "" {
			cleanOutput := filterOutputForDisplay(p.result.Output)
			if cleanOutput != "" {
				lines = append(lines, s.Dim.Render(cleanOutput))
			}
		}

		lines = append(lines, "")
		lines = append(lines, s.KeyBinding.Render("[Esc]")+" Close")
		return strings.Join(lines, "\n")
	}

	if p.diffAnalysis == nil {
		return p.viewIdleContent(width, focused)
	}

	d := p.diffAnalysis
	var lines []string

	// Header with file names
	lines = append(lines, s.Header.Render("Comparing:"))
	lines = append(lines, fmt.Sprintf("  %s  vs  %s", s.Info.Render(d.File1), s.Warning.Render(d.File2)))
	lines = append(lines, "")

	if p.showVisual {
		// Visual side-by-side comparison
		colWidth := (width - 12) / 2

		// Packet count comparison
		maxPkts := d.File1Packets
		if d.File2Packets > maxPkts {
			maxPkts = d.File2Packets
		}
		bar1Len := (d.File1Packets * colWidth) / maxPkts
		bar2Len := (d.File2Packets * colWidth) / maxPkts

		lines = append(lines, "Packets:")
		lines = append(lines, fmt.Sprintf("  %s %s %d",
			s.Info.Render(strings.Repeat("█", bar1Len)+strings.Repeat("░", colWidth-bar1Len)),
			s.Dim.Render("|"),
			d.File1Packets))
		lines = append(lines, fmt.Sprintf("  %s %s %d",
			s.Warning.Render(strings.Repeat("█", bar2Len)+strings.Repeat("░", colWidth-bar2Len)),
			s.Dim.Render("|"),
			d.File2Packets))
		lines = append(lines, "")

		// Service differences as visual bars
		lines = append(lines, "Service Differences:")
		for _, diff := range d.ServiceDiffs {
			maxVal := diff.File1Count
			if diff.File2Count > maxVal {
				maxVal = diff.File2Count
			}
			if maxVal == 0 {
				maxVal = 1
			}

			bar1 := (diff.File1Count * 15) / maxVal
			bar2 := (diff.File2Count * 15) / maxVal

			diffStr := ""
			if diff.Diff > 0 {
				diffStr = s.Success.Render(fmt.Sprintf("+%d", diff.Diff))
			} else if diff.Diff < 0 {
				diffStr = s.Error.Render(fmt.Sprintf("%d", diff.Diff))
			} else {
				diffStr = s.Dim.Render("=")
			}

			lines = append(lines, fmt.Sprintf("  %-10s %s|%s %s",
				diff.Service,
				s.Info.Render(strings.Repeat("█", bar1)),
				s.Warning.Render(strings.Repeat("█", bar2)),
				diffStr))
		}

		lines = append(lines, "")
		// Only in each file
		if len(d.OnlyInFile1) > 0 {
			lines = append(lines, s.Info.Render("Only in "+d.File1+":")+s.Dim.Render(" "+strings.Join(d.OnlyInFile1, ", ")))
		}
		if len(d.OnlyInFile2) > 0 {
			lines = append(lines, s.Warning.Render("Only in "+d.File2+":")+s.Dim.Render(" "+strings.Join(d.OnlyInFile2, ", ")))
		}
	} else {
		// Text comparison
		lines = append(lines, fmt.Sprintf("%-20s  %-10s  %-10s  %s", "Metric", d.File1, d.File2, "Diff"))
		lines = append(lines, strings.Repeat("─", 50))
		lines = append(lines, fmt.Sprintf("%-20s  %-10d  %-10d  %+d", "Packets", d.File1Packets, d.File2Packets, d.File2Packets-d.File1Packets))
		lines = append(lines, "")
		for _, diff := range d.ServiceDiffs {
			lines = append(lines, fmt.Sprintf("%-20s  %-10d  %-10d  %+d", diff.Service, diff.File1Count, diff.File2Count, diff.Diff))
		}
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("Common Services: %d", d.CommonServices))
		if len(d.OnlyInFile1) > 0 {
			lines = append(lines, fmt.Sprintf("Only in %s: %s", d.File1, strings.Join(d.OnlyInFile1, ", ")))
		}
		if len(d.OnlyInFile2) > 0 {
			lines = append(lines, fmt.Sprintf("Only in %s: %s", d.File2, strings.Join(d.OnlyInFile2, ", ")))
		}
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[v]")+" Toggle View  "+s.KeyBinding.Render("[Esc]")+" Close")

	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewPacketViewerContent(width int, focused bool) string {
	s := p.styles
	var lines []string

	lines = append(lines, s.Header.Render("Packet Viewer: ")+p.getFileName(p.selectedFile))
	lines = append(lines, "")

	// Column headers
	hdr := fmt.Sprintf("  %-4s %-9s %-4s %-4s %-10s %-3s %-3s %s",
		"#", "Time", "Proto", "Len", "Service", "Dir", "Sts", "Summary")
	lines = append(lines, s.SectionName.Render(hdr))
	lines = append(lines, s.Muted.Render("  "+strings.Repeat("─", width-4)))

	// Packet list with scrolling
	visibleRows := 8
	startIdx := p.viewerOffset
	if p.selectedPkt >= startIdx+visibleRows {
		startIdx = p.selectedPkt - visibleRows + 1
	}
	if p.selectedPkt < startIdx {
		startIdx = p.selectedPkt
	}
	p.viewerOffset = startIdx

	endIdx := startIdx + visibleRows
	if endIdx > len(p.packets) {
		endIdx = len(p.packets)
	}

	for i := startIdx; i < endIdx; i++ {
		pkt := p.packets[i]
		cursor := "  "
		if i == p.selectedPkt {
			cursor = s.Selected.Render("> ")
		}

		// Status coloring
		statusStyle := s.Success
		if pkt.Status == "ERR" {
			statusStyle = s.Error
		}

		// Direction coloring
		dirStyle := s.Info
		if pkt.Direction == "RSP" {
			dirStyle = s.Warning
		}

		line := fmt.Sprintf("%s%-4d %-9s %-4s %-4d %-10s %s %s %s",
			cursor,
			pkt.Number,
			s.Dim.Render(pkt.Timestamp),
			pkt.Protocol,
			pkt.Length,
			pkt.Service,
			dirStyle.Render(pkt.Direction),
			statusStyle.Render(pkt.Status),
			s.Dim.Render(pkt.Summary))
		lines = append(lines, line)
	}

	// Scroll indicator
	if len(p.packets) > visibleRows {
		lines = append(lines, "")
		scrollPct := (p.selectedPkt * 100) / len(p.packets)
		lines = append(lines, s.Dim.Render(fmt.Sprintf("  Packet %d/%d (%d%%)", p.selectedPkt+1, len(p.packets), scrollPct)))
	}

	// Selected packet details
	if p.selectedPkt < len(p.packets) {
		pkt := p.packets[p.selectedPkt]
		lines = append(lines, "")
		lines = append(lines, s.Header.Render("Selected Packet Details:"))
		lines = append(lines, fmt.Sprintf("  Service: %s (0x%02X)", pkt.Service, 0x0E))
		lines = append(lines, fmt.Sprintf("  Path: %s", pkt.Summary))
		lines = append(lines, fmt.Sprintf("  Length: %d bytes", pkt.Length))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Up/Down]")+" Navigate  "+s.KeyBinding.Render("[PgUp/PgDn]")+" Scroll  "+s.KeyBinding.Render("[Esc]")+" Close")

	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) renderMetricBar(label string, value, max float64, width int, s Styles) string {
	labelWidth := 10
	barWidth := width - labelWidth - 10

	pct := value / max
	if pct > 1 {
		pct = 1
	}
	filledWidth := int(pct * float64(barWidth))

	bar := s.Info.Render(strings.Repeat("█", filledWidth)) +
		s.Muted.Render(strings.Repeat("░", barWidth-filledWidth))

	return fmt.Sprintf("%-*s %s %6.0f", labelWidth, label, bar, value)
}

func (p *PCAPPanel) renderBox(title, content string, width int, focused bool, accentColor lipgloss.Color) string {
	borderColor := DefaultTheme.Border
	if focused {
		borderColor = accentColor
	}

	innerWidth := width - 4
	titleBar := p.renderTitleBar(title, innerWidth)

	contentLines := strings.Split(content, "\n")
	var paddedLines []string
	for _, line := range contentLines {
		lineWidth := lipgloss.Width(line)
		if lineWidth < innerWidth {
			line += strings.Repeat(" ", innerWidth-lineWidth)
		}
		paddedLines = append(paddedLines, line)
	}

	var result strings.Builder
	result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("╭") + titleBar + lipgloss.NewStyle().Foreground(borderColor).Render("╮") + "\n")
	for _, line := range paddedLines {
		result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("│ ") + line + lipgloss.NewStyle().Foreground(borderColor).Render(" │") + "\n")
	}
	result.WriteString(lipgloss.NewStyle().Foreground(borderColor).Render("╰" + strings.Repeat("─", innerWidth) + "╯"))

	return result.String()
}

func (p *PCAPPanel) renderTitleBar(title string, width int) string {
	titleText := " " + title + " "
	titleLen := lipgloss.Width(titleText)
	remaining := width - titleLen - 1
	if remaining < 0 {
		remaining = 0
	}
	return lipgloss.NewStyle().Foreground(DefaultTheme.Border).Render("─") +
		p.styles.Header.Render(titleText) +
		lipgloss.NewStyle().Foreground(DefaultTheme.Border).Render(strings.Repeat("─", remaining))
}

// --------------------------------------------------------------------------
// Helper functions
// --------------------------------------------------------------------------

func renderMiniSparkline(data []float64, width int, s Styles) string {
	if len(data) == 0 || width <= 0 {
		return ""
	}

	// Normalize data
	maxVal := data[0]
	for _, v := range data {
		if v > maxVal {
			maxVal = v
		}
	}

	if maxVal == 0 {
		maxVal = 1
	}

	bars := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	var result strings.Builder
	step := len(data) / width
	if step < 1 {
		step = 1
	}

	for i := 0; i < width && i*step < len(data); i++ {
		val := data[i*step]
		normalized := val / maxVal
		barIndex := int(normalized * float64(len(bars)-1))
		if barIndex >= len(bars) {
			barIndex = len(bars) - 1
		}
		result.WriteRune(bars[barIndex])
	}

	return s.Info.Render(result.String())
}

// --------------------------------------------------------------------------
// CatalogPanel
// --------------------------------------------------------------------------

// CatalogPanel handles the CIP catalog browser panel using service groups.
type CatalogPanel struct {
	mode         PanelMode
	focusedField int
	styles       Styles
	state        *AppState

	// Catalog data
	catalog *catalog.Catalog
	groups  []*catalog.ServiceGroup

	// Browse state - two levels: groups and entries within group
	screen        int // 0=groups, 1=entries
	groupCursor   int
	groupScroll   int
	entryCursor   int
	entryScroll   int
	selectedGroup *catalog.ServiceGroup
	domainFilter  catalog.Domain // "" = all
	domainIndex   int            // 0=All, 1=Core, 2=Logix, 3=Legacy

	// Search
	searchMode  bool
	searchQuery string

	// Test config
	selectedEntry *catalog.Entry
	testIP        string
	testPort      string
	testTag       string // For symbolic entries

	// Running state
	testRunning bool
	startTime   *time.Time

	// Result
	testResult string
	testError  string
}

// NewCatalogPanel creates a new catalog panel.
func NewCatalogPanel(styles Styles, state *AppState) *CatalogPanel {
	p := &CatalogPanel{
		mode:     PanelIdle,
		styles:   styles,
		state:    state,
		testPort: "44818",
	}
	p.loadCatalog()
	return p
}

func (p *CatalogPanel) loadCatalog() {
	cwd, _ := os.Getwd()
	path, err := catalog.FindCoreCatalog(cwd)
	if err != nil {
		return
	}
	file, err := catalog.Load(path)
	if err != nil {
		return
	}
	p.catalog = catalog.NewCatalog(file)
	p.updateGroups()

	// Share catalog with state for other components
	if p.state != nil {
		p.state.CatalogInstance = p.catalog
		p.state.CatalogEntries = p.catalog.ListAll()
		p.state.CatalogGroups = p.catalog.Groups()
	}
}

// GetCatalog returns the loaded catalog.
func (p *CatalogPanel) GetCatalog() *catalog.Catalog {
	return p.catalog
}

func (p *CatalogPanel) updateGroups() {
	if p.catalog == nil {
		p.groups = nil
		return
	}

	// Get groups by domain filter
	var groups []*catalog.ServiceGroup
	if p.domainFilter != "" {
		groups = p.catalog.GroupsByDomain(p.domainFilter)
	} else {
		groups = p.catalog.Groups()
	}

	// Apply search filter if present
	if p.searchQuery != "" {
		query := strings.ToLower(p.searchQuery)
		var filtered []*catalog.ServiceGroup
		for _, g := range groups {
			// Match against service name, object name, or hex codes
			serviceName := strings.ToLower(g.ServiceName)
			objectName := strings.ToLower(g.ObjectName)
			serviceHex := fmt.Sprintf("0x%02x", g.ServiceCode)
			objectHex := fmt.Sprintf("0x%02x", g.ObjectClass)

			if strings.Contains(serviceName, query) ||
				strings.Contains(objectName, query) ||
				strings.Contains(serviceHex, query) ||
				strings.Contains(objectHex, query) {
				filtered = append(filtered, g)
			}
		}
		groups = filtered
	}

	p.groups = groups
}

func (p *CatalogPanel) Mode() PanelMode { return p.mode }
func (p *CatalogPanel) Name() string    { return "catalog" }

func (p *CatalogPanel) Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd) {
	if !focused {
		return p, nil
	}

	switch p.mode {
	case PanelIdle:
		if p.screen == 0 {
			return p.updateGroupBrowse(msg)
		}
		return p.updateEntryBrowse(msg)
	case PanelConfig:
		return p.updateConfig(msg)
	case PanelRunning:
		return p.updateRunning(msg)
	case PanelResult:
		return p.updateResult(msg)
	}
	return p, nil
}

func (p *CatalogPanel) updateGroupBrowse(msg tea.KeyMsg) (Panel, tea.Cmd) {
	// Handle search mode input
	if p.searchMode {
		switch msg.String() {
		case "esc":
			p.searchMode = false
			p.searchQuery = ""
			p.updateGroups()
			p.groupCursor = 0
			p.groupScroll = 0
		case "enter":
			// Exit search mode but keep filter applied
			p.searchMode = false
		case "backspace":
			if len(p.searchQuery) > 0 {
				p.searchQuery = p.searchQuery[:len(p.searchQuery)-1]
				p.updateGroups()
				p.groupCursor = 0
				p.groupScroll = 0
			}
		default:
			ch := msg.String()
			if len(ch) == 1 && ch != "/" {
				p.searchQuery += ch
				p.updateGroups()
				p.groupCursor = 0
				p.groupScroll = 0
			}
		}
		return p, nil
	}

	// Normal browse mode
	switch msg.String() {
	case "up", "k":
		if p.groupCursor > 0 {
			p.groupCursor--
			if p.groupCursor < p.groupScroll {
				p.groupScroll = p.groupCursor
			}
		}
	case "down", "j":
		if p.groupCursor < len(p.groups)-1 {
			p.groupCursor++
			if p.groupCursor >= p.groupScroll+10 {
				p.groupScroll = p.groupCursor - 9
			}
		}
	case "left", "h":
		// Previous domain filter
		p.domainIndex = (p.domainIndex + 3) % 4 // wrap backwards
		p.applyDomainIndex()
		p.updateGroups()
		p.groupCursor = 0
		p.groupScroll = 0
	case "right", "l":
		// Next domain filter
		p.domainIndex = (p.domainIndex + 1) % 4
		p.applyDomainIndex()
		p.updateGroups()
		p.groupCursor = 0
		p.groupScroll = 0
	case "/":
		// Enter search mode
		p.searchMode = true
		p.searchQuery = ""
	case "enter":
		// Enter group to see entries
		if p.groupCursor < len(p.groups) {
			p.selectedGroup = p.groups[p.groupCursor]
			// If only one entry, go straight to config
			if len(p.selectedGroup.Entries) == 1 {
				p.selectedEntry = p.selectedGroup.Entries[0]
				p.mode = PanelConfig
				p.focusedField = 0
			} else {
				p.screen = 1
				p.entryCursor = 0
				p.entryScroll = 0
			}
		}
	case "t":
		// Quick test - use first entry in group
		if p.groupCursor < len(p.groups) && len(p.groups[p.groupCursor].Entries) > 0 {
			p.selectedGroup = p.groups[p.groupCursor]
			p.selectedEntry = p.selectedGroup.Entries[0]
			p.mode = PanelConfig
			p.focusedField = 0
		}
	case "esc":
		// Clear search query if present, otherwise clear domain filter
		if p.searchQuery != "" {
			p.searchQuery = ""
			p.updateGroups()
			p.groupCursor = 0
			p.groupScroll = 0
		} else if p.domainFilter != "" {
			p.domainIndex = 0
			p.domainFilter = ""
			p.updateGroups()
			p.groupCursor = 0
			p.groupScroll = 0
		}
	}
	return p, nil
}

func (p *CatalogPanel) applyDomainIndex() {
	switch p.domainIndex {
	case 0:
		p.domainFilter = ""
	case 1:
		p.domainFilter = catalog.DomainCore
	case 2:
		p.domainFilter = catalog.DomainLogix
	case 3:
		p.domainFilter = catalog.DomainLegacy
	}
}

func (p *CatalogPanel) updateEntryBrowse(msg tea.KeyMsg) (Panel, tea.Cmd) {
	if p.selectedGroup == nil {
		p.screen = 0
		return p, nil
	}

	switch msg.String() {
	case "up", "k":
		if p.entryCursor > 0 {
			p.entryCursor--
			if p.entryCursor < p.entryScroll {
				p.entryScroll = p.entryCursor
			}
		}
	case "down", "j":
		if p.entryCursor < len(p.selectedGroup.Entries)-1 {
			p.entryCursor++
			if p.entryCursor >= p.entryScroll+10 {
				p.entryScroll = p.entryCursor - 9
			}
		}
	case "enter", "t":
		// Select entry for test
		if p.entryCursor < len(p.selectedGroup.Entries) {
			p.selectedEntry = p.selectedGroup.Entries[p.entryCursor]
			p.mode = PanelConfig
			p.focusedField = 0
		}
	case "esc":
		// Back to groups
		p.screen = 0
		p.selectedGroup = nil
	}
	return p, nil
}

func (p *CatalogPanel) updateConfig(msg tea.KeyMsg) (Panel, tea.Cmd) {
	maxField := 2 // IP, Port
	if p.selectedEntry != nil && len(p.selectedEntry.RequiresInput) > 0 {
		maxField = 3 // IP, Port, Tag
	}

	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
		p.testResult = ""
		p.testError = ""
		// Go back to entries screen if group has multiple entries, otherwise groups
		if p.selectedGroup != nil && len(p.selectedGroup.Entries) > 1 {
			p.screen = 1
		} else {
			p.screen = 0
			p.selectedGroup = nil
		}
		p.selectedEntry = nil
	case "tab":
		p.focusedField = (p.focusedField + 1) % maxField
	case "shift+tab":
		p.focusedField = (p.focusedField + maxField - 1) % maxField
	case "enter":
		if p.testIP != "" {
			p.mode = PanelRunning
			p.testRunning = true
			now := time.Now()
			p.startTime = &now
			// Simulate test completion (real implementation would use client)
			return p, func() tea.Msg {
				time.Sleep(100 * time.Millisecond)
				return catalogTestCompleteMsg{
					result: "Status=0x00 (Success) RTT=12.3ms",
					err:    "",
				}
			}
		}
	case "backspace":
		switch p.focusedField {
		case 0:
			if len(p.testIP) > 0 {
				p.testIP = p.testIP[:len(p.testIP)-1]
			}
		case 1:
			if len(p.testPort) > 0 {
				p.testPort = p.testPort[:len(p.testPort)-1]
			}
		case 2:
			if len(p.testTag) > 0 {
				p.testTag = p.testTag[:len(p.testTag)-1]
			}
		}
	default:
		ch := msg.String()
		if len(ch) == 1 {
			switch p.focusedField {
			case 0: // IP
				if ch == "." || (ch >= "0" && ch <= "9") {
					p.testIP += ch
				}
			case 1: // Port
				if ch >= "0" && ch <= "9" {
					p.testPort += ch
				}
			case 2: // Tag
				p.testTag += ch
			}
		}
	}
	return p, nil
}

func (p *CatalogPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		p.mode = PanelResult
		p.testRunning = false
		p.testError = "Cancelled"
	}
	return p, nil
}

func (p *CatalogPanel) updateResult(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		p.mode = PanelIdle
		p.testResult = ""
		p.testError = ""
		// Go back to entries screen if group has multiple entries, otherwise groups
		if p.selectedGroup != nil && len(p.selectedGroup.Entries) > 1 {
			p.screen = 1
		} else {
			p.screen = 0
			p.selectedGroup = nil
		}
		p.selectedEntry = nil
	case "r":
		// Re-run
		p.mode = PanelConfig
	}
	return p, nil
}

// catalogTestCompleteMsg is sent when a catalog test completes.
type catalogTestCompleteMsg struct {
	result string
	err    string
}

// HandleTestComplete processes test completion.
func (p *CatalogPanel) HandleTestComplete(result, err string) {
	p.testRunning = false
	p.testResult = result
	p.testError = err
	p.mode = PanelResult
}

func (p *CatalogPanel) View(width int, focused bool) string {
	return p.ViewContent(width, focused)
}

func (p *CatalogPanel) Title() string {
	switch p.mode {
	case PanelConfig:
		if p.selectedEntry != nil {
			return fmt.Sprintf("CATALOG > %s", p.selectedEntry.Name)
		}
		return "CATALOG > Test"
	case PanelRunning:
		return "CATALOG > Running..."
	case PanelResult:
		return "CATALOG > Result"
	default:
		if p.screen == 1 && p.selectedGroup != nil {
			return fmt.Sprintf("CATALOG > %s", p.selectedGroup.ObjectName)
		}
		domainLabel := "All"
		if p.domainFilter != "" {
			domainLabel = string(p.domainFilter)
		}
		if p.searchQuery != "" {
			return fmt.Sprintf("CATALOG [%s] \"%s\" (%d)", domainLabel, p.searchQuery, len(p.groups))
		}
		return fmt.Sprintf("CATALOG [%s] (%d groups)", domainLabel, len(p.groups))
	}
}

func (p *CatalogPanel) ViewContent(width int, focused bool) string {
	switch p.mode {
	case PanelConfig:
		return p.viewConfig(width)
	case PanelRunning:
		return p.viewRunning(width)
	case PanelResult:
		return p.viewResult(width)
	default:
		if p.screen == 1 {
			return p.viewEntries(width, focused)
		}
		return p.viewGroups(width, focused)
	}
}

func (p *CatalogPanel) viewGroups(width int, focused bool) string {
	s := p.styles
	var lines []string

	if p.catalog == nil {
		lines = append(lines, s.Error.Render("Catalog not loaded"))
		lines = append(lines, s.Dim.Render("Ensure catalogs/core.yaml exists"))
		return strings.Join(lines, "\n")
	}

	// Domain filter bar with left/right navigation hint
	domains := []string{"All", "Core", "Logix", "Legacy"}
	var filterParts []string
	for i, name := range domains {
		if i == p.domainIndex {
			filterParts = append(filterParts, s.Selected.Render("["+name+"]"))
		} else {
			filterParts = append(filterParts, s.Dim.Render(name))
		}
	}
	filterLine := "◀ " + strings.Join(filterParts, " ") + " ▶"
	lines = append(lines, filterLine)

	// Search bar
	if p.searchMode {
		searchLine := s.Info.Render("/") + p.searchQuery + s.Selected.Render("█")
		lines = append(lines, searchLine)
	} else if p.searchQuery != "" {
		// Show active search filter
		lines = append(lines, s.Dim.Render("search: ")+s.Info.Render(p.searchQuery)+s.Dim.Render(" (Esc to clear)"))
	} else {
		lines = append(lines, s.Dim.Render("/ to search"))
	}
	lines = append(lines, "")

	// Column headers - wider SERVICE column
	header := fmt.Sprintf("  %-7s %-28s %-18s %s", "DOMAIN", "SERVICE", "OBJECT", "TARGETS")
	lines = append(lines, s.Dim.Render(header))
	lines = append(lines, s.Dim.Render(strings.Repeat("─", width)))

	if len(p.groups) == 0 {
		if p.searchQuery != "" {
			lines = append(lines, s.Dim.Render("No matches for \""+p.searchQuery+"\""))
		} else {
			lines = append(lines, s.Dim.Render("No groups found"))
		}
		return strings.Join(lines, "\n")
	}

	// Show scrollable list
	maxVisible := 10
	endIdx := p.groupScroll + maxVisible
	if endIdx > len(p.groups) {
		endIdx = len(p.groups)
	}

	for i := p.groupScroll; i < endIdx; i++ {
		g := p.groups[i]

		// Wider service column - full service name without truncation where possible
		service := fmt.Sprintf("%s 0x%02X", truncStr(g.ServiceName, 22), g.ServiceCode)
		object := fmt.Sprintf("%s 0x%02X", truncStr(g.ObjectName, 10), g.ObjectClass)
		targets := g.TargetPreview(3)

		prefix := "  "
		if i == p.groupCursor {
			prefix = "> "
		}

		line := fmt.Sprintf("%s%-7s %-28s %-18s %s", prefix, g.Domain, service, object, targets)

		if i == p.groupCursor && focused {
			lines = append(lines, s.Selected.Render(line))
		} else {
			lines = append(lines, line)
		}
	}

	// Scroll indicator
	if len(p.groups) > maxVisible {
		lines = append(lines, s.Dim.Render(fmt.Sprintf("  %d/%d groups", p.groupCursor+1, len(p.groups))))
	}

	return strings.Join(lines, "\n")
}

func (p *CatalogPanel) viewEntries(width int, focused bool) string {
	s := p.styles
	var lines []string

	if p.selectedGroup == nil {
		return s.Error.Render("No group selected")
	}

	g := p.selectedGroup

	// Header with service info
	lines = append(lines, s.Header.Render(fmt.Sprintf("%s 0x%02X on %s 0x%02X",
		g.ServiceName, g.ServiceCode, g.ObjectName, g.ObjectClass)))
	lines = append(lines, s.Dim.Render(fmt.Sprintf("Domain: %s  |  %d targets available", g.Domain, len(g.Entries))))
	lines = append(lines, "")

	// Column headers
	header := fmt.Sprintf("  %-6s %-40s %s", "ATTR", "NAME", "TYPE")
	lines = append(lines, s.Dim.Render(header))
	lines = append(lines, s.Dim.Render(strings.Repeat("─", width)))

	// Show entries
	maxVisible := 10
	endIdx := p.entryScroll + maxVisible
	if endIdx > len(g.Entries) {
		endIdx = len(g.Entries)
	}

	for i := p.entryScroll; i < endIdx; i++ {
		e := g.Entries[i]

		attr := "-"
		if e.EPATH.Attribute != 0 {
			attr = fmt.Sprintf("0x%02X", e.EPATH.Attribute)
		}

		dataType := ""
		if desc := e.Description; desc != "" {
			if idx := strings.LastIndex(desc, "("); idx > 0 {
				dataType = strings.Trim(desc[idx:], "()")
			}
		}

		prefix := "  "
		if i == p.entryCursor {
			prefix = "> "
		}

		line := fmt.Sprintf("%s%-6s %-40s %s", prefix, attr, truncStr(e.Name, 38), dataType)

		if i == p.entryCursor && focused {
			lines = append(lines, s.Selected.Render(line))
		} else {
			lines = append(lines, line)
		}
	}

	// Scroll indicator
	if len(g.Entries) > maxVisible {
		lines = append(lines, s.Dim.Render(fmt.Sprintf("  %d/%d targets", p.entryCursor+1, len(g.Entries))))
	}

	return strings.Join(lines, "\n")
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func (p *CatalogPanel) viewConfig(width int) string {
	s := p.styles
	var lines []string

	if p.selectedEntry == nil {
		lines = append(lines, s.Error.Render("No entry selected"))
		return strings.Join(lines, "\n")
	}

	e := p.selectedEntry

	// Entry info
	lines = append(lines, s.Header.Render(e.Name))
	lines = append(lines, s.Dim.Render(fmt.Sprintf("Service: %s (0x%02X)  Object: %s (0x%02X)",
		e.ServiceName, e.ServiceCode, e.ObjectName, e.ObjectClass)))
	lines = append(lines, "")

	// EPATH preview
	epath := fmt.Sprintf("0x%02X/0x%02X", e.EPATH.Class, e.EPATH.Instance)
	if e.EPATH.Attribute != 0 {
		epath += fmt.Sprintf("/0x%02X", e.EPATH.Attribute)
	}
	lines = append(lines, s.Dim.Render("EPATH: ")+s.Info.Render(epath))
	lines = append(lines, "")

	// Config fields
	cursor := "█"

	// IP field
	ipLabel := "Target IP"
	ipValue := p.testIP
	if ipValue == "" {
		ipValue = "_____________"
	}
	if p.focusedField == 0 {
		lines = append(lines, s.Selected.Render(ipLabel)+": "+ipValue+cursor)
	} else {
		lines = append(lines, s.Dim.Render(ipLabel)+": "+ipValue)
	}

	// Port field
	portLabel := "Port"
	portValue := p.testPort
	if portValue == "" {
		portValue = "44818"
	}
	if p.focusedField == 1 {
		lines = append(lines, s.Selected.Render(portLabel)+": "+portValue+cursor)
	} else {
		lines = append(lines, s.Dim.Render(portLabel)+": "+portValue)
	}

	// Tag field (if required)
	if len(e.RequiresInput) > 0 {
		lines = append(lines, "")
		tagLabel := "Tag/Symbol"
		tagValue := p.testTag
		if tagValue == "" {
			tagValue = "_____________"
		}
		if p.focusedField == 2 {
			lines = append(lines, s.Selected.Render(tagLabel)+": "+tagValue+cursor)
		} else {
			lines = append(lines, s.Dim.Render(tagLabel)+": "+tagValue)
		}
	}

	return strings.Join(lines, "\n")
}

func (p *CatalogPanel) viewRunning(width int) string {
	s := p.styles
	var lines []string

	if p.selectedEntry != nil {
		lines = append(lines, s.Header.Render("Testing: "+p.selectedEntry.Name))
	} else {
		lines = append(lines, s.Header.Render("Testing..."))
	}

	lines = append(lines, "")
	lines = append(lines, s.Info.Render("Sending CIP request to "+p.testIP+":"+p.testPort+"..."))
	lines = append(lines, "")

	if p.startTime != nil {
		elapsed := time.Since(*p.startTime)
		lines = append(lines, s.Dim.Render(fmt.Sprintf("Elapsed: %.1fs", elapsed.Seconds())))
	}

	return strings.Join(lines, "\n")
}

func (p *CatalogPanel) viewResult(width int) string {
	s := p.styles
	var lines []string

	if p.selectedEntry != nil {
		lines = append(lines, s.Header.Render("Result: "+p.selectedEntry.Name))
	} else {
		lines = append(lines, s.Header.Render("Result"))
	}

	lines = append(lines, "")
	lines = append(lines, s.Dim.Render("Target: "+p.testIP+":"+p.testPort))
	lines = append(lines, "")

	if p.testError != "" {
		lines = append(lines, s.Error.Render("Error: "+p.testError))
	} else if p.testResult != "" {
		lines = append(lines, s.Success.Render("Success: "+p.testResult))
	}

	return strings.Join(lines, "\n")
}

// getServiceName returns a friendly name for a CIP service code.
// Standard CIP services (0x01-0x1C) have consistent names.
// Object-specific services (0x4B+) vary by object class, so we show "Obj-Specific".
func getServiceName(code string) string {
	// Parse hex code string to uint8
	code = strings.TrimPrefix(strings.ToLower(code), "0x")
	var val uint8
	if _, err := fmt.Sscanf(code, "%x", &val); err != nil {
		return "Unknown"
	}

	// Standard CIP services have consistent names across objects
	standardServices := map[uint8]string{
		0x01: "Get_Attr_All",
		0x02: "Set_Attr_All",
		0x03: "Get_Attr_List",
		0x04: "Set_Attr_List",
		0x05: "Reset",
		0x06: "Start",
		0x07: "Stop",
		0x08: "Create",
		0x09: "Delete",
		0x0A: "Multiple_Svc",
		0x0D: "Apply_Attr",
		0x0E: "Get_Attr_Single",
		0x10: "Set_Attr_Single",
		0x11: "Find_Next",
		0x15: "Restore",
		0x16: "Save",
		0x17: "No_Op",
		0x18: "Get_Member",
		0x19: "Set_Member",
		0x1A: "Insert_Member",
		0x1B: "Remove_Member",
	}

	if name, ok := standardServices[val]; ok {
		return name
	}

	// Object-specific services (0x4B+) - meaning varies by object class
	// Connection Manager services
	if val == 0x52 {
		return "Unconn_Send"
	}
	if val == 0x54 {
		return "Forward_Open"
	}
	if val == 0x4E {
		return "Fwd_Close"
	}
	if val == 0x5B {
		return "Large_Fwd_Open"
	}

	// For other object-specific codes, just indicate they're object-specific
	if val >= 0x4B {
		return "Obj-Specific"
	}

	return "Unknown"
}

// --------------------------------------------------------------------------
// DiscoverPanel - Device discovery using ListIdentity
// --------------------------------------------------------------------------

// DiscoverPanel handles device discovery operations.
type DiscoverPanel struct {
	mode         PanelMode
	focusedField int
	styles       Styles

	// Config fields
	interfaceName string        // Network interface (empty = all)
	timeout       string        // Timeout in seconds
	outputFormat  int           // 0=text, 1=json

	// Available interfaces
	interfaces []string

	// Running state
	runCtx    context.Context
	runCancel context.CancelFunc
	startTime *time.Time

	// Result
	result       *CommandResult
	resultScroll int
	resultLines  []string

	// Discovered devices
	devices []DiscoveredDevice
}

// DiscoveredDevice represents a discovered CIP device.
type DiscoveredDevice struct {
	IP          string
	VendorID    int
	DeviceType  int
	ProductCode int
	Revision    string
	Serial      string
	ProductName string
	State       string
}

var discoverOutputFormats = []string{"text", "json"}

// NewDiscoverPanel creates a new discover panel.
func NewDiscoverPanel(styles Styles) *DiscoverPanel {
	dp := &DiscoverPanel{
		mode:    PanelIdle,
		styles:  styles,
		timeout: "5",
	}
	dp.detectInterfaces()
	return dp
}

// detectInterfaces detects available network interfaces.
func (p *DiscoverPanel) detectInterfaces() {
	interfaces, err := netdetect.ListInterfaces()
	if err != nil {
		p.interfaces = []string{"(auto)"}
		return
	}

	p.interfaces = []string{"(auto)"} // First option is auto-detect
	for _, iface := range interfaces {
		if !iface.IsLoopback && iface.IsUp {
			displayName := netdetect.GetInterfaceDisplayName(iface)
			p.interfaces = append(p.interfaces, displayName)
		}
	}
}

func (p *DiscoverPanel) Mode() PanelMode { return p.mode }
func (p *DiscoverPanel) Name() string    { return "discover" }

// Title returns the panel title based on current mode.
func (p *DiscoverPanel) Title() string {
	switch p.mode {
	case PanelConfig:
		return "DISCOVER (Config)"
	case PanelRunning:
		return "DISCOVER (Scanning)"
	case PanelResult:
		return "DISCOVER (Results)"
	default:
		return "DISCOVER"
	}
}

// BuildRunConfig creates a DiscoverRunConfig from the current panel settings.
func (p *DiscoverPanel) BuildRunConfig() DiscoverRunConfig {
	timeoutSec, _ := strconv.Atoi(p.timeout)
	if timeoutSec <= 0 {
		timeoutSec = 5
	}

	cfg := DiscoverRunConfig{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Output:  discoverOutputFormats[p.outputFormat],
	}

	// Set interface if not auto
	if p.focusedField == 0 && len(p.interfaces) > 0 && p.interfaceName != "" && p.interfaceName != "(auto)" {
		cfg.Interface = p.interfaceName
	}

	return cfg
}

func (p *DiscoverPanel) Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd) {
	if !focused {
		return p, nil
	}

	switch p.mode {
	case PanelIdle:
		return p.updateIdle(msg)
	case PanelConfig:
		return p.updateConfig(msg)
	case PanelRunning:
		return p.updateRunning(msg)
	case PanelResult:
		return p.updateResult(msg)
	}
	return p, nil
}

func (p *DiscoverPanel) updateIdle(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "enter", "d":
		p.mode = PanelConfig
		p.focusedField = 0
	}
	return p, nil
}

func (p *DiscoverPanel) updateConfig(msg tea.KeyMsg) (Panel, tea.Cmd) {
	maxField := 3 // interface, timeout, format

	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
	case "enter":
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.runCtx, p.runCancel = context.WithCancel(context.Background())
		return p, func() tea.Msg {
			return startDiscoverRunMsg{config: p.BuildRunConfig()}
		}
	case "tab":
		p.focusedField = (p.focusedField + 1) % maxField
	case "shift+tab":
		p.focusedField = (p.focusedField - 1 + maxField) % maxField
	case "up":
		switch p.focusedField {
		case 2: // output format
			if p.outputFormat > 0 {
				p.outputFormat--
			}
		}
	case "down":
		switch p.focusedField {
		case 2: // output format
			if p.outputFormat < len(discoverOutputFormats)-1 {
				p.outputFormat++
			}
		}
	case "backspace":
		if p.focusedField == 1 && len(p.timeout) > 0 {
			p.timeout = p.timeout[:len(p.timeout)-1]
		}
	default:
		if len(msg.String()) == 1 {
			ch := msg.String()
			if p.focusedField == 1 && ch >= "0" && ch <= "9" {
				p.timeout += ch
			}
		}
	}
	return p, nil
}

func (p *DiscoverPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "x":
		if p.runCancel != nil {
			p.runCancel()
		}
		p.mode = PanelResult
		p.result = &CommandResult{
			Output:   "Cancelled by user",
			ExitCode: 1,
		}
	}
	return p, nil
}

func (p *DiscoverPanel) updateResult(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		p.mode = PanelIdle
		p.result = nil
		p.resultLines = nil
	case "r":
		// Re-run discovery
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.runCtx, p.runCancel = context.WithCancel(context.Background())
		return p, func() tea.Msg {
			return startDiscoverRunMsg{config: p.BuildRunConfig()}
		}
	case "up", "k":
		if p.resultScroll > 0 {
			p.resultScroll--
		}
	case "down", "j":
		if p.resultScroll < len(p.resultLines)-10 {
			p.resultScroll++
		}
	}
	return p, nil
}

func (p *DiscoverPanel) View(width int, focused bool) string {
	return p.ViewContent(width, focused)
}

// ViewContent returns the panel content.
func (p *DiscoverPanel) ViewContent(width int, focused bool) string {
	switch p.mode {
	case PanelConfig:
		return p.viewConfigContent(width, focused)
	case PanelRunning:
		return p.viewRunningContent(width, focused)
	case PanelResult:
		return p.viewResultContent(width, focused)
	default:
		return p.viewIdleContent(width, focused)
	}
}

func (p *DiscoverPanel) viewIdleContent(width int, focused bool) string {
	s := p.styles
	content := []string{
		"Discover CIP devices on the network",
		"",
		fmt.Sprintf("Interface: %s", s.Dim.Render(p.getInterfaceDisplay())),
		fmt.Sprintf("Timeout:   %s", s.Dim.Render(p.timeout+"s")),
		"",
	}
	if focused {
		content = append(content, s.KeyBinding.Render("[Enter]")+" Configure  "+s.KeyBinding.Render("[d]")+" Quick scan")
	} else {
		content = append(content, s.Dim.Render("[d] Configure"))
	}
	return strings.Join(content, "\n")
}

func (p *DiscoverPanel) getInterfaceDisplay() string {
	if p.interfaceName == "" || p.interfaceName == "(auto)" {
		return "all interfaces"
	}
	return p.interfaceName
}

func (p *DiscoverPanel) viewConfigContent(width int, focused bool) string {
	s := p.styles
	lines := []string{
		s.Header.Render("Discovery Configuration"),
		"",
	}

	// Interface selection
	ifaceLabel := "Interface"
	ifaceValue := p.getInterfaceDisplay()
	if p.focusedField == 0 {
		lines = append(lines, s.Selected.Render(ifaceLabel)+": "+ifaceValue+" "+s.Dim.Render("(↑↓ to change)"))
	} else {
		lines = append(lines, s.Dim.Render(ifaceLabel)+": "+ifaceValue)
	}

	// Timeout
	timeoutLabel := "Timeout"
	if p.focusedField == 1 {
		lines = append(lines, s.Selected.Render(timeoutLabel)+": "+p.timeout+s.Cursor.Render("█")+"s")
	} else {
		lines = append(lines, s.Dim.Render(timeoutLabel)+": "+p.timeout+"s")
	}

	// Output format
	formatLabel := "Format"
	formatValue := discoverOutputFormats[p.outputFormat]
	if p.focusedField == 2 {
		lines = append(lines, s.Selected.Render(formatLabel)+": "+formatValue+" "+s.Dim.Render("(↑↓ to change)"))
	} else {
		lines = append(lines, s.Dim.Render(formatLabel)+": "+formatValue)
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Run  "+s.KeyBinding.Render("[Esc]")+" Cancel  "+s.KeyBinding.Render("[Tab]")+" Next field")

	return strings.Join(lines, "\n")
}

func (p *DiscoverPanel) viewRunningContent(width int, focused bool) string {
	s := p.styles
	elapsed := time.Since(*p.startTime).Round(time.Millisecond)

	lines := []string{
		s.Header.Render("Discovering Devices..."),
		"",
		fmt.Sprintf("Elapsed: %v", elapsed),
		"",
		s.Dim.Render("Sending ListIdentity broadcasts..."),
		"",
		s.KeyBinding.Render("[Esc]") + " Cancel",
	}

	return strings.Join(lines, "\n")
}

func (p *DiscoverPanel) viewResultContent(width int, focused bool) string {
	s := p.styles

	if p.result == nil {
		return "No results"
	}

	lines := []string{
		s.Header.Render("Discovery Results"),
		"",
	}

	// Parse and display result lines
	if len(p.resultLines) == 0 && p.result.Output != "" {
		p.resultLines = strings.Split(filterOutputForDisplay(p.result.Output), "\n")
	}

	// Show result with scrolling
	maxLines := 15
	start := p.resultScroll
	end := start + maxLines
	if end > len(p.resultLines) {
		end = len(p.resultLines)
	}

	for i := start; i < end; i++ {
		lines = append(lines, p.resultLines[i])
	}

	if len(p.resultLines) > maxLines {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render(fmt.Sprintf("Showing %d-%d of %d lines", start+1, end, len(p.resultLines))))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter/Esc]")+" Done  "+s.KeyBinding.Render("[r]")+" Re-run  "+s.KeyBinding.Render("[↑↓]")+" Scroll")

	return strings.Join(lines, "\n")
}

// SetResult sets the result and transitions to result mode.
func (p *DiscoverPanel) SetResult(result CommandResult) {
	p.result = &result
	p.resultLines = nil
	p.resultScroll = 0
	p.mode = PanelResult
}
