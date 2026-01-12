package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	profiles     []string

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
	pcapEnabled   bool
	pcapInterface string
	pcapAuto      bool

	// Config file
	configFile string

	// Firewall options (when firewall scenario selected)
	firewallVendor int

	// Running stats
	stats         StatsUpdate
	statsHistory  []float64
	startTime     *time.Time
	lastResponse  string
	recentErrors  []string
	avgLatency    float64
	successRate   float64

	// Result
	result *CommandResult
}

var clientScenarios = []string{"baseline", "stress", "io", "edge", "mixed", "firewall", "vendor_variants"}
var clientModePresets = []string{"Quick (30s)", "Standard (5m)", "Extended (30m)", "Custom"}
var protocolVariants = []string{"strict_odva", "rockwell_enbt", "schneider_m580", "siemens_s7_1200"}
var firewallVendors = []string{"All", "Hirschmann EAGLE", "Moxa EDR", "Dynics"}

// NewClientPanel creates a new client panel.
func NewClientPanel(styles Styles) *ClientPanel {
	return &ClientPanel{
		mode:            PanelIdle,
		styles:          styles,
		targetIP:        "192.168.1.100",
		port:            "44818",
		scenario:        0,
		duration:        "300",
		interval:        "250",
		modePreset:      1, // Standard
		profiles:        []string{"baseline_client", "stress_test", "io_scanner"},
		pcapAuto:        true,
		recentErrors:    make([]string, 0),
	}
}

func (p *ClientPanel) Mode() PanelMode { return p.mode }
func (p *ClientPanel) Name() string    { return "client" }

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
	maxField := 4 // Basic fields: IP, port, scenario, mode preset
	if p.showAdvanced {
		maxField = 12 // Add: duration, interval, CIP profiles x3, protocol, PCAP, interface, config
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
		p.recentErrors = nil
		// TODO: actually start client operation
	case "a":
		p.showAdvanced = !p.showAdvanced
		if !p.showAdvanced && p.focusedField > 4 {
			p.focusedField = 0
		}
	case "p":
		p.useProfile = !p.useProfile
		p.focusedField = 0
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
			}
		} else {
			if p.scenario > 0 {
				p.scenario--
			}
		}
	case 3: // mode preset
		if p.modePreset > 0 {
			p.modePreset--
			p.applyModePreset()
		}
	case 9: // protocol variant
		if p.protocolVariant > 0 {
			p.protocolVariant--
		}
	case 11: // firewall vendor
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
			}
		} else {
			if p.scenario < len(clientScenarios)-1 {
				p.scenario++
			}
		}
	case 3: // mode preset
		if p.modePreset < len(clientModePresets)-1 {
			p.modePreset++
			p.applyModePreset()
		}
	case 9: // protocol variant
		if p.protocolVariant < len(protocolVariants)-1 {
			p.protocolVariant++
		}
	case 11: // firewall vendor
		if p.firewallVendor < len(firewallVendors)-1 {
			p.firewallVendor++
		}
	}
}

func (p *ClientPanel) handleSpaceKey() {
	switch p.focusedField {
	case 6: // CIP Energy
		p.cipEnergy = !p.cipEnergy
	case 7: // CIP Safety
		p.cipSafety = !p.cipSafety
	case 8: // CIP Motion
		p.cipMotion = !p.cipMotion
	case 10: // PCAP enabled
		p.pcapEnabled = !p.pcapEnabled
	}
}

func (p *ClientPanel) applyModePreset() {
	switch p.modePreset {
	case 0: // Quick
		p.duration = "30"
		p.interval = "250"
	case 1: // Standard
		p.duration = "300"
		p.interval = "250"
	case 2: // Extended
		p.duration = "1800"
		p.interval = "250"
	// case 3: Custom - don't change values
	}
}

func (p *ClientPanel) handleBackspace() {
	switch p.focusedField {
	case 0: // Target IP
		if len(p.targetIP) > 0 {
			p.targetIP = p.targetIP[:len(p.targetIP)-1]
		}
	case 1: // Port
		if len(p.port) > 0 {
			p.port = p.port[:len(p.port)-1]
		}
	case 4: // Duration (in advanced mode)
		if len(p.duration) > 0 {
			p.duration = p.duration[:len(p.duration)-1]
		}
	case 5: // Interval (in advanced mode)
		if len(p.interval) > 0 {
			p.interval = p.interval[:len(p.interval)-1]
		}
	}
}

func (p *ClientPanel) handleChar(ch string) {
	switch p.focusedField {
	case 0: // Target IP
		if ch == "." || (ch >= "0" && ch <= "9") {
			p.targetIP += ch
		}
	case 1: // Port
		if ch >= "0" && ch <= "9" {
			p.port += ch
		}
	case 4: // Duration
		if ch >= "0" && ch <= "9" {
			p.duration += ch
			p.modePreset = 3 // Switch to Custom
		}
	case 5: // Interval
		if ch >= "0" && ch <= "9" {
			p.interval += ch
			p.modePreset = 3 // Switch to Custom
		}
	}
}

func (p *ClientPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "x":
		p.mode = PanelResult
		p.result = &CommandResult{
			Output:   "Operation stopped by user",
			ExitCode: 0,
		}
		// TODO: actually stop client operation
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
	content := []string{
		fmt.Sprintf("Target: %s", s.Dim.Render(p.targetIP)),
		fmt.Sprintf("Scenario: %s", s.Dim.Render(clientScenarios[p.scenario])),
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

	// Mode toggle header
	modeIndicator := s.Dim.Render("[p] Profile Mode")
	if p.useProfile {
		modeIndicator = s.Info.Render("[p] ● Profile Mode")
	}
	header := modeIndicator + "  " + s.KeyBinding.Render("[a]") + " " + s.Dim.Render("Advanced")

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
		leftCol = append(leftCol, s.Header.Render("Profile:"))
		for i, prof := range p.profiles {
			radio := "( )"
			if i == p.profileIndex {
				radio = s.Success.Render("(●)")
			}
			style := s.Dim
			if p.focusedField == 2 && i == p.profileIndex {
				style = s.Selected
			}
			leftCol = append(leftCol, " "+radio+" "+style.Render(prof))
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

	rightCol = append(rightCol, s.Header.Render("Duration Preset:"))
	for i, preset := range clientModePresets {
		radio := "( )"
		if i == p.modePreset {
			radio = s.Success.Render("(●)")
		}
		style := s.Dim
		if p.focusedField == 3 && i == p.modePreset {
			style = s.Selected
		}
		rightCol = append(rightCol, " "+radio+" "+style.Render(preset))
	}

	// Advanced options in right column
	if p.showAdvanced {
		rightCol = append(rightCol, "")
		rightCol = append(rightCol, s.Header.Render("Advanced:"))

		// Duration
		if p.focusedField == 4 {
			rightCol = append(rightCol, s.Selected.Render("Duration")+": "+p.duration+"s"+s.Cursor.Render("█"))
		} else {
			rightCol = append(rightCol, s.Dim.Render("Duration")+": "+p.duration+"s")
		}

		// Interval
		if p.focusedField == 5 {
			rightCol = append(rightCol, s.Selected.Render("Interval")+": "+p.interval+"ms"+s.Cursor.Render("█"))
		} else {
			rightCol = append(rightCol, s.Dim.Render("Interval")+": "+p.interval+"ms")
		}

		// CIP Profiles on one line
		rightCol = append(rightCol, "")
		rightCol = append(rightCol,
			p.renderCheckbox("Energy", p.cipEnergy, p.focusedField == 6, s)+" "+
				p.renderCheckbox("Safety", p.cipSafety, p.focusedField == 7, s)+" "+
				p.renderCheckbox("Motion", p.cipMotion, p.focusedField == 8, s))

		// Protocol variant
		if p.focusedField == 9 {
			rightCol = append(rightCol, s.Selected.Render("Protocol")+": "+s.Info.Render(protocolVariants[p.protocolVariant])+" ▼")
		} else {
			rightCol = append(rightCol, s.Dim.Render("Protocol")+": "+protocolVariants[p.protocolVariant])
		}

		// PCAP capture
		rightCol = append(rightCol, p.renderCheckbox("PCAP Capture", p.pcapEnabled, p.focusedField == 10, s))

		// Firewall vendor (if firewall scenario)
		if clientScenarios[p.scenario] == "firewall" {
			if p.focusedField == 11 {
				rightCol = append(rightCol, s.Selected.Render("FW Vendor")+": "+s.Warning.Render(firewallVendors[p.firewallVendor])+" ▼")
			} else {
				rightCol = append(rightCol, s.Dim.Render("FW Vendor")+": "+firewallVendors[p.firewallVendor])
			}
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

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Start  "+s.KeyBinding.Render("[Tab]")+" Next  "+s.KeyBinding.Render("[Esc]")+" Cancel")

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

	// Calculate success rate
	successRate := 0.0
	if p.stats.TotalRequests > 0 {
		successRate = float64(p.stats.SuccessfulRequests) / float64(p.stats.TotalRequests) * 100
	}

	scenarioName := clientScenarios[p.scenario]
	if p.useProfile && p.profileIndex < len(p.profiles) {
		scenarioName = p.profiles[p.profileIndex]
	}

	lines := []string{
		s.Running.Render("● RUNNING"),
		"",
		fmt.Sprintf("Target:   %s:%s", p.targetIP, p.port),
		fmt.Sprintf("Scenario: %s", scenarioName),
		fmt.Sprintf("Elapsed:  %s", formatDuration(elapsed.Seconds())),
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
	lines = append(lines, s.KeyBinding.Render("[Esc/x]")+" Stop  "+s.KeyBinding.Render("[Space]")+" Pause")

	return strings.Join(lines, "\n")
}

func (p *ClientPanel) viewResultContent(width int, focused bool) string {
	s := p.styles

	status := s.Success.Render("✓ Completed")
	if p.result != nil && p.result.ExitCode != 0 {
		status = s.Error.Render("✗ Failed")
	}

	lines := []string{
		status,
		"",
		fmt.Sprintf("Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Success: %s", s.Success.Render(fmt.Sprintf("%d", p.stats.SuccessfulRequests))),
		fmt.Sprintf("Errors: %s", s.Error.Render(fmt.Sprintf("%d", p.stats.TotalErrors))),
		"",
		s.KeyBinding.Render("[Enter/Esc]") + " Dismiss  " + s.KeyBinding.Render("[r]") + " Re-run",
	}

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
	profiles     []string

	// Config fields
	listenAddr  string
	port        string
	personality int
	opMode      int // Operating mode

	// Advanced options
	showAdvanced bool
	cipEnergy    bool
	cipSafety    bool
	cipMotion    bool
	udpIO        bool
	udpPort      string

	// PCAP capture
	pcapEnabled   bool
	pcapInterface string
	pcapAuto      bool

	// Running stats
	stats         StatsUpdate
	connections   []string
	recentReqs    []string
	statsHistory  []float64
	startTime     *time.Time

	// Result
	result *CommandResult
}

var serverPersonalities = []string{"adapter", "logix_like", "minimal"}
var serverOpModes = []string{"baseline", "realistic", "dpi-torture", "perf"}

// NewServerPanel creates a new server panel.
func NewServerPanel(styles Styles) *ServerPanel {
	return &ServerPanel{
		mode:        PanelIdle,
		styles:      styles,
		listenAddr:  "0.0.0.0",
		port:        "44818",
		udpPort:     "2222",
		personality: 0,
		profiles:    []string{"adapter_basic", "logix_emulator", "io_scanner_server"},
		pcapAuto:    true,
		recentReqs:  make([]string, 0),
	}
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
	maxField := 4 // Basic: listen, port, personality, op mode
	if p.showAdvanced {
		maxField = 10 // Add: CIP x3, UDP I/O, UDP port, PCAP
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
		// TODO: actually start server operation
	case "a":
		p.showAdvanced = !p.showAdvanced
		if !p.showAdvanced && p.focusedField > 4 {
			p.focusedField = 0
		}
	case "p":
		p.useProfile = !p.useProfile
		p.focusedField = 0
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
		case 4:
			p.cipEnergy = !p.cipEnergy
		case 5:
			p.cipSafety = !p.cipSafety
		case 6:
			p.cipMotion = !p.cipMotion
		case 7:
			p.udpIO = !p.udpIO
		case 9:
			p.pcapEnabled = !p.pcapEnabled
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
		}
	case 1:
		if len(p.port) > 0 {
			p.port = p.port[:len(p.port)-1]
		}
	case 8: // UDP port
		if len(p.udpPort) > 0 {
			p.udpPort = p.udpPort[:len(p.udpPort)-1]
		}
	}
}

func (p *ServerPanel) handleChar(ch string) {
	switch p.focusedField {
	case 0:
		if ch == "." || (ch >= "0" && ch <= "9") {
			p.listenAddr += ch
		}
	case 1:
		if ch >= "0" && ch <= "9" {
			p.port += ch
		}
	case 8: // UDP port
		if ch >= "0" && ch <= "9" {
			p.udpPort += ch
		}
	}
}

func (p *ServerPanel) updateRunning(msg tea.KeyMsg) (Panel, tea.Cmd) {
	switch msg.String() {
	case "esc", "x":
		p.mode = PanelResult
		p.result = &CommandResult{
			Output:   "Server stopped",
			ExitCode: 0,
		}
		// TODO: actually stop server
	}
	return p, nil
}

func (p *ServerPanel) updateResult(msg tea.KeyMsg) (Panel, tea.Cmd) {
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
		return p.viewResultContent(width, focused)
	default:
		return p.viewIdleContent(width, focused)
	}
}

// Title returns the panel title based on current mode.
func (p *ServerPanel) Title() string {
	switch p.mode {
	case PanelConfig:
		return "SERVER (Config)"
	case PanelRunning:
		return "SERVER (Listening)"
	case PanelResult:
		return "SERVER (Stopped)"
	default:
		return "SERVER"
	}
}

func (p *ServerPanel) viewIdleContent(width int, focused bool) string {
	s := p.styles
	content := []string{
		fmt.Sprintf("Listen: %s:%s", s.Dim.Render(p.listenAddr), s.Dim.Render(p.port)),
		fmt.Sprintf("Personality: %s", s.Dim.Render(serverPersonalities[p.personality])),
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

	// Mode toggle header
	modeIndicator := s.Dim.Render("[p] Profile Mode")
	if p.useProfile {
		modeIndicator = s.Info.Render("[p] ● Profile Mode")
	}
	header := modeIndicator + "  " + s.KeyBinding.Render("[a]") + " " + s.Dim.Render("Advanced")

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
		leftCol = append(leftCol, s.Header.Render("Profile:"))
		for i, prof := range p.profiles {
			radio := "( )"
			if i == p.profileIndex {
				radio = s.Success.Render("(●)")
			}
			style := s.Dim
			if p.focusedField == 2 && i == p.profileIndex {
				style = s.Selected
			}
			leftCol = append(leftCol, " "+radio+" "+style.Render(prof))
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

		// CIP Profiles on one line
		rightCol = append(rightCol,
			p.renderCheckbox("Energy", p.cipEnergy, p.focusedField == 4, s)+" "+
				p.renderCheckbox("Safety", p.cipSafety, p.focusedField == 5, s)+" "+
				p.renderCheckbox("Motion", p.cipMotion, p.focusedField == 6, s))

		// UDP I/O
		rightCol = append(rightCol, p.renderCheckbox("UDP I/O", p.udpIO, p.focusedField == 7, s))
		if p.udpIO {
			if p.focusedField == 8 {
				rightCol = append(rightCol, "  "+s.Selected.Render("UDP Port")+": "+p.udpPort+s.Cursor.Render("█"))
			} else {
				rightCol = append(rightCol, "  "+s.Dim.Render("UDP Port")+": "+p.udpPort)
			}
		}

		// PCAP capture
		rightCol = append(rightCol, p.renderCheckbox("PCAP Capture", p.pcapEnabled, p.focusedField == 9, s))
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

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Start  "+s.KeyBinding.Render("[Tab]")+" Next  "+s.KeyBinding.Render("[Esc]")+" Cancel")

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

func (p *ServerPanel) viewRunningContent(width int, focused bool) string {
	s := p.styles

	elapsed := time.Since(*p.startTime)

	personalityName := serverPersonalities[p.personality]
	if p.useProfile && p.profileIndex < len(p.profiles) {
		personalityName = p.profiles[p.profileIndex]
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
	if p.startTime != nil {
		uptime = formatDuration(time.Since(*p.startTime).Seconds())
	}

	lines := []string{
		s.Dim.Render("■ Stopped"),
		"",
		fmt.Sprintf("Uptime: %s", uptime),
		fmt.Sprintf("Total Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Total Connections: %d", p.stats.TotalConnections),
		"",
		s.KeyBinding.Render("[Enter/Esc]") + " Dismiss  " + s.KeyBinding.Render("[r]") + " Restart",
	}

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
	files        []string
	styles       Styles
	focusedField int

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

var pcapModes = []string{"Summary", "Report", "Coverage", "Replay", "Rewrite", "Dump", "Diff"}

// NewPCAPPanel creates a new PCAP panel.
func NewPCAPPanel(styles Styles) *PCAPPanel {
	return &PCAPPanel{
		mode:       PanelIdle,
		styles:     styles,
		files:      []string{"ENIP.pcap", "stress_test.pcap", "baseline.pcap", "errors.pcap"},
		showVisual: true,
		packets:    generateSamplePackets(),
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
	// Get max fields for current mode
	maxField := p.getMaxFields()

	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
	case "enter":
		p.runAnalysis()
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
		// Tab always navigates fields within mode
		if maxField > 1 {
			p.focusedField = (p.focusedField + 1) % maxField
		}
	case "shift+tab":
		// Shift+Tab goes to previous field
		if maxField > 1 && p.focusedField > 0 {
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
	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
		p.analysis = nil
		p.diffAnalysis = nil
	case "v":
		// Toggle visual/text mode
		p.showVisual = !p.showVisual
	case "up":
		if p.modeIndex == 2 && p.selectedPkt > 0 { // Viewer mode
			p.selectedPkt--
		}
	case "down":
		if p.modeIndex == 2 && p.selectedPkt < len(p.packets)-1 { // Viewer mode
			p.selectedPkt++
		}
	case "pageup":
		if p.modeIndex == 2 {
			p.selectedPkt -= 5
			if p.selectedPkt < 0 {
				p.selectedPkt = 0
			}
		}
	case "pagedown":
		if p.modeIndex == 2 {
			p.selectedPkt += 5
			if p.selectedPkt >= len(p.packets) {
				p.selectedPkt = len(p.packets) - 1
			}
		}
	}
	return p, nil
}

func (p *PCAPPanel) runAnalysis() {
	p.mode = PanelResult

	switch p.modeIndex {
	case 0: // Summary
		p.analysis = &PCAPAnalysis{
			Filename:       p.files[p.selectedFile],
			TotalPackets:   1234,
			ENIPPackets:    1180,
			CIPRequests:    456,
			CIPResponses:   450,
			UniqueServices: 12,
			Duration:       5 * time.Minute,
			BytesTotal:     98432,
			AvgPacketSize:  80,
			PacketsPerSec:  4.1,
			TopServices: []ServiceCount{
				{"GetAttrSingle", 0x0E, 234},
				{"ReadTag", 0x4C, 156},
				{"WriteTag", 0x4D, 89},
				{"FwdOpen", 0x54, 45},
				{"FwdClose", 0x4E, 42},
			},
			ErrorCount: 6,
		}
	case 1: // Diff
		p.diffAnalysis = &PCAPDiffAnalysis{
			File1:          p.files[p.diffFile1],
			File2:          p.files[p.diffFile2],
			File1Packets:   1234,
			File2Packets:   1456,
			CommonServices: 8,
			OnlyInFile1:    []string{"MultiService", "Reset"},
			OnlyInFile2:    []string{"ListIdentity"},
			ServiceDiffs: []ServiceDiff{
				{"GetAttrSingle", 234, 198, -36},
				{"ReadTag", 156, 289, 133},
				{"WriteTag", 89, 92, 3},
				{"FwdOpen", 45, 67, 22},
			},
		}
	case 2: // Viewer
		// packets already loaded
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

func (p *PCAPPanel) viewIdleContent(width int, focused bool) string {
	s := p.styles
	content := []string{
		fmt.Sprintf("Mode: %s", s.Dim.Render(pcapModes[p.modeIndex])),
		fmt.Sprintf("Files: %d available", len(p.files)),
	}
	if len(p.files) > 0 {
		content = append(content, fmt.Sprintf("Selected: %s", s.Dim.Render(p.files[p.selectedFile])))
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
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+file)
		}

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
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile && p.focusedField == 0 {
				cursor = s.Selected.Render("> ")
			} else if i == p.selectedFile {
				cursor = s.Success.Render("● ")
			}
			lines = append(lines, cursor+file)
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
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+file)
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Output: {filename}_rewritten.pcap"))

	case 5: // Dump
		lines = append(lines, s.Header.Render("Hex dump by service code:"))
		lines = append(lines, "")
		// File selection
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile && p.focusedField == 0 {
				cursor = s.Selected.Render("> ")
			} else if i == p.selectedFile {
				cursor = s.Success.Render("● ")
			}
			lines = append(lines, cursor+file)
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
			lines = append(lines, fmt.Sprintf("%s%-18s  %s%s", left, p.files[i], right, p.files[i]))
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Use Left/Right to switch, Up/Down to select"))
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
	default:
		return p.viewSummaryResultContent(width, focused)
	}
}

func (p *PCAPPanel) viewReportResultContent(width int, focused bool) string {
	s := p.styles
	modeName := pcapModes[p.modeIndex]
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
	lines := []string{
		s.Success.Render("✓ Replay Complete"),
		"",
		fmt.Sprintf("Target:  %s", p.replayTargetIP),
		fmt.Sprintf("File:    %s", p.files[p.selectedFile]),
		fmt.Sprintf("Packets: %d sent", 1234), // placeholder
		"",
		s.KeyBinding.Render("[Esc]") + " Close",
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewRewriteResultContent(width int, focused bool) string {
	s := p.styles
	outputFile := strings.TrimSuffix(p.files[p.selectedFile], ".pcap") + "_rewritten.pcap"

	lines := []string{
		s.Success.Render("✓ Rewrite Complete"),
		"",
		s.Dim.Render("Input:  ") + p.files[p.selectedFile],
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
		serviceCode = "0x0E"
	}

	// Sample hex dump output
	lines := []string{
		s.Success.Render("✓ Dump for service " + serviceCode),
		"",
		s.Dim.Render("File: ") + p.files[p.selectedFile],
		s.Dim.Render("Matching packets: 45"),
		"",
		s.Header.Render("Sample:"),
		s.Dim.Render("0000: 65 00 04 00 00 00 00 00  e......."),
		s.Dim.Render("0008: 00 00 00 00 00 00 00 00  ........"),
		s.Dim.Render("0010: 00 00 00 00 00 00 00 00  ........"),
		"",
		s.KeyBinding.Render("[Esc]") + " Close",
	}
	return strings.Join(lines, "\n")
}

func (p *PCAPPanel) viewSummaryResultContent(width int, focused bool) string {
	s := p.styles
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

func (p *PCAPPanel) viewDiffResultContent(width int, focused bool) string {
	s := p.styles
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

	lines = append(lines, s.Header.Render("Packet Viewer: ")+p.files[p.selectedFile])
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
