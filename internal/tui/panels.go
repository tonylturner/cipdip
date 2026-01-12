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

	// Config fields
	targetIP string
	port     string
	scenario int
	duration string

	// Running stats
	stats        StatsUpdate
	statsHistory []float64
	startTime    *time.Time

	// Result
	result *CommandResult
}

var clientScenarios = []string{"baseline", "stress", "io", "edge", "mixed"}

// NewClientPanel creates a new client panel.
func NewClientPanel(styles Styles) *ClientPanel {
	return &ClientPanel{
		mode:     PanelIdle,
		styles:   styles,
		targetIP: "192.168.1.100",
		port:     "44818",
		scenario: 0,
		duration: "120",
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
	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
	case "enter":
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.stats = StatsUpdate{}
		p.statsHistory = nil
		// TODO: actually start client operation
	case "tab":
		p.focusedField = (p.focusedField + 1) % 4
	case "shift+tab":
		p.focusedField = (p.focusedField - 1 + 4) % 4
	case "up":
		if p.focusedField == 2 { // scenario field
			if p.scenario > 0 {
				p.scenario--
			}
		}
	case "down":
		if p.focusedField == 2 { // scenario field
			if p.scenario < len(clientScenarios)-1 {
				p.scenario++
			}
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

func (p *ClientPanel) handleBackspace() {
	switch p.focusedField {
	case 0:
		if len(p.targetIP) > 0 {
			p.targetIP = p.targetIP[:len(p.targetIP)-1]
		}
	case 1:
		if len(p.port) > 0 {
			p.port = p.port[:len(p.port)-1]
		}
	case 3:
		if len(p.duration) > 0 {
			p.duration = p.duration[:len(p.duration)-1]
		}
	}
}

func (p *ClientPanel) handleChar(ch string) {
	switch p.focusedField {
	case 0:
		if ch == "." || (ch >= "0" && ch <= "9") {
			p.targetIP += ch
		}
	case 1:
		if ch >= "0" && ch <= "9" {
			p.port += ch
		}
	case 3:
		if ch >= "0" && ch <= "9" {
			p.duration += ch
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
	switch p.mode {
	case PanelConfig:
		return p.viewConfig(width, focused)
	case PanelRunning:
		return p.viewRunning(width, focused)
	case PanelResult:
		return p.viewResult(width, focused)
	default:
		return p.viewIdle(width, focused)
	}
}

func (p *ClientPanel) viewIdle(width int, focused bool) string {
	s := p.styles
	content := []string{
		fmt.Sprintf("Target: %s", s.Dim.Render(p.targetIP)),
		fmt.Sprintf("Scenario: %s", s.Dim.Render(clientScenarios[p.scenario])),
		"Status: " + s.Dim.Render("idle"),
		"",
	}
	if focused {
		content = append(content, s.KeyBinding.Render("[Enter]")+" Configure")
	} else {
		content = append(content, s.Dim.Render("[c] Configure"))
	}
	return p.renderBox("CLIENT", strings.Join(content, "\n"), width, focused, DefaultTheme.Info)
}

func (p *ClientPanel) viewConfig(width int, focused bool) string {
	s := p.styles
	var lines []string

	// Target IP field
	label := "Target IP"
	value := p.targetIP
	if p.focusedField == 0 {
		lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render(" "))
	} else {
		lines = append(lines, s.Dim.Render(label)+": "+value)
	}

	// Port field
	label = "Port"
	value = p.port
	if p.focusedField == 1 {
		lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render(" "))
	} else {
		lines = append(lines, s.Dim.Render(label)+": "+value)
	}

	// Scenario field
	for i, sc := range clientScenarios {
		radio := "( )"
		if i == p.scenario {
			radio = s.Success.Render("(●)")
		}
		style := s.Dim
		if p.focusedField == 2 && i == p.scenario {
			style = s.Selected
		}
		lines = append(lines, "  "+radio+" "+style.Render(sc))
	}

	// Duration field
	label = "Duration"
	value = p.duration + "s"
	if p.focusedField == 3 {
		lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render(" "))
	} else {
		lines = append(lines, s.Dim.Render(label)+": "+value)
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Start  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return p.renderBox("CLIENT (Config)", strings.Join(lines, "\n"), width, focused, DefaultTheme.Accent)
}

func (p *ClientPanel) viewRunning(width int, focused bool) string {
	s := p.styles

	elapsed := time.Since(*p.startTime)
	lines := []string{
		s.Running.Render("● RUNNING"),
		"",
		fmt.Sprintf("Target: %s", p.targetIP),
		fmt.Sprintf("Scenario: %s", clientScenarios[p.scenario]),
		fmt.Sprintf("Elapsed: %s", formatDuration(elapsed.Seconds())),
		"",
		fmt.Sprintf("Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Success: %s", s.Success.Render(fmt.Sprintf("%d", p.stats.SuccessfulRequests))),
		fmt.Sprintf("Errors: %s", s.Error.Render(fmt.Sprintf("%d", p.stats.TotalErrors))),
	}

	// Mini sparkline
	if len(p.statsHistory) > 0 {
		lines = append(lines, "")
		lines = append(lines, renderMiniSparkline(p.statsHistory, width-6, s))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Esc/x]")+" Stop")

	return p.renderBox("CLIENT", strings.Join(lines, "\n"), width, focused, DefaultTheme.Running)
}

func (p *ClientPanel) viewResult(width int, focused bool) string {
	s := p.styles

	status := s.Success.Render("Completed")
	if p.result != nil && p.result.ExitCode != 0 {
		status = s.Error.Render("Failed")
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

	return p.renderBox("CLIENT (Result)", strings.Join(lines, "\n"), width, focused, DefaultTheme.Success)
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

	// Config fields
	listenAddr  string
	port        string
	personality int

	// Running stats
	stats        StatsUpdate
	connections  []string
	statsHistory []float64
	startTime    *time.Time

	// Result
	result *CommandResult
}

var serverPersonalities = []string{"adapter", "logix_like", "minimal"}

// NewServerPanel creates a new server panel.
func NewServerPanel(styles Styles) *ServerPanel {
	return &ServerPanel{
		mode:        PanelIdle,
		styles:      styles,
		listenAddr:  "0.0.0.0",
		port:        "44818",
		personality: 0,
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
	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
	case "enter":
		p.mode = PanelRunning
		now := time.Now()
		p.startTime = &now
		p.stats = StatsUpdate{}
		p.statsHistory = nil
		// TODO: actually start server operation
	case "tab":
		p.focusedField = (p.focusedField + 1) % 3
	case "shift+tab":
		p.focusedField = (p.focusedField - 1 + 3) % 3
	case "up":
		if p.focusedField == 2 {
			if p.personality > 0 {
				p.personality--
			}
		}
	case "down":
		if p.focusedField == 2 {
			if p.personality < len(serverPersonalities)-1 {
				p.personality++
			}
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
	switch p.mode {
	case PanelConfig:
		return p.viewConfig(width, focused)
	case PanelRunning:
		return p.viewRunning(width, focused)
	case PanelResult:
		return p.viewResult(width, focused)
	default:
		return p.viewIdle(width, focused)
	}
}

func (p *ServerPanel) viewIdle(width int, focused bool) string {
	s := p.styles
	content := []string{
		fmt.Sprintf("Listen: %s:%s", s.Dim.Render(p.listenAddr), s.Dim.Render(p.port)),
		fmt.Sprintf("Personality: %s", s.Dim.Render(serverPersonalities[p.personality])),
		"Status: " + s.Dim.Render("stopped"),
		"",
	}
	if focused {
		content = append(content, s.KeyBinding.Render("[Enter]")+" Configure")
	} else {
		content = append(content, s.Dim.Render("[s] Configure"))
	}
	return p.renderBox("SERVER", strings.Join(content, "\n"), width, focused, DefaultTheme.Success)
}

func (p *ServerPanel) viewConfig(width int, focused bool) string {
	s := p.styles
	var lines []string

	// Listen addr field
	label := "Listen"
	value := p.listenAddr
	if p.focusedField == 0 {
		lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render(" "))
	} else {
		lines = append(lines, s.Dim.Render(label)+": "+value)
	}

	// Port field
	label = "Port"
	value = p.port
	if p.focusedField == 1 {
		lines = append(lines, s.Selected.Render(label)+": "+value+s.Cursor.Render(" "))
	} else {
		lines = append(lines, s.Dim.Render(label)+": "+value)
	}

	// Personality field
	for i, pers := range serverPersonalities {
		radio := "( )"
		if i == p.personality {
			radio = s.Success.Render("(●)")
		}
		style := s.Dim
		if p.focusedField == 2 && i == p.personality {
			style = s.Selected
		}
		lines = append(lines, "  "+radio+" "+style.Render(pers))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Enter]")+" Start  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return p.renderBox("SERVER (Config)", strings.Join(lines, "\n"), width, focused, DefaultTheme.Accent)
}

func (p *ServerPanel) viewRunning(width int, focused bool) string {
	s := p.styles

	elapsed := time.Since(*p.startTime)
	lines := []string{
		s.Running.Render("● LISTENING"),
		"",
		fmt.Sprintf("Address: %s:%s", p.listenAddr, p.port),
		fmt.Sprintf("Personality: %s", serverPersonalities[p.personality]),
		fmt.Sprintf("Uptime: %s", formatDuration(elapsed.Seconds())),
		"",
		fmt.Sprintf("Connections: %d", p.stats.ActiveConnections),
		fmt.Sprintf("Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Errors: %s", s.Error.Render(fmt.Sprintf("%d", p.stats.TotalErrors))),
	}

	// Mini sparkline
	if len(p.statsHistory) > 0 {
		lines = append(lines, "")
		lines = append(lines, renderMiniSparkline(p.statsHistory, width-6, s))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Esc/x]")+" Stop")

	return p.renderBox("SERVER", strings.Join(lines, "\n"), width, focused, DefaultTheme.Running)
}

func (p *ServerPanel) viewResult(width int, focused bool) string {
	s := p.styles

	var uptime string
	if p.startTime != nil {
		uptime = formatDuration(time.Since(*p.startTime).Seconds())
	}

	lines := []string{
		s.Dim.Render("Stopped"),
		"",
		fmt.Sprintf("Uptime: %s", uptime),
		fmt.Sprintf("Total Requests: %d", p.stats.TotalRequests),
		fmt.Sprintf("Total Connections: %d", p.stats.TotalConnections),
		"",
		s.KeyBinding.Render("[Enter/Esc]") + " Dismiss  " + s.KeyBinding.Render("[r]") + " Restart",
	}

	return p.renderBox("SERVER (Stopped)", strings.Join(lines, "\n"), width, focused, DefaultTheme.TextDim)
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
	modeIndex    int // 0=Summary, 1=Diff, 2=Viewer, 3=Export
	selectedFile int
	files        []string
	styles       Styles

	// For diff mode
	diffFile1     int
	diffFile2     int
	diffSelectIdx int // 0=file1, 1=file2

	// For viewer mode
	viewerOffset  int
	selectedPkt   int
	packets       []PacketInfo

	// Display options
	showVisual bool // Toggle between visual and text metrics

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

var pcapModes = []string{"Summary", "Diff", "Viewer", "Export"}

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
	switch msg.String() {
	case "esc":
		p.mode = PanelIdle
	case "enter":
		p.runAnalysis()
	case "tab":
		p.modeIndex = (p.modeIndex + 1) % len(pcapModes)
		// Reset selections when changing modes
		if p.modeIndex == 1 { // Diff mode
			p.diffFile1 = 0
			p.diffFile2 = 1
			p.diffSelectIdx = 0
		}
	case "shift+tab":
		p.modeIndex = (p.modeIndex - 1 + len(pcapModes)) % len(pcapModes)
	case "up":
		if p.modeIndex == 1 { // Diff mode
			if p.diffSelectIdx == 0 && p.diffFile1 > 0 {
				p.diffFile1--
			} else if p.diffSelectIdx == 1 && p.diffFile2 > 0 {
				p.diffFile2--
			}
		} else {
			if p.selectedFile > 0 {
				p.selectedFile--
			}
		}
	case "down":
		if p.modeIndex == 1 { // Diff mode
			if p.diffSelectIdx == 0 && p.diffFile1 < len(p.files)-1 {
				p.diffFile1++
			} else if p.diffSelectIdx == 1 && p.diffFile2 < len(p.files)-1 {
				p.diffFile2++
			}
		} else {
			if p.selectedFile < len(p.files)-1 {
				p.selectedFile++
			}
		}
	case "left", "right":
		if p.modeIndex == 1 { // Diff mode - switch between file selectors
			p.diffSelectIdx = 1 - p.diffSelectIdx
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
	switch p.mode {
	case PanelConfig:
		return p.viewConfig(width, focused)
	case PanelRunning:
		return p.viewRunning(width, focused)
	case PanelResult:
		return p.viewResult(width, focused)
	default:
		return p.viewIdle(width, focused)
	}
}

func (p *PCAPPanel) viewIdle(width int, focused bool) string {
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
	return p.renderBox("PCAP", strings.Join(content, "\n"), width, focused, DefaultTheme.Purple)
}

func (p *PCAPPanel) viewConfig(width int, focused bool) string {
	s := p.styles
	var lines []string

	// Mode tabs
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
		lines = append(lines, s.Header.Render("Select file to analyze:"))
		lines = append(lines, "")
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+file)
		}

	case 1: // Diff - side by side file selection
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

	case 2: // Viewer
		lines = append(lines, s.Header.Render("Select file to view packets:"))
		lines = append(lines, "")
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+file)
		}

	case 3: // Export
		lines = append(lines, s.Header.Render("Export analysis results:"))
		lines = append(lines, "")
		for i, file := range p.files {
			cursor := "  "
			if i == p.selectedFile {
				cursor = s.Selected.Render("> ")
			}
			lines = append(lines, cursor+file)
		}
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Formats: JSON, CSV, Markdown"))
	}

	lines = append(lines, "")
	lines = append(lines, s.KeyBinding.Render("[Tab]")+" Mode  "+s.KeyBinding.Render("[Enter]")+" Run  "+s.KeyBinding.Render("[Esc]")+" Cancel")

	return p.renderBox("PCAP", strings.Join(lines, "\n"), width, focused, DefaultTheme.Accent)
}

func (p *PCAPPanel) viewRunning(width int, focused bool) string {
	s := p.styles
	lines := []string{
		s.Running.Render("● ANALYZING..."),
		"",
		"Processing packets...",
		"",
		ProgressBar("Progress", 67, width-10, s),
	}
	return p.renderBox("PCAP", strings.Join(lines, "\n"), width, focused, DefaultTheme.Running)
}

func (p *PCAPPanel) viewResult(width int, focused bool) string {
	switch p.modeIndex {
	case 0:
		return p.viewSummaryResult(width, focused)
	case 1:
		return p.viewDiffResult(width, focused)
	case 2:
		return p.viewPacketViewer(width, focused)
	default:
		return p.viewSummaryResult(width, focused)
	}
}

func (p *PCAPPanel) viewSummaryResult(width int, focused bool) string {
	s := p.styles
	if p.analysis == nil {
		return p.viewIdle(width, focused)
	}

	a := p.analysis
	var lines []string

	lines = append(lines, s.Success.Render("Analysis: ")+a.Filename)
	lines = append(lines, "")

	if p.showVisual {
		// Visual metrics with bars
		lines = append(lines, p.renderMetricBar("Packets", float64(a.TotalPackets), 2000, width-8, s))
		lines = append(lines, p.renderMetricBar("CIP Req", float64(a.CIPRequests), 500, width-8, s))
		lines = append(lines, p.renderMetricBar("CIP Rsp", float64(a.CIPResponses), 500, width-8, s))
		lines = append(lines, p.renderMetricBar("Errors", float64(a.ErrorCount), 50, width-8, s))
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

	return p.renderBox("PCAP Summary", strings.Join(lines, "\n"), width, focused, DefaultTheme.Success)
}

func (p *PCAPPanel) viewDiffResult(width int, focused bool) string {
	s := p.styles
	if p.diffAnalysis == nil {
		return p.viewIdle(width, focused)
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

	return p.renderBox("PCAP Diff", strings.Join(lines, "\n"), width, focused, DefaultTheme.Info)
}

func (p *PCAPPanel) viewPacketViewer(width int, focused bool) string {
	s := p.styles
	var lines []string

	lines = append(lines, s.Header.Render("Packet Viewer: ")+p.files[p.selectedFile])
	lines = append(lines, "")

	// Column headers
	hdr := fmt.Sprintf("  %-4s %-9s %-4s %-4s %-10s %-3s %-3s %s",
		"#", "Time", "Proto", "Len", "Service", "Dir", "Sts", "Summary")
	lines = append(lines, s.SectionName.Render(hdr))
	lines = append(lines, s.Muted.Render("  "+strings.Repeat("─", width-6)))

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

	return p.renderBox("PCAP Viewer", strings.Join(lines, "\n"), width, focused, DefaultTheme.Purple)
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
