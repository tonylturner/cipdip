package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MainScreenModel handles the dashboard screen.
type MainScreenModel struct {
	state  *AppState
	styles Styles
	model  *Model

	// Dashboard state
	trafficHistory []float64
	errorHistory   []float64
	latencyHistory []float64
	serviceStats   map[string]float64

	// Live stats from running operations
	clientStats StatsUpdate
	serverStats StatsUpdate

	// Scrolling hint banner
	hintIndex  int
	hintOffset int

	// Help panel
	showHelp bool
}

// Contextual hints for the scrolling banner
var contextualHints = map[string][]string{
	"idle": {
		"Press [c] to configure and run a client scenario",
		"Press [s] to start the server emulator",
		"Press [p] to analyze PCAP files",
		"Press [k] to browse the CIP object catalog",
		"Use [Tab] to cycle through panels",
	},
	"client_config": {
		"Use Tab to move between fields",
		"Press Enter to start the client",
		"Press Esc to cancel configuration",
		"Arrow keys change scenario selection",
	},
	"client_running": {
		"Client scenario is running - stats updating live",
		"Press Esc or x to stop the operation",
		"Watch the traffic graph for request rate",
	},
	"server_config": {
		"Configure server listen address and personality",
		"Press Enter to start listening",
		"Press Esc to cancel",
	},
	"server_running": {
		"Server is listening for connections",
		"Press Esc or x to stop the server",
		"Connection count shown in stats",
	},
	"pcap_config": {
		"Select a PCAP file and analysis mode",
		"Use arrow keys to navigate files",
		"Press Enter to analyze",
	},
}

// NewMainScreenModel creates a new dashboard model.
func NewMainScreenModel(state *AppState, styles Styles, model *Model) *MainScreenModel {
	m := &MainScreenModel{
		state:  state,
		styles: styles,
		model:  model,
		serviceStats: map[string]float64{
			"GetAttr":  45,
			"SetAttr":  12,
			"FwdOpen":  28,
			"FwdClose": 25,
			"ReadTag":  67,
			"WriteTag": 34,
		},
	}

	m.trafficHistory = GenerateTestData(60)
	m.errorHistory = make([]float64, 60)
	for i := range m.errorHistory {
		m.errorHistory[i] = float64(i % 5)
	}
	m.latencyHistory = make([]float64, 60)
	for i := range m.latencyHistory {
		m.latencyHistory[i] = 10 + float64(i%20)
	}

	return m
}

// UpdateStats updates live stats from running operations.
func (m *MainScreenModel) UpdateStats(clientStats, serverStats StatsUpdate) {
	m.clientStats = clientStats
	m.serverStats = serverStats

	if clientStats.TotalRequests > 0 || serverStats.TotalRequests > 0 {
		newVal := float64(clientStats.TotalRequests + serverStats.TotalRequests)
		m.trafficHistory = append(m.trafficHistory[1:], newVal)
	}

	// Advance hint banner
	m.hintOffset++
}

// Update handles input for the dashboard.
func (m *MainScreenModel) Update(msg tea.KeyMsg) (*MainScreenModel, tea.Cmd) {
	return m, nil
}

// View renders the dashboard.
func (m *MainScreenModel) View() string {
	fullWidth := 120
	fullHeight := 45

	_ = fullHeight // Will use for height calculations

	// Account for outer border (2 chars) and padding (2 chars)
	contentWidth := fullWidth - 4

	var sections []string

	// Header with scrolling hints
	sections = append(sections, m.renderHeader(contentWidth))

	// Top section: Traffic (left) | System + Stats (right)
	topSection := m.renderTopSection(contentWidth)
	sections = append(sections, topSection)

	// Middle row: Services | Recent Runs | Errors (same height)
	middleRow := m.renderMiddleRow(contentWidth)
	sections = append(sections, middleRow)

	// Active panel area
	activePanel := m.renderActivePanel(contentWidth)
	if activePanel != "" {
		sections = append(sections, activePanel)
	}

	content := JoinVertical(1, sections...)

	// Outer border
	outerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(DefaultTheme.Border).
		Padding(0, 1)

	return outerStyle.Render(content)
}

func (m *MainScreenModel) renderHeader(width int) string {
	s := m.styles

	// Title
	title := lipgloss.NewStyle().
		Foreground(DefaultTheme.Accent).
		Bold(true).
		Render("CIPDIP")

	// Status indicators
	var serverStatus, clientStatus string
	if m.state.ServerRunning {
		serverStatus = s.Success.Render("Server") + s.Success.Render("●")
	} else {
		serverStatus = s.Dim.Render("Server○")
	}
	if m.state.ClientRunning {
		clientStatus = s.Success.Render("Client") + s.Success.Render("●")
	} else {
		clientStatus = s.Dim.Render("Client○")
	}

	// Get contextual hint
	hint := m.getCurrentHint()
	hintStyle := lipgloss.NewStyle().Foreground(DefaultTheme.Info).Italic(true)
	hintText := hintStyle.Render(hint)

	// Build header
	left := title
	right := serverStatus + " " + clientStatus

	// Calculate space for hint
	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	hintSpace := width - leftWidth - rightWidth - 6
	if hintSpace < 20 {
		hintSpace = 20
	}

	// Truncate hint if needed
	if lipgloss.Width(hint) > hintSpace {
		hint = hint[:hintSpace-3] + "..."
		hintText = hintStyle.Render(hint)
	}

	padding := width - leftWidth - lipgloss.Width(hintText) - rightWidth - 2
	if padding < 1 {
		padding = 1
	}

	header := left + "  " + hintText + strings.Repeat(" ", padding) + right
	divider := s.Muted.Render(strings.Repeat("─", width))

	return header + "\n" + divider
}

func (m *MainScreenModel) getCurrentHint() string {
	context := "idle"

	if m.model != nil {
		switch m.model.GetEmbeddedPanel() {
		case EmbedClient:
			switch m.model.GetClientPanel().Mode() {
			case PanelConfig:
				context = "client_config"
			case PanelRunning:
				context = "client_running"
			}
		case EmbedServer:
			switch m.model.GetServerPanel().Mode() {
			case PanelConfig:
				context = "server_config"
			case PanelRunning:
				context = "server_running"
			}
		case EmbedPCAP:
			if m.model.GetPCAPPanel().Mode() == PanelConfig {
				context = "pcap_config"
			}
		}
	}

	hints := contextualHints[context]
	if len(hints) == 0 {
		hints = contextualHints["idle"]
	}

	idx := (m.hintOffset / 30) % len(hints) // Change hint every ~3 seconds
	return hints[idx]
}

func (m *MainScreenModel) renderTopSection(fullWidth int) string {
	gap := 2
	trafficWidth := 70
	rightWidth := fullWidth - trafficWidth - gap

	// Traffic panel (left)
	trafficPanel := m.renderTrafficGraph(trafficWidth)

	// Right column: System above Stats, vertically stacked
	rightColumn := m.renderRightColumn(rightWidth, trafficPanel)

	return JoinHorizontal(gap, trafficPanel, rightColumn)
}

func (m *MainScreenModel) renderRightColumn(width int, trafficPanel string) string {
	// Calculate heights to align bottom edges
	trafficHeight := strings.Count(trafficPanel, "\n") + 1

	// System panel (compact)
	systemPanel := m.renderSystemPanel(width)
	systemHeight := strings.Count(systemPanel, "\n") + 1

	// Stats panel fills remaining space
	statsHeight := trafficHeight - systemHeight - 1 // -1 for gap
	if statsHeight < 6 {
		statsHeight = 6
	}
	statsPanel := m.renderStatsPanel(width, statsHeight)

	return JoinVertical(1, systemPanel, statsPanel)
}

func (m *MainScreenModel) renderTrafficGraph(width int) string {
	s := m.styles

	graph := TrafficGraph{
		Title:   "TRAFFIC",
		Values:  m.trafficHistory,
		Width:   width - 4,
		Height:  8,
		ShowMax: true,
	}

	content := graph.Render(s)

	currentRate := m.trafficHistory[len(m.trafficHistory)-1]
	rateStr := fmt.Sprintf("Current: %.0f req/s", currentRate)
	content += "\n" + s.Dim.Render(rateStr)

	return m.panelBox("", content, width)
}

func (m *MainScreenModel) renderSystemPanel(width int) string {
	s := m.styles

	wsName := m.state.WorkspaceName
	if wsName == "" {
		wsName = filepath.Base(m.state.WorkspaceRoot)
	}
	if wsName == "" {
		wsName = "default"
	}

	items := [][]string{
		{"Workspace", wsName},
		{"Profiles", fmt.Sprintf("%d", len(m.state.Profiles))},
		{"Catalog", fmt.Sprintf("%d", len(m.state.Catalog))},
		{"Runs", fmt.Sprintf("%d", len(m.state.Runs))},
	}

	return m.panelBox("SYSTEM", MiniTable(items, s), width)
}

func (m *MainScreenModel) renderStatsPanel(width, height int) string {
	s := m.styles

	// Calculate stats - integrate with active panel
	totalRequests := float64(m.clientStats.TotalRequests + m.serverStats.TotalRequests)
	if totalRequests == 0 {
		for _, v := range m.trafficHistory {
			totalRequests += v
		}
	}

	avgLatency := 0.0
	for _, v := range m.latencyHistory {
		avgLatency += v
	}
	avgLatency /= float64(len(m.latencyHistory))

	totalErrors := float64(m.clientStats.TotalErrors + m.serverStats.TotalErrors)
	conns := m.serverStats.ActiveConnections

	// Format as 2x2 grid
	items := []string{
		BigNumber(formatNumber(totalRequests), "Total", DefaultTheme.Accent, s),
		BigNumber(fmt.Sprintf("%.1fms", avgLatency), "Latency", DefaultTheme.Success, s),
		BigNumber(formatNumber(totalErrors), "Errors", DefaultTheme.Error, s),
		BigNumber(fmt.Sprintf("%d", conns), "Conns", DefaultTheme.Info, s),
	}

	grid := Grid{Columns: 2, Gap: 2, Items: items}
	content := grid.Render(width - 4)

	// Pad to requested height
	contentLines := strings.Split(content, "\n")
	innerHeight := height - 3 // Account for box borders
	for len(contentLines) < innerHeight {
		contentLines = append(contentLines, "")
	}

	return m.panelBox("STATS", strings.Join(contentLines, "\n"), width)
}

func (m *MainScreenModel) renderMiddleRow(fullWidth int) string {
	gap := 2
	totalGaps := gap * 2 // Two gaps between three panels
	// Calculate panel widths to fill exactly fullWidth
	baseWidth := (fullWidth - totalGaps) / 3
	remainder := (fullWidth - totalGaps) % 3
	panelHeight := 8 // Fixed height for all three panels

	// Distribute remainder to first panels
	serviceWidth := baseWidth
	runsWidth := baseWidth
	errorsWidth := baseWidth
	if remainder >= 1 {
		serviceWidth++
	}
	if remainder >= 2 {
		runsWidth++
	}

	servicePanel := m.renderServicePanel(serviceWidth, panelHeight)
	runsPanel := m.renderRunsPanel(runsWidth, panelHeight)
	errorsPanel := m.renderErrorsPanel(errorsWidth, panelHeight)

	return JoinHorizontal(gap, servicePanel, runsPanel, errorsPanel)
}

func (m *MainScreenModel) renderServicePanel(width, height int) string {
	s := m.styles

	var items []BarChartItem
	colors := []lipgloss.Color{
		DefaultTheme.Accent, DefaultTheme.Success, DefaultTheme.Warning,
		DefaultTheme.Error, DefaultTheme.Info, DefaultTheme.Purple,
	}

	i := 0
	for name, value := range m.serviceStats {
		items = append(items, BarChartItem{
			Label: name,
			Value: value,
			Color: colors[i%len(colors)],
		})
		i++
		if i >= 5 {
			break
		}
	}

	chart := BarChart{Items: items, Width: width - 6}
	content := chart.Render(s)

	// Pad to height
	contentLines := strings.Split(content, "\n")
	innerHeight := height - 3
	for len(contentLines) < innerHeight {
		contentLines = append(contentLines, "")
	}

	return m.panelBox("SERVICES", strings.Join(contentLines, "\n"), width)
}

func (m *MainScreenModel) renderRunsPanel(width, height int) string {
	s := m.styles
	var lines []string

	if m.state.ServerRunning {
		lines = append(lines, StatusIcon("running", s)+" "+s.Running.Render("server")+" "+s.Dim.Render("running"))
	}
	if m.state.ClientRunning {
		lines = append(lines, StatusIcon("running", s)+" "+s.Running.Render("client")+" "+s.Dim.Render("running"))
	}

	for i, run := range m.state.Runs {
		if i >= 4 {
			lines = append(lines, s.Dim.Render(fmt.Sprintf("+%d more", len(m.state.Runs)-4)))
			break
		}
		name := filepath.Base(run)
		parts := strings.Split(name, "_")
		timeStr, runType := "", "run"
		if len(parts) >= 2 {
			if t, err := time.Parse("2006-01-02_15-04", parts[0]+"_"+parts[1]); err == nil {
				timeStr = t.Format("15:04")
			}
		}
		if len(parts) >= 3 {
			runType = parts[2]
		}
		lines = append(lines, fmt.Sprintf("%s %s %s", StatusIcon("success", s), s.Dim.Render(timeStr), runType))
	}

	if len(lines) == 0 {
		lines = append(lines, s.Dim.Render("No recent runs"))
	}

	// Pad to height
	innerHeight := height - 3
	for len(lines) < innerHeight {
		lines = append(lines, "")
	}

	return m.panelBox("RECENT RUNS", strings.Join(lines, "\n"), width)
}

func (m *MainScreenModel) renderErrorsPanel(width, height int) string {
	s := m.styles

	sampleErrors := []struct {
		time, msg, level string
	}{
		{"14:32", "Timeout", "warning"},
		{"14:28", "Invalid resp", "error"},
		{"14:15", "Retry ok", "success"},
	}

	var lines []string
	for _, err := range sampleErrors {
		lines = append(lines, fmt.Sprintf("%s %s %s", StatusIcon(err.level, s), s.Dim.Render(err.time), err.msg))
	}

	sparkline := Sparkline(m.errorHistory, width-10, s)
	lines = append(lines, "", s.Dim.Render("Rate:")+sparkline)

	// Pad to height
	innerHeight := height - 3
	for len(lines) < innerHeight {
		lines = append(lines, "")
	}

	return m.panelBox("ERRORS", strings.Join(lines, "\n"), width)
}

func (m *MainScreenModel) renderActivePanel(fullWidth int) string {
	if m.model == nil {
		return m.renderEmptyActivePanel(fullWidth)
	}

	embeddedPanel := m.model.GetEmbeddedPanel()
	if embeddedPanel == EmbedNone {
		return m.renderEmptyActivePanel(fullWidth)
	}

	panelWidth := fullWidth
	if m.showHelp {
		panelWidth = fullWidth - 34 // Reserve space for help
	}

	var panelContent, panelTitle string
	var helpContent string

	switch embeddedPanel {
	case EmbedClient:
		panel := m.model.GetClientPanel()
		panelTitle = panel.Title()
		panelContent = panel.ViewContent(panelWidth-4, true)
		helpContent = m.getClientHelp()
	case EmbedServer:
		panel := m.model.GetServerPanel()
		panelTitle = panel.Title()
		panelContent = panel.ViewContent(panelWidth-4, true)
		helpContent = m.getServerHelp()
	case EmbedPCAP:
		panel := m.model.GetPCAPPanel()
		panelTitle = panel.Title()
		panelContent = panel.ViewContent(panelWidth-4, true)
		helpContent = m.getPCAPHelp()
	case EmbedCatalog:
		panelTitle = "CATALOG"
		panelContent = m.renderCatalogContent(panelWidth - 4)
		helpContent = m.getCatalogHelp()
	}

	activeBox := m.renderActivePanelBox(panelTitle, panelContent, panelWidth)

	if m.showHelp && helpContent != "" {
		helpBox := m.renderHelpPanel(helpContent, 30)
		return JoinHorizontal(2, activeBox, helpBox)
	}

	return activeBox
}

func (m *MainScreenModel) renderEmptyActivePanel(width int) string {
	s := m.styles
	content := s.Dim.Render("Press [c] Client  [s] Server  [p] PCAP  [k] Catalog")
	return m.panelBox("SELECT ACTION", content, width)
}

func (m *MainScreenModel) renderActivePanelBox(name, content string, width int) string {
	s := m.styles
	innerWidth := width - 4
	if innerWidth < 1 {
		innerWidth = 1
	}
	borderWidth := width - 2

	borderStyle := lipgloss.NewStyle().Foreground(DefaultTheme.Accent)
	b := func(ch string) string { return borderStyle.Render(ch) }

	title := fmt.Sprintf(" %s ", name)
	titleLen := lipgloss.Width(title)
	remaining := borderWidth - titleLen - 1
	if remaining < 0 {
		remaining = 0
	}
	topLine := b("╭─") + s.Header.Render(title) + b(strings.Repeat("─", remaining)+"╮")

	var result strings.Builder
	result.WriteString(topLine + "\n")

	for _, line := range strings.Split(content, "\n") {
		lineWidth := lipgloss.Width(line)
		if lineWidth > innerWidth {
			line = lipgloss.NewStyle().MaxWidth(innerWidth).Render(line)
		}
		paddedLine := lipgloss.PlaceHorizontal(innerWidth, lipgloss.Left, line)
		result.WriteString(b("│") + " " + paddedLine + " " + b("│") + "\n")
	}

	result.WriteString(b("╰" + strings.Repeat("─", borderWidth) + "╯"))
	return result.String()
}

// truncateToWidth truncates a string to fit within the specified visible width.
func truncateToWidth(s string, maxWidth int) string {
	if maxWidth < 3 {
		maxWidth = 3
	}
	if lipgloss.Width(s) <= maxWidth {
		return s
	}
	// Strip ANSI codes, truncate, but this loses styling
	// Instead, truncate rune by rune until we fit
	runes := []rune(s)
	for i := len(runes); i > 0; i-- {
		candidate := string(runes[:i])
		if lipgloss.Width(candidate) <= maxWidth-3 {
			return candidate + "..."
		}
	}
	return "..."
}

func (m *MainScreenModel) renderHelpPanel(content string, width int) string {
	s := m.styles
	innerWidth := width - 4
	if innerWidth < 1 {
		innerWidth = 1
	}
	borderWidth := width - 2

	borderStyle := lipgloss.NewStyle().Foreground(DefaultTheme.Info)
	b := func(ch string) string { return borderStyle.Render(ch) }

	title := " HELP "
	titleLen := lipgloss.Width(title)
	remaining := borderWidth - titleLen - 1
	if remaining < 0 {
		remaining = 0
	}
	topLine := b("╭─") + s.Header.Render(title) + b(strings.Repeat("─", remaining)+"╮")

	var result strings.Builder
	result.WriteString(topLine + "\n")

	for _, line := range strings.Split(content, "\n") {
		lineWidth := lipgloss.Width(line)
		if lineWidth > innerWidth {
			line = lipgloss.NewStyle().MaxWidth(innerWidth).Render(line)
		}
		paddedLine := lipgloss.PlaceHorizontal(innerWidth, lipgloss.Left, line)
		result.WriteString(b("│") + " " + paddedLine + " " + b("│") + "\n")
	}

	result.WriteString(b("╰" + strings.Repeat("─", borderWidth) + "╯"))
	return result.String()
}

func (m *MainScreenModel) getClientHelp() string {
	return `CLIENT HELP

Config:
  Tab      Next field
  Up/Down  Change scenario
  Enter    Start client
  Esc      Cancel

Running:
  Esc/x    Stop client

Result:
  Enter    Dismiss
  r        Re-run`
}

func (m *MainScreenModel) getServerHelp() string {
	return `SERVER HELP

Config:
  Tab      Next field
  Up/Down  Change personality
  Enter    Start server
  Esc      Cancel

Running:
  Esc/x    Stop server

Listening:
  Connections shown
  in stats panel`
}

func (m *MainScreenModel) getPCAPHelp() string {
	return `PCAP HELP

Modes:
  Summary  Quick stats
  Report   Full report
  Coverage Service coverage
  Replay   Re-send packets
  Rewrite  Modify IPs/MACs
  Dump     Hex dump
  Diff     Compare files

Navigation:
  ←/→      Change mode
  Tab      Next field
  Up/Down  Select file
  Enter    Analyze
  Esc      Cancel`
}

func (m *MainScreenModel) getCatalogHelp() string {
	return `CATALOG HELP

Browse CIP objects
and definitions.

Navigation:
  Up/Down  Select item
  Enter    View details
  /        Search
  Esc      Close

Categories:
  Identity objects
  Network objects
  Application objects`
}

func (m *MainScreenModel) renderCatalogContent(width int) string {
	s := m.styles

	categories := []struct {
		name  string
		items []string
	}{
		{"Identity", []string{"Identity (0x01)", "MsgRouter (0x02)", "Assembly (0x04)"}},
		{"Network", []string{"TCP/IP (0xF5)", "EthLink (0xF6)", "ConnMgr (0x06)"}},
		{"Application", []string{"Parameter (0x0F)", "File (0x37)", "TimeSync (0x43)"}},
	}

	var lines []string
	for _, cat := range categories {
		lines = append(lines, s.Header.Render(cat.name))
		for _, item := range cat.items {
			lines = append(lines, "  "+item)
		}
		lines = append(lines, "")
	}

	// Pad content
	for len(lines) < 10 {
		lines = append(lines, "")
	}

	return strings.Join(lines, "\n")
}

func (m *MainScreenModel) panelBox(title, content string, width int) string {
	s := m.styles
	innerWidth := width - 4 // Content area width (excluding borders and padding)
	if innerWidth < 1 {
		innerWidth = 1
	}
	borderWidth := width - 2 // Width between corner chars (innerWidth + 2 for padding spaces)

	borderStyle := lipgloss.NewStyle().Foreground(DefaultTheme.Border)
	b := func(ch string) string { return borderStyle.Render(ch) }

	// Build title bar - total width should be: ╭ + borderWidth + ╮ = width
	var topLine string
	if title != "" {
		titleText := " " + title + " "
		titleLen := lipgloss.Width(titleText)
		remaining := borderWidth - titleLen - 1 // -1 for the first ─ after ╭
		if remaining < 0 {
			remaining = 0
		}
		topLine = b("╭─") + s.Header.Render(titleText) + b(strings.Repeat("─", remaining)+"╮")
	} else {
		topLine = b("╭" + strings.Repeat("─", borderWidth) + "╮")
	}

	// Process content lines - truncate if too wide, then pad to exact width
	contentLines := strings.Split(content, "\n")
	var paddedLines []string
	for _, line := range contentLines {
		lineWidth := lipgloss.Width(line)
		if lineWidth > innerWidth {
			line = lipgloss.NewStyle().MaxWidth(innerWidth).Render(line)
		}
		paddedLine := lipgloss.PlaceHorizontal(innerWidth, lipgloss.Left, line)
		paddedLines = append(paddedLines, paddedLine)
	}

	// Build box - content lines: │ + space + content + space + │ = width
	var result strings.Builder
	result.WriteString(topLine + "\n")
	for _, line := range paddedLines {
		result.WriteString(b("│") + " " + line + " " + b("│") + "\n")
	}
	result.WriteString(b("╰" + strings.Repeat("─", borderWidth) + "╯"))

	return result.String()
}

// ToggleHelp toggles the help panel.
func (m *MainScreenModel) ToggleHelp() {
	m.showHelp = !m.showHelp
}

// Footer returns the footer text.
func (m *MainScreenModel) Footer() string {
	s := m.styles

	// Left side: panel shortcuts
	left := fmt.Sprintf("%s%s  %s%s  %s%s  %s%s",
		s.KeyBinding.Render("[c]"), s.Dim.Render("Client"),
		s.KeyBinding.Render("[s]"), s.Dim.Render("Server"),
		s.KeyBinding.Render("[p]"), s.Dim.Render("PCAP"),
		s.KeyBinding.Render("[k]"), s.Dim.Render("Catalog"),
	)

	// Right side: global shortcuts
	right := fmt.Sprintf("%s%s  %s%s  %s%s",
		s.KeyBinding.Render("[Tab]"), s.Dim.Render("Cycle"),
		s.KeyBinding.Render("[h]"), s.Dim.Render("Help"),
		s.KeyBinding.Render("[q]"), s.Dim.Render("Quit"),
	)

	// Add panel-specific hints
	var middle string
	if m.model != nil && m.model.GetEmbeddedPanel() != EmbedNone {
		panel := m.model.getActiveEmbeddedPanel()
		if panel != nil {
			switch panel.Mode() {
			case PanelConfig:
				middle = s.Info.Render("[Enter]Start [Esc]Cancel")
			case PanelRunning:
				middle = s.Warning.Render("[Esc]Stop")
			case PanelResult:
				middle = s.Success.Render("[Enter]OK [r]Re-run")
			}
		}
	}

	if middle != "" {
		return left + "  |  " + middle + "  |  " + right
	}
	return left + "  |  " + right
}
