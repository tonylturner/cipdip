package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tonylturner/cipdip/internal/pcap"
)

// MainScreenModel handles the dashboard screen.
type MainScreenModel struct {
	state  *AppState
	styles Styles
	model  *Model

	// Dashboard state - real data (colored series)
	readHistory   []float64 // Read operations (GetAttr, ReadTag, etc.)
	writeHistory  []float64 // Write operations (SetAttr, WriteTag, etc.)
	errorHistory  []float64 // Errors
	otherHistory  []float64 // Other traffic (Forward_Open, etc.)
	trafficHistory []float64 // Total (kept for backwards compat)
	latencyHistory []float64
	serviceStats   map[string]float64

	// Live stats from running operations
	clientStats StatsUpdate
	serverStats StatsUpdate

	// Accumulated stats
	totalRequests   int
	totalReads      int
	totalWrites     int
	totalErrors     int
	totalLatencySum float64
	latencyCount    int

	// TCP-level metrics from PCAP
	tcpRetransmits    int
	tcpResets         int
	tcpLostSegments   int
	cipErrorResponses int

	// Error log
	recentErrors []ErrorEntry

	// Data source tracking
	hasLiveData     bool
	hasPCAPData     bool
	pcapSource      string
	asyncInitDone   bool

	// Scrolling hint banner
	hintIndex  int
	hintOffset int

	// Help panel
	showHelp bool
}

// ErrorEntry represents a logged error.
type ErrorEntry struct {
	Time    time.Time
	Message string
	Level   string // "error", "warning", "info"
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
		state:          state,
		styles:         styles,
		model:          model,
		serviceStats:   make(map[string]float64),
		recentErrors:   make([]ErrorEntry, 0),
		readHistory:    make([]float64, 60),
		writeHistory:   make([]float64, 60),
		errorHistory:   make([]float64, 60),
		otherHistory:   make([]float64, 60),
		trafficHistory: make([]float64, 60),
		latencyHistory: make([]float64, 60),
	}

	// Use placeholder data initially for fast startup
	// PCAP data will be loaded lazily on first tick
	m.usePlaceholderData()

	return m
}

// InitAsync performs async initialization after the UI is displayed.
// Call this from the first tick to load PCAP data in the background.
func (m *MainScreenModel) InitAsync() {
	if m.asyncInitDone || m.hasPCAPData || m.hasLiveData {
		return // Already initialized or in progress
	}
	m.asyncInitDone = true

	// Load PCAP data in background (this can be slow)
	go func() {
		m.loadPCAPFallback()
	}()
}

// LoadFromPCAP loads dashboard data from a specific PCAP file.
func (m *MainScreenModel) LoadFromPCAP(pcapPath string) error {
	if _, err := os.Stat(pcapPath); err != nil {
		return err
	}
	summary, err := pcap.SummarizeENIPFromPCAP(pcapPath)
	if err != nil {
		return err
	}
	m.loadFromPCAPSummary(summary)
	m.pcapSource = pcapPath
	m.hasPCAPData = true
	m.hasLiveData = false
	return nil
}

// loadPCAPFallback loads stats from PCAP files in /pcaps directory.
func (m *MainScreenModel) loadPCAPFallback() {
	var pcapPaths []string

	if m.state == nil {
		return
	}

	// Priority 1: Main ENIP.pcap from repo root (has the most data)
	if m.state.WorkspaceRoot != "" {
		repoRoot := filepath.Dir(filepath.Dir(m.state.WorkspaceRoot))
		pcapPaths = append(pcapPaths,
			filepath.Join(repoRoot, "pcaps", "ENIP.pcap"),
			filepath.Join(repoRoot, "pcaps", "stress", "ENIP.pcap"),
		)
	}

	// Priority 2: Relative to current working directory
	pcapPaths = append(pcapPaths,
		"pcaps/ENIP.pcap",
		"pcaps/stress/ENIP.pcap",
	)

	// Priority 3: Relative to executable location
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		pcapPaths = append(pcapPaths,
			filepath.Join(exeDir, "pcaps", "ENIP.pcap"),
			filepath.Join(exeDir, "..", "pcaps", "ENIP.pcap"),
		)
	}

	// Priority 4: Workspace pcaps (smaller, less complete)
	if m.state.WorkspaceRoot != "" {
		wsPath := filepath.Join(m.state.WorkspaceRoot, "pcaps")
		if entries, err := os.ReadDir(wsPath); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".pcap") {
					pcapPaths = append(pcapPaths, filepath.Join(wsPath, e.Name()))
				}
			}
		}
	}

	for _, path := range pcapPaths {
		if _, err := os.Stat(path); err == nil {
			if summary, err := pcap.SummarizeENIPFromPCAP(path); err == nil {
				// Only use this PCAP if it has useful data
				if len(summary.CIPServices) > 0 || summary.ENIPPackets > 100 {
					m.loadFromPCAPSummary(summary)
					m.pcapSource = path
					m.hasPCAPData = true
					return
				}
			}
		}
	}
}

// isReadService returns true if the service is a read operation.
func isReadService(name string) bool {
	reads := []string{
		"Get_Attribute_Single", "Get_Attribute_All", "Get_Attributes_All",
		"Read_Tag", "Read_Tag_Fragmented", "Get_Member",
		"GetAttr", "GetAll", "ReadTag", "ReadFrag",
	}
	for _, r := range reads {
		if strings.Contains(name, r) {
			return true
		}
	}
	return false
}

// isWriteService returns true if the service is a write operation.
func isWriteService(name string) bool {
	writes := []string{
		"Set_Attribute_Single", "Set_Attribute_All", "Set_Attributes_All",
		"Write_Tag", "Write_Tag_Fragmented", "Set_Member",
		"SetAttr", "WriteTag", "WriteFrag",
	}
	for _, w := range writes {
		if strings.Contains(name, w) {
			return true
		}
	}
	return false
}

// loadFromPCAPSummary populates dashboard stats from PCAP analysis.
func (m *MainScreenModel) loadFromPCAPSummary(summary *pcap.PCAPSummary) {
	// Service stats and categorization
	m.serviceStats = make(map[string]float64)
	var totalReads, totalWrites, totalOther int

	for svc, count := range summary.CIPServices {
		// Shorten service names for display
		shortName := shortenServiceName(svc)
		m.serviceStats[shortName] = float64(count)

		// Categorize
		if isReadService(svc) {
			totalReads += count
		} else if isWriteService(svc) {
			totalWrites += count
		} else {
			totalOther += count
		}
	}

	m.totalReads = totalReads
	m.totalWrites = totalWrites

	// Store TCP-level metrics
	m.tcpRetransmits = summary.TCPRetransmits
	m.tcpResets = summary.TCPResets
	m.tcpLostSegments = summary.TCPLostSegments
	m.cipErrorResponses = summary.CIPErrorResponses

	// Calculate total errors including TCP issues
	totalTCPErrors := summary.TCPRetransmits + summary.TCPResets + summary.TCPLostSegments
	totalAllErrors := summary.RequestValidationFailed + totalTCPErrors + summary.CIPErrorResponses

	// Generate traffic history with colored series
	duration := 60.0
	readsPerSec := float64(totalReads) / duration
	writesPerSec := float64(totalWrites) / duration
	baseErrorsPerSec := float64(totalAllErrors) / duration
	otherPerSec := float64(totalOther) / duration

	for i := 0; i < 60; i++ {
		// Add variance to make the graph more interesting
		variance := 0.7 + (float64(i%10) / 15.0)
		m.readHistory[i] = readsPerSec * variance
		m.writeHistory[i] = writesPerSec * (0.8 + float64((i+5)%10)/20.0)
		m.otherHistory[i] = otherPerSec * (0.9 + float64((i+3)%8)/25.0)

		// Error history with spikes for retransmits
		m.errorHistory[i] = baseErrorsPerSec * (0.5 + float64(i%5)/10.0)
		// Add spikes at intervals to represent retransmit bursts
		if totalTCPErrors > 0 && (i%12 == 3 || i%12 == 7) {
			spikeAmount := float64(totalTCPErrors) / 10.0
			m.errorHistory[i] += spikeAmount
		}

		// Total for backwards compat
		m.trafficHistory[i] = m.readHistory[i] + m.writeHistory[i] + m.errorHistory[i] + m.otherHistory[i]
	}

	// Populate error entries from validation errors and TCP issues
	m.recentErrors = nil

	// Add TCP-level errors first (most important)
	if summary.TCPRetransmits > 0 {
		m.recentErrors = append(m.recentErrors, ErrorEntry{
			Time:    time.Time{},
			Message: fmt.Sprintf("TCP retransmits (×%d)", summary.TCPRetransmits),
			Level:   "error",
		})
	}
	if summary.TCPResets > 0 {
		m.recentErrors = append(m.recentErrors, ErrorEntry{
			Time:    time.Time{},
			Message: fmt.Sprintf("TCP resets (×%d)", summary.TCPResets),
			Level:   "error",
		})
	}
	if summary.TCPLostSegments > 0 {
		m.recentErrors = append(m.recentErrors, ErrorEntry{
			Time:    time.Time{},
			Message: fmt.Sprintf("TCP lost segments (×%d)", summary.TCPLostSegments),
			Level:   "error",
		})
	}
	if summary.CIPErrorResponses > 0 {
		m.recentErrors = append(m.recentErrors, ErrorEntry{
			Time:    time.Time{},
			Message: fmt.Sprintf("CIP error responses (×%d)", summary.CIPErrorResponses),
			Level:   "warning",
		})
	}

	// Add CIP validation errors
	for errMsg, count := range summary.RequestValidationErrors {
		if len(m.recentErrors) >= 10 {
			break
		}
		msg := errMsg
		if len(msg) > 40 {
			msg = msg[:37] + "..."
		}
		level := "warning"
		if strings.Contains(errMsg, "decode error") {
			level = "error"
		}
		m.recentErrors = append(m.recentErrors, ErrorEntry{
			Time:    time.Time{},
			Message: fmt.Sprintf("%s (×%d)", msg, count),
			Level:   level,
		})
	}

	// Latency placeholder (PCAP doesn't have latency data)
	for i := range m.latencyHistory {
		m.latencyHistory[i] = 5.0 + float64(i%10)*0.5
	}

	// Set totals
	m.totalRequests = summary.Requests
	m.totalErrors = totalAllErrors
}

// shortenServiceName abbreviates CIP service names for display.
func shortenServiceName(name string) string {
	replacements := map[string]string{
		"Get_Attribute_Single":  "GetAttr",
		"Get_Attribute_All":     "GetAll",
		"Get_Attributes_All":    "GetAll",
		"Set_Attribute_Single":  "SetAttr",
		"Forward_Open":          "FwdOpen",
		"Forward_Close":         "FwdClose",
		"Read_Tag":              "ReadTag",
		"Write_Tag":             "WriteTag",
		"Unconnected_Send":      "UCMM",
		"Multiple_Service":      "Multi",
		"Read_Tag_Fragmented":   "ReadFrag",
		"Write_Tag_Fragmented":  "WriteFrag",
	}
	if short, ok := replacements[name]; ok {
		return short
	}
	// Truncate long names
	if len(name) > 10 {
		return name[:10]
	}
	return name
}

// usePlaceholderData sets minimal placeholder when no real data is available.
func (m *MainScreenModel) usePlaceholderData() {
	m.serviceStats = map[string]float64{
		"(no data)": 0,
	}
	// Zero all traffic history arrays
	for i := 0; i < 60; i++ {
		m.readHistory[i] = 0
		m.writeHistory[i] = 0
		m.errorHistory[i] = 0
		m.otherHistory[i] = 0
		m.trafficHistory[i] = 0
		m.latencyHistory[i] = 0
	}
}

// UpdateStats updates live stats from running operations.
func (m *MainScreenModel) UpdateStats(clientStats, serverStats StatsUpdate) {
	m.clientStats = clientStats
	m.serverStats = serverStats

	// Track that we have live data
	if clientStats.TotalRequests > 0 || serverStats.TotalRequests > 0 {
		m.hasLiveData = true

		// Update traffic history with delta (new requests since last update)
		prevTotal := m.totalRequests
		newTotal := clientStats.TotalRequests + serverStats.TotalRequests
		delta := float64(newTotal - prevTotal)
		if delta < 0 {
			delta = float64(newTotal) // Reset occurred
		}
		m.totalRequests = newTotal

		// Shift and add new value
		m.trafficHistory = append(m.trafficHistory[1:], delta)

		// Update error history
		prevErrors := m.totalErrors
		newErrors := clientStats.TotalErrors + serverStats.TotalErrors
		errorDelta := float64(newErrors - prevErrors)
		if errorDelta < 0 {
			errorDelta = 0
		}
		m.totalErrors = newErrors
		m.errorHistory = append(m.errorHistory[1:], errorDelta)
	}

	// Advance hint banner
	m.hintOffset++
}

// AddError adds an error to the recent errors list.
func (m *MainScreenModel) AddError(message, level string) {
	entry := ErrorEntry{
		Time:    time.Now(),
		Message: message,
		Level:   level,
	}
	m.recentErrors = append([]ErrorEntry{entry}, m.recentErrors...)
	if len(m.recentErrors) > 20 {
		m.recentErrors = m.recentErrors[:20]
	}
}

// AddLatency adds a latency measurement.
func (m *MainScreenModel) AddLatency(latencyMs float64) {
	m.latencyHistory = append(m.latencyHistory[1:], latencyMs)
	m.totalLatencySum += latencyMs
	m.latencyCount++
}

// GetAverageLatency returns the average latency.
func (m *MainScreenModel) GetAverageLatency() float64 {
	if m.latencyCount == 0 {
		// Use average from history
		var sum float64
		for _, v := range m.latencyHistory {
			sum += v
		}
		return sum / float64(len(m.latencyHistory))
	}
	return m.totalLatencySum / float64(m.latencyCount)
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

	// Status indicators - light up when running OR when panel is active (config/running mode)
	var serverStatus, clientStatus string

	// Server indicator: running = green filled, active panel = yellow filled, inactive = dim empty
	serverActive := m.model != nil && m.model.GetEmbeddedPanel() == EmbedServer &&
		(m.model.GetServerPanel().Mode() == PanelConfig || m.model.GetServerPanel().Mode() == PanelRunning)
	if m.state.ServerRunning {
		serverStatus = s.Success.Render("Server●")
	} else if serverActive {
		serverStatus = s.Warning.Render("Server●")
	} else {
		serverStatus = s.Dim.Render("Server○")
	}

	// Client indicator: running = green filled, active panel = yellow filled, inactive = dim empty
	clientActive := m.model != nil && m.model.GetEmbeddedPanel() == EmbedClient &&
		(m.model.GetClientPanel().Mode() == PanelConfig || m.model.GetClientPanel().Mode() == PanelRunning)
	if m.state.ClientRunning {
		clientStatus = s.Success.Render("Client●")
	} else if clientActive {
		clientStatus = s.Warning.Render("Client●")
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

	// System panel (compact) - render first to measure
	systemPanel := m.renderSystemPanel(width)
	systemHeight := strings.Count(systemPanel, "\n") + 1

	// Stats panel fills remaining space exactly
	// Total right column = systemHeight + 1 (gap) + statsHeight = trafficHeight
	statsHeight := trafficHeight - systemHeight - 1
	if statsHeight < 5 {
		statsHeight = 5
	}
	statsPanel := m.renderStatsPanel(width, statsHeight)

	return JoinVertical(1, systemPanel, statsPanel)
}

func (m *MainScreenModel) renderTrafficGraph(width int) string {
	s := m.styles

	// Use colored braille dot graph with multiple series
	graph := ColoredTrafficGraph{
		Title:   "TRAFFIC",
		Width:   width - 4,
		Height:  8,
		ShowMax: true,
		Series: []TrafficSeries{
			{Values: m.readHistory, Color: lipgloss.Color("#7aa2f7"), Label: "Reads"},   // Blue
			{Values: m.writeHistory, Color: lipgloss.Color("#ff9e64"), Label: "Writes"}, // Orange
			{Values: m.errorHistory, Color: lipgloss.Color("#f7768e"), Label: "Errors"}, // Red
			{Values: m.otherHistory, Color: lipgloss.Color("#9ece6a"), Label: "Other"},  // Green
		},
	}

	content := graph.Render(s)

	// Single footer line: left side (rate + source), right side (legend)
	currentRate := m.readHistory[len(m.readHistory)-1] +
		m.writeHistory[len(m.writeHistory)-1] +
		m.errorHistory[len(m.errorHistory)-1] +
		m.otherHistory[len(m.otherHistory)-1]

	// Right side: compact legend using braille pattern (U+2009 thin space between block and letter)
	legend := lipgloss.NewStyle().Foreground(lipgloss.Color("#7aa2f7")).Render("⣿") + "\u2009R  " +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#ff9e64")).Render("⣿") + "\u2009W  " +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#f7768e")).Render("⣿") + "\u2009E  " +
		lipgloss.NewStyle().Foreground(lipgloss.Color("#9ece6a")).Render("⣿") + "\u2009O"

	// Calculate available space for left side
	innerWidth := width - 6 // Account for panel box borders and padding
	legendWidth := lipgloss.Width(legend)
	maxLeftWidth := innerWidth - legendWidth - 2 // Leave space for padding

	// Build left side: rate and source
	rateStr := fmt.Sprintf("%.0f req/s", currentRate)
	var sourceStr string
	if m.hasLiveData {
		if m.model != nil && m.model.clientPanel != nil && m.state.ClientRunning {
			sourceStr = s.Success.Render("live → " + m.model.clientPanel.targetIP)
		} else if m.state.ServerRunning {
			sourceStr = s.Success.Render("live ← server")
		}
	} else if m.hasPCAPData && m.pcapSource != "" {
		pcapName := filepath.Base(m.pcapSource)
		// Calculate max pcap name length to fit
		prefixLen := len(rateStr) + len("  from: ")
		maxPcapLen := maxLeftWidth - prefixLen
		if maxPcapLen < 8 {
			maxPcapLen = 8
		}
		if len(pcapName) > maxPcapLen {
			pcapName = pcapName[:maxPcapLen-3] + "..."
		}
		sourceStr = "from: " + pcapName
	}

	var leftStr string
	if sourceStr != "" {
		leftStr = s.Dim.Render(rateStr + "  " + sourceStr)
	} else {
		leftStr = s.Dim.Render(rateStr)
	}

	// Calculate padding to right-align legend
	leftWidth := lipgloss.Width(leftStr)
	padding := innerWidth - leftWidth - legendWidth
	if padding < 1 {
		padding = 1
	}

	content += "\n" + leftStr + strings.Repeat(" ", padding) + legend

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

	// Count PCAP files in workspace
	pcapCount := 0
	if m.state.WorkspaceRoot != "" {
		pcapDir := filepath.Join(m.state.WorkspaceRoot, "pcaps")
		if entries, err := os.ReadDir(pcapDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".pcap") {
					pcapCount++
				}
			}
		}
	}

	// Calculate uptime from first run or session start
	var uptimeStr string
	if len(m.state.RecentRuns) > 0 {
		oldest := m.state.RecentRuns[len(m.state.RecentRuns)-1].Time
		uptime := time.Since(oldest).Round(time.Minute)
		if uptime.Hours() >= 1 {
			uptimeStr = fmt.Sprintf("%.0fh", uptime.Hours())
		} else {
			uptimeStr = fmt.Sprintf("%.0fm", uptime.Minutes())
		}
	} else {
		uptimeStr = "new"
	}

	items := [][]string{
		{"Workspace", wsName},
		{"Profiles", fmt.Sprintf("%d", len(m.state.Profiles))},
		{"PCAPs", fmt.Sprintf("%d", pcapCount)},
		{"Session", uptimeStr},
	}

	return m.panelBox("SYSTEM", MiniTable(items, s), width)
}

func (m *MainScreenModel) renderStatsPanel(width, height int) string {
	s := m.styles

	// Calculate stats from live operations or PCAP data
	var totalRequests, reads, writes, errors float64
	var conns int

	// Use live stats if available
	if m.hasLiveData {
		totalRequests = float64(m.clientStats.TotalRequests + m.serverStats.TotalRequests)
		errors = float64(m.clientStats.TotalErrors + m.serverStats.TotalErrors)
		conns = m.serverStats.ActiveConnections
		// Estimate reads/writes from live traffic (rough 60/30 split)
		reads = totalRequests * 0.6
		writes = totalRequests * 0.3
	} else {
		// Use PCAP-derived stats
		reads = float64(m.totalReads)
		writes = float64(m.totalWrites)
		errors = float64(m.totalErrors)
		totalRequests = float64(m.totalRequests)
		if totalRequests == 0 {
			for _, v := range m.trafficHistory {
				totalRequests += v
			}
		}
	}

	// Format as 2x2 grid with colored categories
	items := []string{
		BigNumber(formatNumber(reads), "Reads", lipgloss.Color("#7aa2f7"), s),    // Blue
		BigNumber(formatNumber(writes), "Writes", lipgloss.Color("#ff9e64"), s),  // Orange
		BigNumber(formatNumber(errors), "Errors", lipgloss.Color("#f7768e"), s),  // Red
		BigNumber(fmt.Sprintf("%d", conns), "Conns", DefaultTheme.Info, s),
	}

	grid := Grid{Columns: 2, Gap: 2, Items: items}
	content := grid.Render(width - 4)

	// Pad to requested height (panelBox adds 2 lines for borders)
	contentLines := strings.Split(content, "\n")
	innerHeight := height - 2
	for len(contentLines) < innerHeight {
		contentLines = append(contentLines, "")
	}
	// Trim if content is too tall
	if len(contentLines) > innerHeight {
		contentLines = contentLines[:innerHeight]
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

	// Pad to height (panelBox adds 2 lines for borders)
	contentLines := strings.Split(content, "\n")
	innerHeight := height - 2
	for len(contentLines) < innerHeight {
		contentLines = append(contentLines, "")
	}

	return m.panelBox("SERVICES", strings.Join(contentLines, "\n"), width)
}

func (m *MainScreenModel) renderRunsPanel(width, height int) string {
	s := m.styles
	var lines []string

	// Show currently running operations first
	if m.state.ServerRunning {
		lines = append(lines, StatusIcon("running", s)+" "+s.Running.Render("server")+" "+s.Dim.Render("listening"))
	}
	if m.state.ClientRunning {
		lines = append(lines, StatusIcon("running", s)+" "+s.Running.Render("client")+" "+s.Dim.Render("running"))
	}

	// Show RecentRuns from state (prioritize over directory listing)
	maxRuns := 4 - len(lines) // Leave room for running operations
	if maxRuns < 0 {
		maxRuns = 0
	}

	if len(m.state.RecentRuns) > 0 {
		for i, run := range m.state.RecentRuns {
			if i >= maxRuns {
				remaining := len(m.state.RecentRuns) - maxRuns
				if remaining > 0 {
					lines = append(lines, s.Dim.Render(fmt.Sprintf("  +%d more", remaining)))
				}
				break
			}
			timeStr := run.Time.Format("15:04")
			status := run.Status
			if status == "" {
				status = "ok"
			}

			// Build run description
			desc := run.Type
			if run.Details != "" {
				desc = run.Details
			}

			// Truncate if needed
			maxDesc := width - 16
			if maxDesc < 8 {
				maxDesc = 8
			}
			if len(desc) > maxDesc {
				desc = desc[:maxDesc-3] + "..."
			}

			lines = append(lines, fmt.Sprintf("%s %s %s", StatusIcon(status, s), s.Dim.Render(timeStr), desc))
		}
	} else if len(m.state.Runs) > 0 {
		// Fallback to directory listing
		for i, run := range m.state.Runs {
			if i >= maxRuns {
				if len(m.state.Runs) > maxRuns {
					lines = append(lines, s.Dim.Render(fmt.Sprintf("  +%d more", len(m.state.Runs)-maxRuns)))
				}
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
	}

	if len(lines) == 0 {
		lines = append(lines, s.Dim.Render("No recent runs"))
	}

	// Pad to height (panelBox adds 2 lines for borders)
	innerHeight := height - 2
	for len(lines) < innerHeight {
		lines = append(lines, "")
	}

	return m.panelBox("RECENT RUNS", strings.Join(lines, "\n"), width)
}

func (m *MainScreenModel) renderErrorsPanel(width, height int) string {
	s := m.styles

	var lines []string

	// Use real errors if available, otherwise show placeholder
	if len(m.recentErrors) > 0 {
		maxShow := 3
		if len(m.recentErrors) < maxShow {
			maxShow = len(m.recentErrors)
		}
		for i := 0; i < maxShow; i++ {
			err := m.recentErrors[i]
			// Show time for live errors, "PCAP" for PCAP errors
			var timeStr string
			if err.Time.IsZero() {
				timeStr = "PCAP"
			} else {
				timeStr = err.Time.Format("15:04")
			}
			// Truncate message to fit
			msg := err.Message
			maxLen := width - 14
			if maxLen < 10 {
				maxLen = 10
			}
			if len(msg) > maxLen {
				msg = msg[:maxLen-3] + "..."
			}
			lines = append(lines, fmt.Sprintf("%s %s %s", StatusIcon(err.Level, s), s.Dim.Render(timeStr), msg))
		}
		// Show more count if truncated
		if len(m.recentErrors) > maxShow {
			lines = append(lines, s.Dim.Render(fmt.Sprintf("  +%d more", len(m.recentErrors)-maxShow)))
		}
	} else if m.totalErrors > 0 {
		// We have error count but no detailed entries
		lines = append(lines, fmt.Sprintf("%s %s %s", StatusIcon("warning", s), s.Dim.Render("PCAP"), fmt.Sprintf("%d validation errors", m.totalErrors)))
	} else {
		// No errors - show placeholder
		lines = append(lines, s.Dim.Render("No errors recorded"))
	}

	sparkline := Sparkline(m.errorHistory, width-10, s)
	lines = append(lines, s.Dim.Render("Rate:")+sparkline)

	// Pad to height (panelBox adds 2 lines for borders)
	innerHeight := height - 2
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
		panel := m.model.GetCatalogPanel()
		panelTitle = panel.Title()
		panelContent = panel.ViewContent(panelWidth-4, true)
		helpContent = m.getCatalogHelp()
	case EmbedOrch:
		panel := m.model.GetOrchPanel()
		panelTitle = panel.Title()
		panelContent = panel.ViewContent(panelWidth-4, true)
		helpContent = m.getOrchHelp()
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
	content := s.Dim.Render("Press [c] Client  [s] Server  [p] PCAP  [k] Catalog  [o] Orch")
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
	panel := m.model.GetCatalogPanel()
	switch panel.Mode() {
	case PanelConfig:
		return `TEST CONFIGURATION

Send a CIP request to a
real EtherNet/IP device.

The EPATH is built from
the selected catalog
entry (service, class,
instance, attribute).

Target IP
  IPv4 of the device

Port
  Default 44818 (ENIP)

Payload
  Optional request data
  in hex (e.g. 01020304)`

	case PanelRunning:
		return `REQUEST IN PROGRESS

Connecting to target
via TCP port 44818.

Sequence:
1. TCP connect
2. RegisterSession
3. SendRRData with
   embedded CIP request
4. Parse response

Press Esc to abort.`

	case PanelResult:
		return `CIP RESPONSE

Common Status Codes:

0x00 Success
     Request completed

0x04 Path Segment Error
     Invalid class/inst

0x08 Service Not Supported
     Unknown service code

0x0E Attribute Not Settable
     Read-only attribute

0x14 Not Enough Data
     Payload too short`

	default:
		return `CIP SERVICE CATALOG

Groups services by their
service code + object
class combination.

DOMAIN
  Core   ODVA standard
  Logix  Rockwell-specific
  Legacy Older protocols

SERVICE
  CIP service name and
  hex code (e.g. 0x0E)

OBJECT
  Target class/instance
  (e.g. Identity 0x01)

TARGETS
  Available attributes
  or instances to query

Use 'f' to filter by
domain. Select a group
to see its targets.`
	}
}

func (m *MainScreenModel) getOrchHelp() string {
	panel := m.model.GetOrchPanel()
	switch panel.Mode() {
	case PanelConfig:
		return `ORCHESTRATION

Configure and run
distributed tests using
Run Manifests.

MANIFEST
  YAML file defining
  roles, agents, and
  network settings.

BUNDLE DIR
  Output directory for
  run bundles containing
  all artifacts.

TIMEOUT
  Overall run timeout
  in seconds.

DRY RUN
  Validate and plan
  without execution.

[v] Validate manifest
[e] Edit in editor
[Tab] Switch to Agent`

	case PanelRunning:
		return `RUN IN PROGRESS

The controller is
executing the manifest
through phases:

1. init - Create bundle
2. stage - Copy profiles
3. server_start
4. server_ready - Wait
5. client_start
6. client_done - Wait
7. server_stop
8. collect - Artifacts
9. bundle - Finalize

[x] Stop execution`

	case PanelResult:
		return `RUN COMPLETE

The run has finished.
Artifacts are stored
in the bundle dir.

Bundle Contents:
- manifest.yaml
- manifest_resolved.yaml
- roles/<role>/
  - *.pcap
  - stdout.log
  - role_meta.json
- hashes.txt

[Enter] New run
[o] Open bundle dir`

	default:
		if panel.view == OrchViewAgents {
			return `AGENTS

Manage remote agents
for orchestration.

AGENT LIST
  Local + registered
  remote agents

DETAILS
  Transport URL
  Status & last check

ACTIONS
  [a] Add agent
  [d] Delete
  [c] Check one
  [C] Check all
  [s] SSH wizard

[R] Refresh
[Tab] Controller`
		}
		if panel.view == OrchViewAgentSetup {
			return `SSH WIZARD

Guided SSH setup for
remote agents.

STEPS
  1. Check SSH agent
  2. Enter host info
  3. Verify host key
  4. Test connection
  5. Copy SSH key
  6. Save agent

[←] Back step
[Esc] Cancel`
		}
		return `ORCHESTRATION

Press any key to
configure orchestration.

[Tab] Switch views`
	}
}

func (m *MainScreenModel) renderCatalogContent(width int) string {
	s := m.styles
	entries := m.state.CatalogEntries

	var lines []string

	if len(entries) == 0 {
		lines = append(lines, s.Dim.Render("No catalog entries loaded."))
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Catalog loaded from:"))
		lines = append(lines, s.Dim.Render("  /catalogs/core.yaml"))
	} else {
		// Header
		lines = append(lines, s.Dim.Render(fmt.Sprintf("Entries: %d", len(entries))))
		lines = append(lines, "")

		// Show entries with full EPATH tuple
		maxShow := 12
		if len(entries) < maxShow {
			maxShow = len(entries)
		}

		for i := 0; i < maxShow; i++ {
			entry := entries[i]
			// Build EPATH: Service/Class/Instance/Attribute
			epath := fmt.Sprintf("0x%02X/0x%04X/0x%04X", entry.ServiceCode, entry.EPATH.Class, entry.EPATH.Instance)
			if entry.EPATH.Attribute != 0 {
				epath += fmt.Sprintf("/0x%04X", entry.EPATH.Attribute)
			}

			// Truncate name if needed
			name := entry.Name
			if name == "" {
				name = entry.Key
			}
			maxName := width - len(epath) - 4
			if maxName < 10 {
				maxName = 10
			}
			if len(name) > maxName {
				name = name[:maxName-3] + "..."
			}

			line := fmt.Sprintf("%-26s %s", epath, name)
			lines = append(lines, line)
		}

		if len(entries) > maxShow {
			lines = append(lines, "")
			lines = append(lines, s.Dim.Render(fmt.Sprintf("  +%d more...", len(entries)-maxShow)))
		}
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
