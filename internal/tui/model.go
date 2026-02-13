package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tturner/cipdip/internal/orch/controller"
	"github.com/tturner/cipdip/internal/ui"
)

// Screen represents the current active screen.
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

// EmbeddedPanel tracks which panel is shown inline on the dashboard.
type EmbeddedPanel int

const (
	EmbedNone EmbeddedPanel = iota
	EmbedClient
	EmbedServer
	EmbedPCAP
	EmbedCatalog
	EmbedOrch
	EmbedDiscover
)

// Model is the main TUI model.
type Model struct {
	state    *AppState
	styles   Styles
	layout   Layout
	screen   Screen
	showHelp bool
	error    string

	// Embedded panel on dashboard
	embeddedPanel  EmbeddedPanel
	clientPanel    *ClientPanel
	serverPanel    *ServerPanel
	pcapPanel      *PCAPPanel
	catalogPanel   *CatalogPanel
	orchPanel      *OrchestrationPanel
	discoverPanel  *DiscoverPanel

	// Screen-specific models (for full-screen views)
	mainScreen *MainScreenModel
	catalogV2  *CatalogV2Model // Enhanced catalog workflow
	runsScreen *RunsScreenModel
}

// NewModel creates a new TUI model.
func NewModel(state *AppState) *Model {
	styles := DefaultStyles
	m := &Model{
		state:         state,
		styles:        styles,
		layout:        NewLayout(DefaultWidth, DefaultHeight),
		screen:        ScreenMain,
		embeddedPanel: EmbedNone,
		clientPanel:   NewClientPanel(styles),
		serverPanel:   NewServerPanel(styles),
		pcapPanel:     NewPCAPPanel(styles),
		catalogPanel:  NewCatalogPanel(styles, state),
		orchPanel:     NewOrchestrationPanelWithWorkspace(styles, state.WorkspaceRoot),
		discoverPanel: NewDiscoverPanel(styles),
	}

	// Refresh PCAP files with workspace context
	m.pcapPanel.RefreshFiles(state.WorkspaceRoot)

	// Initialize main screen
	m.mainScreen = NewMainScreenModel(state, styles, m)

	// Initialize enhanced catalog (V2) model
	m.catalogV2 = NewCatalogV2Model(styles)

	return m
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
	)
}

// tickMsg is sent periodically.
type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.layout = NewLayout(msg.Width, msg.Height)
		return m, nil

	case tickMsg:
		return m.handleTick()

	case tea.KeyMsg:
		return m.handleKey(msg)

	case TestResultMsg:
		// Handle catalog test result
		if m.catalogV2 != nil {
			m.catalogV2.HandleTestResult(msg)
		}
		return m, nil

	case sshCopyIDResultMsg:
		// Handle ssh-copy-id completion - update orchestration panel
		if m.orchPanel != nil {
			if msg.err != nil {
				m.orchPanel.sshWizardMsg = fmt.Sprintf("ssh-copy-id failed: %v", msg.err)
			} else {
				m.orchPanel.sshWizardMsg = "Key copied successfully!"
				m.orchPanel.sshWizardStep = SSHStepVerify
			}
		}
		return m, nil

	case startClientRunMsg:
		// Start the actual client run
		return m.startClientRun(msg.config)

	case clientRunResultMsg:
		// Client run completed
		exitCode := 0
		if msg.result.Error != nil {
			exitCode = 1
		}
		m.clientPanel.SetResult(CommandResult{
			Output:   msg.result.Output,
			ExitCode: exitCode,
			Err:      msg.result.Error,
		})
		m.clientPanel.stats = msg.result.Stats
		m.state.ClientRunning = false

		// Save run artifacts
		if m.clientPanel.runDir != "" && m.clientPanel.startTime != nil {
			status := "success"
			if msg.result.Error != nil {
				status = "failed"
			}
			endTime := time.Now()
			summary := ui.RunSummary{
				Status:     status,
				Command:    m.clientPanel.BuildRunConfig(m.state.WorkspaceRoot).BuildCommandArgs(),
				StartedAt:  m.clientPanel.startTime.Format(time.RFC3339),
				FinishedAt: endTime.Format(time.RFC3339),
				ExitCode:   exitCode,
			}
			resolved := map[string]interface{}{
				"type":   "client",
				"target": m.clientPanel.targetIP,
				"stats":  msg.result.Stats,
			}
			_ = ui.WriteRunArtifacts(m.clientPanel.runDir, resolved, summary.Command, msg.result.Output, summary)

			// Write detailed metrics
			metrics := ui.BuildMetrics("client", *m.clientPanel.startTime, endTime, ui.StatsUpdate(msg.result.Stats))
			_ = ui.WriteMetrics(m.clientPanel.runDir, metrics)
		}

		// Add to recent runs
		run := RecentRun{
			Time:       time.Now(),
			Type:       "client",
			Details:    clientScenarios[m.clientPanel.scenario],
			Target:     m.clientPanel.targetIP,
			Status:     "ok",
			Count:      msg.result.Stats.TotalRequests,
			ErrorCount: msg.result.Stats.TotalErrors,
		}
		if msg.result.Error != nil {
			run.Status = "error"
		}
		m.state.RecentRuns = append([]RecentRun{run}, m.state.RecentRuns...)
		if len(m.state.RecentRuns) > 20 {
			m.state.RecentRuns = m.state.RecentRuns[:20]
		}
		return m, nil

	case clientStatsMsg:
		// Update client stats
		m.clientPanel.UpdateStats(msg.stats)
		return m, nil

	case startServerRunMsg:
		// Start the actual server run
		return m.startServerRun(msg.config)

	case serverRunResultMsg:
		// Server run completed
		m.serverPanel.SetResult(CommandResult{
			Output:   msg.output,
			ExitCode: msg.exitCode,
			Err:      msg.err,
		})
		m.state.ServerRunning = false

		// Save run artifacts
		if m.serverPanel.runDir != "" && m.serverPanel.startTime != nil {
			status := "success"
			if msg.err != nil {
				status = "failed"
			}
			endTime := time.Now()
			summary := ui.RunSummary{
				Status:     status,
				Command:    m.serverPanel.BuildRunConfig(m.state.WorkspaceRoot).BuildCommandArgs(),
				StartedAt:  m.serverPanel.startTime.Format(time.RFC3339),
				FinishedAt: endTime.Format(time.RFC3339),
				ExitCode:   msg.exitCode,
			}
			resolved := map[string]interface{}{
				"type":        "server",
				"personality": serverPersonalities[m.serverPanel.personality],
				"stats":       m.serverPanel.stats,
			}
			_ = ui.WriteRunArtifacts(m.serverPanel.runDir, resolved, summary.Command, msg.output, summary)

			// Write detailed metrics
			metrics := ui.BuildMetrics("server", *m.serverPanel.startTime, endTime, ui.StatsUpdate(m.serverPanel.stats))
			_ = ui.WriteMetrics(m.serverPanel.runDir, metrics)
		}

		// Add to recent runs
		run := RecentRun{
			Time:       time.Now(),
			Type:       "server",
			Details:    serverPersonalities[m.serverPanel.personality],
			Target:     m.serverPanel.listenAddr + ":" + m.serverPanel.port,
			Status:     "ok",
			Count:      m.serverPanel.stats.TotalRequests,
			ErrorCount: m.serverPanel.stats.TotalErrors,
		}
		if msg.err != nil {
			run.Status = "error"
		}
		m.state.RecentRuns = append([]RecentRun{run}, m.state.RecentRuns...)
		if len(m.state.RecentRuns) > 20 {
			m.state.RecentRuns = m.state.RecentRuns[:20]
		}
		return m, nil

	case serverStatsMsg:
		// Update server stats
		m.serverPanel.UpdateStats(msg.stats)
		return m, nil

	case startPCAPRunMsg:
		// Start the actual PCAP run
		return m.startPCAPRun(msg.config)

	case pcapRunResultMsg:
		// PCAP run completed
		m.pcapPanel.result = &CommandResult{
			Output:   msg.output,
			ExitCode: msg.exitCode,
			Err:      msg.err,
		}
		m.pcapPanel.mode = PanelResult

		// Track this as a recent run
		pcapFile := ""
		if len(m.pcapPanel.files) > m.pcapPanel.selectedFile {
			pcapFile = m.pcapPanel.files[m.pcapPanel.selectedFile]
		}
		run := RecentRun{
			Time:    time.Now(),
			Type:    "pcap",
			Details: pcapModes[m.pcapPanel.modeIndex],
			Target:  filepath.Base(pcapFile),
			Status:  "ok",
		}
		if msg.exitCode != 0 || msg.err != nil {
			run.Status = "error"
		}
		m.state.RecentRuns = append([]RecentRun{run}, m.state.RecentRuns...)
		if len(m.state.RecentRuns) > 20 {
			m.state.RecentRuns = m.state.RecentRuns[:20]
		}

		// If analysis succeeded for Summary mode, update dashboard with this PCAP
		if msg.exitCode == 0 && m.pcapPanel.modeIndex == 0 {
			if pcapFile != "" {
				m.pcapPanel.lastAnalyzedPath = pcapFile
				// Refresh dashboard with this PCAP data
				if m.mainScreen != nil {
					m.mainScreen.LoadFromPCAP(pcapFile)
				}
			}
		}
		return m, nil

	case startDiscoverRunMsg:
		// Start discover operation
		return m, StartDiscoverRunCmd(m.discoverPanel.runCtx, msg.config)

	case discoverRunResultMsg:
		// Discover completed
		m.discoverPanel.SetResult(CommandResult{
			Output:   msg.output,
			ExitCode: msg.exitCode,
			Err:      msg.err,
		})

		// Track as recent run
		run := RecentRun{
			Time:    time.Now(),
			Type:    "discover",
			Details: "ListIdentity",
			Target:  "broadcast",
			Status:  "ok",
		}
		if msg.exitCode != 0 || msg.err != nil {
			run.Status = "error"
		}
		m.state.RecentRuns = append([]RecentRun{run}, m.state.RecentRuns...)
		if len(m.state.RecentRuns) > 20 {
			m.state.RecentRuns = m.state.RecentRuns[:20]
		}
		return m, nil

	case rerunCommandMsg:
		// Handle re-run request from runs screen
		return m.handleRerunCommand(msg)

	case orchOutputMsg:
		// Handle orchestration output event
		if m.orchPanel != nil {
			m.orchPanel.handleOutputEvent(msg.event)
		}
		// Continue forwarding output events
		if m.state.OrchOutputCh != nil {
			return m, ForwardOrchOutputCmd(m.state.OrchOutputCh)
		}
		return m, nil

	case orchPhaseUpdateMsg:
		// Handle orchestration phase update
		if m.orchPanel != nil {
			m.orchPanel.handlePhaseUpdate(msg.phase, msg.message)
		}
		// Continue forwarding phase events
		if m.state.OrchPhaseCh != nil {
			return m, ForwardOrchPhaseCmd(m.state.OrchPhaseCh)
		}
		return m, nil

	case orchRunDoneMsg:
		// Handle orchestration run completion
		if m.orchPanel != nil {
			m.orchPanel.handleRunDone(msg.result, msg.err)
		}
		m.state.OrchRunning = false
		return m, nil

	case startOrchRunMsg:
		// Start the orchestration run
		return m.startOrchRun(msg.config)
	}

	return m, nil
}

// startOrchRunMsg signals start of an orchestration run.
type startOrchRunMsg struct {
	config OrchRunConfig
}

// handleRerunCommand parses a saved command and dispatches to the appropriate runner.
func (m *Model) handleRerunCommand(msg rerunCommandMsg) (tea.Model, tea.Cmd) {
	// Parse the command string back into arguments
	args := parseCommandArgs(msg.command)
	if len(args) < 2 {
		m.error = "Invalid command format"
		return m, nil
	}

	// Switch to main screen and appropriate panel
	m.screen = ScreenMain

	switch msg.runType {
	case "client":
		// Parse client args and set up panel
		cfg, _ := parseClientArgs(args)
		if cfg.TargetIP != "" {
			m.clientPanel.targetIP = cfg.TargetIP
			m.clientPanel.port = fmt.Sprintf("%d", cfg.Port)
			m.clientPanel.mode = PanelRunning
			m.embeddedPanel = EmbedClient
			return m.startClientRun(cfg)
		}
	case "server":
		// Parse server args and set up panel
		cfg, personality := parseServerArgs(args)
		m.serverPanel.personality = personality
		m.serverPanel.listenAddr = cfg.ListenAddr
		m.serverPanel.port = fmt.Sprintf("%d", cfg.Port)
		m.serverPanel.mode = PanelRunning
		m.embeddedPanel = EmbedServer
		return m.startServerRun(cfg)
	case "pcap":
		// For PCAP, we can re-run the command directly
		cfg := parsePCAPArgs(args)
		if cfg.Mode != "" {
			m.pcapPanel.mode = PanelRunning
			m.embeddedPanel = EmbedPCAP
			return m.startPCAPRun(cfg)
		}
	}

	m.error = "Could not parse command for re-run"
	return m, nil
}

// parseCommandArgs splits a command string into arguments, handling quoted strings.
func parseCommandArgs(cmd string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range cmd {
		switch {
		case r == '"' || r == '\'':
			if inQuote && r == quoteChar {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quoteChar = r
			} else {
				current.WriteRune(r)
			}
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// parseClientArgs extracts client configuration from command arguments.
// Returns the config and personality index.
func parseClientArgs(args []string) (ClientRunConfig, int) {
	cfg := ClientRunConfig{
		Port:       44818,
		DurationS:  300,
		IntervalMs: 250,
	}
	personality := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--ip":
			if i+1 < len(args) {
				cfg.TargetIP = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.Port = p
				}
				i++
			}
		case "--scenario":
			if i+1 < len(args) {
				cfg.Scenario = args[i+1]
				i++
			}
		case "--duration":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(strings.TrimSuffix(args[i+1], "s")); err == nil {
					cfg.DurationS = d
				}
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				if iv, err := strconv.Atoi(strings.TrimSuffix(args[i+1], "ms")); err == nil {
					cfg.IntervalMs = iv
				}
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				cfg.Profile = args[i+1]
				i++
			}
		}
	}
	return cfg, personality
}

// parseServerArgs extracts server configuration from command arguments.
// Returns the config and personality index.
func parseServerArgs(args []string) (ServerRunConfig, int) {
	cfg := ServerRunConfig{
		Port:        44818,
		ListenAddr:  "0.0.0.0",
		Personality: "adapter",
	}
	personality := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--personality":
			if i+1 < len(args) {
				cfg.Personality = args[i+1]
				switch cfg.Personality {
				case "adapter":
					personality = 0
				case "logix_like":
					personality = 1
				}
				i++
			}
		case "--port":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil {
					cfg.Port = p
				}
				i++
			}
		case "--listen":
			if i+1 < len(args) {
				cfg.ListenAddr = args[i+1]
				i++
			}
		case "--profile":
			if i+1 < len(args) {
				cfg.Profile = args[i+1]
				i++
			}
		}
	}
	return cfg, personality
}

// parsePCAPArgs extracts PCAP configuration from command arguments.
func parsePCAPArgs(args []string) PCAPRunConfig {
	cfg := PCAPRunConfig{}
	if len(args) < 1 {
		return cfg
	}

	// Determine mode from command name
	cmd := args[0]
	if strings.HasSuffix(cmd, "cipdip") && len(args) > 1 {
		cmd = args[1]
	}

	switch {
	case strings.Contains(cmd, "pcap-summary"):
		cfg.Mode = "summary"
	case strings.Contains(cmd, "pcap-report"):
		cfg.Mode = "report"
	case strings.Contains(cmd, "pcap-coverage"):
		cfg.Mode = "coverage"
	case strings.Contains(cmd, "pcap-replay"):
		cfg.Mode = "replay"
	case strings.Contains(cmd, "pcap-rewrite"):
		cfg.Mode = "rewrite"
	case strings.Contains(cmd, "pcap-dump"):
		cfg.Mode = "dump"
	case strings.Contains(cmd, "pcap-diff"):
		cfg.Mode = "diff"
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--input", "-i":
			if i+1 < len(args) {
				cfg.InputFile = args[i+1]
				i++
			}
		case "--baseline":
			if i+1 < len(args) {
				cfg.InputFile = args[i+1]
				i++
			}
		case "--compare":
			if i+1 < len(args) {
				cfg.InputFile2 = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				cfg.TargetIP = args[i+1]
				i++
			}
		case "--service":
			if i+1 < len(args) {
				cfg.ServiceCode = args[i+1]
				i++
			}
		}
	}
	return cfg
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {

	// Check if an embedded panel needs text input BEFORE handling global letter shortcuts
	// This allows typing letters like 'm', 'h' in text fields
	panelNeedsTextInput := false
	if m.screen == ScreenMain && m.embeddedPanel != EmbedNone {
		panel := m.getActiveEmbeddedPanel()
		if panel != nil {
			// Panels in Config mode (or Catalog which always needs input) get text input priority
			panelNeedsTextInput = m.embeddedPanel == EmbedCatalog || panel.Mode() == PanelConfig
		}
	}

	// Global keys - but route letter keys to panel first if it needs text input
	switch msg.String() {
	case "q", "ctrl+c":
		// Always allow quit
		return m, tea.Quit

	case "h", "?":
		// Only toggle help if no panel needs text input
		if !panelNeedsTextInput {
			m.showHelp = !m.showHelp
			if m.screen == ScreenMain && m.mainScreen != nil {
				m.mainScreen.ToggleHelp()
			}
			return m, nil
		}

	case "m":
		// Only switch to main screen if no panel needs text input
		if !panelNeedsTextInput {
			m.screen = ScreenMain
			m.error = ""
			return m, nil
		}

	case "esc":
		if m.error != "" {
			m.error = ""
			return m, nil
		}
		// If embedded panel is active, check if it needs esc
		if m.screen == ScreenMain && m.embeddedPanel != EmbedNone {
			return m.handleEmbeddedPanelKey(msg)
		}
	}

	// Route to appropriate handler
	if m.screen == ScreenMain {
		return m.handleMainScreenKey(msg)
	}

	return m.updateScreen(msg)
}

func (m *Model) handleMainScreenKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Check if an embedded panel is active and needs keys routed to it
	// Panels in Config/Running mode get keys FIRST (so 'p' for profile works in client)
	// Catalog always gets keys (browse mode needs key handling)
	if m.embeddedPanel != EmbedNone {
		panel := m.getActiveEmbeddedPanel()
		if panel != nil {
			panelNeedsKeys := m.embeddedPanel == EmbedCatalog || panel.Mode() != PanelIdle
			if panelNeedsKeys {
				return m.handleEmbeddedPanelKey(msg)
			}
		}
	}

	// Panel switching keys - only processed when no active panel or panel is idle
	switch msg.String() {
	case "c":
		m.embeddedPanel = EmbedClient
		m.clientPanel.mode = PanelConfig
		m.clientPanel.focusedField = 0
		return m, nil

	case "s":
		m.embeddedPanel = EmbedServer
		m.serverPanel.mode = PanelConfig
		m.serverPanel.focusedField = 0
		return m, nil

	case "p":
		m.embeddedPanel = EmbedPCAP
		m.pcapPanel.mode = PanelConfig
		return m, nil

	case "k":
		// Catalog in embedded panel
		m.embeddedPanel = EmbedCatalog
		return m, nil

	case "o":
		// Orchestration panel
		m.embeddedPanel = EmbedOrch
		m.orchPanel.mode = PanelConfig
		return m, nil

	case "d":
		// Discover panel
		m.embeddedPanel = EmbedDiscover
		m.discoverPanel.mode = PanelConfig
		m.discoverPanel.focusedField = 0
		return m, nil

	case "K":
		// Full-screen catalog (CatalogV2)
		m.screen = ScreenCatalog
		return m, nil

	case "r":
		// Full screen runs
		m.screen = ScreenRuns
		if m.runsScreen == nil {
			m.runsScreen = NewRunsScreenModel(m.state, m.styles)
		}
		return m, nil

	case "tab":
		// Cycle through embedded panels
		m.embeddedPanel = (m.embeddedPanel + 1) % 7 // None, Client, Server, PCAP, Catalog, Orch, Discover
		return m, nil
	}

	// Route remaining keys to main screen
	if m.mainScreen != nil {
		newScreen, cmd := m.mainScreen.Update(msg)
		m.mainScreen = newScreen
		return m, cmd
	}

	return m, nil
}

func (m *Model) handleEmbeddedPanelKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch m.embeddedPanel {
	case EmbedClient:
		newPanel, c := m.clientPanel.Update(msg, true)
		m.clientPanel = newPanel.(*ClientPanel)
		cmd = c
		// If panel returned to idle, keep it visible but idle
		if m.clientPanel.Mode() == PanelIdle && msg.String() == "esc" {
			m.embeddedPanel = EmbedNone
		}

	case EmbedServer:
		newPanel, c := m.serverPanel.Update(msg, true)
		m.serverPanel = newPanel.(*ServerPanel)
		cmd = c
		if m.serverPanel.Mode() == PanelIdle && msg.String() == "esc" {
			m.embeddedPanel = EmbedNone
		}

	case EmbedPCAP:
		newPanel, c := m.pcapPanel.Update(msg, true)
		m.pcapPanel = newPanel.(*PCAPPanel)
		cmd = c
		if m.pcapPanel.Mode() == PanelIdle && msg.String() == "esc" {
			m.embeddedPanel = EmbedNone
		}

	case EmbedCatalog:
		newPanel, c := m.catalogPanel.Update(msg, true)
		m.catalogPanel = newPanel.(*CatalogPanel)
		cmd = c
		if m.catalogPanel.Mode() == PanelIdle && msg.String() == "esc" {
			m.embeddedPanel = EmbedNone
		}

	case EmbedOrch:
		newPanel, c := m.orchPanel.Update(msg, true)
		m.orchPanel = newPanel.(*OrchestrationPanel)
		cmd = c
		if m.orchPanel.Mode() == PanelIdle && msg.String() == "esc" {
			m.embeddedPanel = EmbedNone
		}

	case EmbedDiscover:
		newPanel, c := m.discoverPanel.Update(msg, true)
		m.discoverPanel = newPanel.(*DiscoverPanel)
		cmd = c
		if m.discoverPanel.Mode() == PanelIdle && msg.String() == "esc" {
			m.embeddedPanel = EmbedNone
		}
	}

	return m, cmd
}

func (m *Model) getActiveEmbeddedPanel() Panel {
	switch m.embeddedPanel {
	case EmbedClient:
		return m.clientPanel
	case EmbedServer:
		return m.serverPanel
	case EmbedPCAP:
		return m.pcapPanel
	case EmbedCatalog:
		return m.catalogPanel
	case EmbedOrch:
		return m.orchPanel
	case EmbedDiscover:
		return m.discoverPanel
	}
	return nil
}

func (m *Model) updateScreen(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch m.screen {
	case ScreenCatalog:
		if m.catalogV2 != nil {
			m.catalogV2, cmd = m.catalogV2.Update(msg)
		}

	case ScreenRuns:
		if m.runsScreen == nil {
			m.runsScreen = NewRunsScreenModel(m.state, m.styles)
		}
		newScreen, c := m.runsScreen.Update(msg)
		m.runsScreen = newScreen
		cmd = c
	}

	return m, cmd
}

func (m *Model) handleTick() (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	cmds = append(cmds, tickCmd())

	// Trigger async initialization of main screen data (PCAP loading etc.)
	if m.mainScreen != nil {
		m.mainScreen.InitAsync()
	}

	// Poll server stats if running
	if m.state.ServerRunning && m.serverPanel.Mode() == PanelRunning &&
		m.state.ServerStatsChan != nil && m.state.ServerResultChan != nil {
		select {
		case stats := <-m.state.ServerStatsChan:
			m.serverPanel.UpdateStats(stats)
		case result := <-m.state.ServerResultChan:
			m.serverPanel.SetResult(result)
			m.state.ServerRunning = false
		default:
		}
	}

	// Poll client stats if running
	if m.state.ClientRunning && m.clientPanel.Mode() == PanelRunning &&
		m.state.ClientStatsChan != nil && m.state.ClientResultChan != nil {
		select {
		case stats := <-m.state.ClientStatsChan:
			m.clientPanel.UpdateStats(stats)
		case result := <-m.state.ClientResultChan:
			m.clientPanel.SetResult(result)
			m.state.ClientRunning = false
		default:
		}
	}

	// Update main screen stats if visible
	if m.mainScreen != nil {
		m.mainScreen.UpdateStats(m.clientPanel.stats, m.serverPanel.stats)
	}

	return m, tea.Batch(cmds...)
}

// View implements tea.Model.
func (m *Model) View() string {
	var content string
	var footer string

	switch m.screen {
	case ScreenMain:
		if m.mainScreen != nil {
			content = m.mainScreen.View()
			footer = m.mainScreen.Footer()
		}
	case ScreenCatalog:
		if m.catalogV2 != nil {
			content = m.catalogV2.View()
			footer = m.catalogV2.Footer()
		} else {
			content = "Loading catalog screen..."
		}
	case ScreenRuns:
		if m.runsScreen != nil {
			content = m.runsScreen.View()
			footer = m.runsScreen.Footer()
		} else {
			content = "Loading runs screen..."
		}
	}

	// Add error if present
	if m.error != "" {
		content += "\n\n" + m.styles.Error.Render("ERROR: "+m.error)
	}

	// Add help overlay if active
	if m.showHelp {
		content = m.renderHelpOverlay(content)
	}

	// Add footer
	content += "\n\n" + m.styles.Footer.Render(footer)

	return content
}

func (m *Model) renderHelpOverlay(baseContent string) string {
	// Skip for main screen - it has its own help system
	if m.screen == ScreenMain {
		return baseContent
	}

	helpContent := m.getHelpForScreen()
	if helpContent == "" {
		return baseContent
	}

	// Render help panel
	helpWidth := 32
	s := m.styles

	borderStyle := lipgloss.NewStyle().Foreground(DefaultTheme.Info)
	b := func(ch string) string { return borderStyle.Render(ch) }

	innerWidth := helpWidth - 4
	borderWidth := helpWidth - 2

	title := " HELP "
	titleLen := lipgloss.Width(title)
	remaining := borderWidth - titleLen - 1
	if remaining < 0 {
		remaining = 0
	}
	topLine := b("╭─") + s.Header.Render(title) + b(strings.Repeat("─", remaining)+"╮")

	var helpBox strings.Builder
	helpBox.WriteString(topLine + "\n")

	for _, line := range strings.Split(helpContent, "\n") {
		lineWidth := lipgloss.Width(line)
		if lineWidth > innerWidth {
			line = lipgloss.NewStyle().MaxWidth(innerWidth).Render(line)
		}
		paddedLine := lipgloss.PlaceHorizontal(innerWidth, lipgloss.Left, line)
		helpBox.WriteString(b("│") + " " + paddedLine + " " + b("│") + "\n")
	}
	helpBox.WriteString(b("╰" + strings.Repeat("─", borderWidth) + "╯"))

	// Join base content with help panel on right
	return JoinHorizontal(2, baseContent, helpBox.String())
}

func (m *Model) getHelpForScreen() string {
	switch m.screen {
	case ScreenRuns:
		if m.runsScreen != nil && m.runsScreen.showDetail {
			return `RUN DETAILS

Navigation:
  Up/Down  Select artifact
  Esc      Back to list

Actions:
  o        Open in editor
  r        Re-run command
  y        Copy command`
		}
		return `RUNS HISTORY

Navigation:
  Tab      Cycle filter
  Up/Down  Select run
  Enter    View details

Actions:
  R        Refresh list
  d        Delete run
  o        Open directory
  r        Re-run
  y        Copy command

Filters:
  all      All runs
  client   Client runs
  server   Server runs
  pcap     PCAP analyses`

	case ScreenCatalog:
		return `CATALOG

Navigation:
  Up/Down  Navigate entries
  Enter    Toggle/Select
  /        Search filter
  Esc      Clear filter

Service Groups:
  Browse CIP services
  by category

Actions:
  t        Test on device
  Tab      Cycle view`

	default:
		return ""
	}
}

// startServerRun starts the server operation.
func (m *Model) startServerRun(cfg ServerRunConfig) (tea.Model, tea.Cmd) {
	// Set up workspace path if available
	if m.state.WorkspaceRoot != "" {
		cfg.OutputDir = m.state.WorkspaceRoot
	}

	m.state.ServerRunning = true

	// Create run directory for artifacts
	runName := "server_" + cfg.Personality
	if cfg.Profile != "" {
		runName = "server_" + cfg.Profile
	}
	if runDir, err := ui.CreateRunDir(m.state.WorkspaceRoot, runName); err == nil {
		m.serverPanel.runDir = runDir
	}

	// Record start time (and clear end time from previous run)
	now := time.Now()
	m.serverPanel.startTime = &now
	m.serverPanel.endTime = nil

	// Create context for this run
	ctx, cancel := context.WithCancel(context.Background())
	m.state.ServerCtx = ctx
	m.state.ServerCancel = cancel
	m.serverPanel.runCtx = ctx
	m.serverPanel.runCancel = cancel

	// Create channels for stats and result forwarding
	statsChan := make(chan StatsUpdate, 100)
	resultChan := make(chan CommandResult, 1)
	m.state.ServerStatsChan = statsChan
	m.state.ServerResultChan = resultChan

	// Start the server run command with channels for stats forwarding
	return m, StartServerRunCmd(ctx, cfg, statsChan, resultChan)
}

// startPCAPRun starts the PCAP operation.
func (m *Model) startPCAPRun(cfg PCAPRunConfig) (tea.Model, tea.Cmd) {
	// Set up workspace path if available
	if m.state.WorkspaceRoot != "" {
		cfg.OutputDir = m.state.WorkspaceRoot
	}

	// Start the PCAP run command
	ctx := context.Background()
	return m, StartPCAPRunCmd(ctx, cfg)
}

// startClientRun starts the client operation.
func (m *Model) startClientRun(cfg ClientRunConfig) (tea.Model, tea.Cmd) {
	// Set up workspace path if available
	if m.state.WorkspaceRoot != "" {
		cfg.OutputDir = m.state.WorkspaceRoot
	}

	m.state.ClientRunning = true

	// Create run directory for artifacts
	runName := "client_" + cfg.Scenario
	if cfg.Profile != "" {
		runName = "client_" + cfg.Profile
	}
	if runDir, err := ui.CreateRunDir(m.state.WorkspaceRoot, runName); err == nil {
		m.clientPanel.runDir = runDir
	}

	// Record start time
	now := time.Now()
	m.clientPanel.startTime = &now

	// Create context for this run
	ctx, cancel := context.WithCancel(context.Background())
	m.state.ClientCtx = ctx
	m.state.ClientCancel = cancel
	m.clientPanel.runCtx = ctx
	m.clientPanel.runCancel = cancel

	// Create channels for stats and result forwarding
	statsChan := make(chan StatsUpdate, 100)
	resultChan := make(chan CommandResult, 1)
	m.state.ClientStatsChan = statsChan
	m.state.ClientResultChan = resultChan

	// Start the client run command with channels for stats forwarding
	return m, StartClientRunCmd(ctx, cfg, statsChan, resultChan)
}

// GetEmbeddedPanel returns the current embedded panel for rendering.
func (m *Model) GetEmbeddedPanel() EmbeddedPanel {
	return m.embeddedPanel
}

// GetClientPanel returns the client panel.
func (m *Model) GetClientPanel() *ClientPanel {
	return m.clientPanel
}

// GetServerPanel returns the server panel.
func (m *Model) GetServerPanel() *ServerPanel {
	return m.serverPanel
}

// GetPCAPPanel returns the PCAP panel.
func (m *Model) GetPCAPPanel() *PCAPPanel {
	return m.pcapPanel
}

// GetCatalogPanel returns the catalog panel.
func (m *Model) GetCatalogPanel() *CatalogPanel {
	return m.catalogPanel
}

// GetOrchPanel returns the orchestration panel.
func (m *Model) GetOrchPanel() *OrchestrationPanel {
	return m.orchPanel
}

// startOrchRun starts the orchestration controller.
func (m *Model) startOrchRun(cfg OrchRunConfig) (tea.Model, tea.Cmd) {
	m.state.OrchRunning = true

	// Create context for this run
	ctx, cancel := context.WithCancel(context.Background())
	m.state.OrchCtx = ctx
	m.state.OrchCancel = cancel

	// Create channels for event forwarding
	outputCh := make(chan controller.OutputEvent, 100)
	phaseCh := make(chan orchPhaseUpdateMsg, 20)
	m.state.OrchOutputCh = outputCh
	m.state.OrchPhaseCh = phaseCh

	// Start the orchestration run command
	runCmd := StartOrchRunCmd(ctx, cfg, outputCh, phaseCh)

	// Also start forwarding commands
	return m, tea.Batch(
		runCmd,
		ForwardOrchOutputCmd(outputCh),
		ForwardOrchPhaseCmd(phaseCh),
	)
}
