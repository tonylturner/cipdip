package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
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
	embeddedPanel EmbeddedPanel
	clientPanel   *ClientPanel
	serverPanel   *ServerPanel
	pcapPanel     *PCAPPanel
	catalogPanel  *CatalogPanel

	// Screen-specific models (for full-screen views)
	mainScreen     *MainScreenModel
	catalogScreen  *CatalogScreenModel
	catalogV2      *CatalogV2Model // New enhanced catalog workflow
	runsScreen     *RunsScreenModel
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
	}

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
			summary := ui.RunSummary{
				Status:     status,
				Command:    m.clientPanel.BuildRunConfig(m.state.WorkspaceRoot).BuildCommandArgs(),
				StartedAt:  m.clientPanel.startTime.Format(time.RFC3339),
				FinishedAt: time.Now().Format(time.RFC3339),
				ExitCode:   exitCode,
			}
			resolved := map[string]interface{}{
				"type":   "client",
				"target": m.clientPanel.targetIP,
				"stats":  msg.result.Stats,
			}
			_ = ui.WriteRunArtifacts(m.clientPanel.runDir, resolved, summary.Command, msg.result.Output, summary)
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
			summary := ui.RunSummary{
				Status:     status,
				Command:    m.serverPanel.BuildRunConfig(m.state.WorkspaceRoot).BuildCommandArgs(),
				StartedAt:  m.serverPanel.startTime.Format(time.RFC3339),
				FinishedAt: time.Now().Format(time.RFC3339),
				ExitCode:   msg.exitCode,
			}
			resolved := map[string]interface{}{
				"type":        "server",
				"personality": serverPersonalities[m.serverPanel.personality],
				"stats":       m.serverPanel.stats,
			}
			_ = ui.WriteRunArtifacts(m.serverPanel.runDir, resolved, summary.Command, msg.output, summary)
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
		return m, nil
	}

	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {

	// Global keys
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "h", "?":
		if m.mainScreen != nil {
			m.mainScreen.ToggleHelp()
		}
		return m, nil

	case "m":
		m.screen = ScreenMain
		m.error = ""
		return m, nil

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
		m.embeddedPanel = (m.embeddedPanel + 1) % 5 // None, Client, Server, PCAP, Catalog
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

	// Poll server stats if running
	if m.state.ServerRunning && m.serverPanel.Mode() == PanelRunning {
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
	if m.state.ClientRunning && m.clientPanel.Mode() == PanelRunning {
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
	// TODO: implement side rail help
	return baseContent
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
	if runDir, err := ui.CreateRunDir(m.state.WorkspaceRoot, runName); err == nil {
		m.serverPanel.runDir = runDir
	}

	// Record start time
	now := time.Now()
	m.serverPanel.startTime = &now

	// Create context for this run
	ctx, cancel := context.WithCancel(context.Background())
	m.state.ServerCtx = ctx
	m.state.ServerCancel = cancel
	m.serverPanel.runCtx = ctx
	m.serverPanel.runCancel = cancel

	// Start the server run command using ui's execution
	return m, StartServerRunCmd(ctx, cfg)
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

	// Start the client run command using ui's execution
	return m, StartClientRunCmd(ctx, cfg)
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
