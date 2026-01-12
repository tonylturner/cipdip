package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
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

	// Screen-specific models (for full-screen views)
	mainScreen    *MainScreenModel
	catalogScreen *CatalogScreenModel
	runsScreen    *RunsScreenModel
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
	}

	// Initialize main screen
	m.mainScreen = NewMainScreenModel(state, styles, m)

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
	// If an embedded panel is active and in CONFIG/RUNNING mode, route to it
	if m.embeddedPanel != EmbedNone {
		panel := m.getActiveEmbeddedPanel()
		if panel != nil && panel.Mode() != PanelIdle {
			return m.handleEmbeddedPanelKey(msg)
		}
	}

	// Panel activation keys
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

	case "tab":
		// Cycle through embedded panels
		m.embeddedPanel = (m.embeddedPanel + 1) % 5 // None, Client, Server, PCAP, Catalog
		return m, nil

	case "k":
		// Catalog in embedded panel
		m.embeddedPanel = EmbedCatalog
		return m, nil

	case "r":
		// Full screen runs
		m.screen = ScreenRuns
		if m.runsScreen == nil {
			m.runsScreen = NewRunsScreenModel(m.state, m.styles)
		}
		return m, nil
	}

	// If embedded panel is idle, route remaining keys to main screen
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
	}
	return nil
}

func (m *Model) updateScreen(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch m.screen {
	case ScreenCatalog:
		if m.catalogScreen == nil {
			m.catalogScreen = NewCatalogScreenModel(m.state, m.styles)
		}
		newScreen, c := m.catalogScreen.Update(msg)
		m.catalogScreen = newScreen
		cmd = c

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
		if m.catalogScreen != nil {
			content = m.catalogScreen.View()
			footer = m.catalogScreen.Footer()
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
