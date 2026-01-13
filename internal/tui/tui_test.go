package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewModel(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		WorkspaceName: "test",
	}
	model := NewModel(state)
	if model == nil {
		t.Fatal("NewModel returned nil")
	}
	if model.screen != ScreenMain {
		t.Errorf("expected initial screen to be ScreenMain, got %d", model.screen)
	}
	if model.clientPanel == nil {
		t.Error("clientPanel should not be nil")
	}
	if model.serverPanel == nil {
		t.Error("serverPanel should not be nil")
	}
	if model.pcapPanel == nil {
		t.Error("pcapPanel should not be nil")
	}
	if model.catalogPanel == nil {
		t.Error("catalogPanel should not be nil")
	}
}

func TestClientPanelModes(t *testing.T) {
	panel := NewClientPanel(DefaultStyles)

	// Should start in idle mode
	if panel.Mode() != PanelIdle {
		t.Errorf("expected PanelIdle, got %d", panel.Mode())
	}

	// Switch to config mode
	panel.mode = PanelConfig
	if panel.Mode() != PanelConfig {
		t.Errorf("expected PanelConfig, got %d", panel.Mode())
	}
}

func TestClientPanelKeyHandling(t *testing.T) {
	panel := NewClientPanel(DefaultStyles)
	panel.mode = PanelConfig
	panel.targetIP = "192.168.1.100"

	// Test 'a' toggles advanced options
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}, true)
	if !panel.showAdvanced {
		t.Error("'a' should toggle advanced options on")
	}
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}, true)
	if panel.showAdvanced {
		t.Error("'a' should toggle advanced options off")
	}

	// Test 'p' toggles profile mode
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}}, true)
	if !panel.useProfile {
		t.Error("'p' should toggle profile mode on")
	}
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}}, true)
	if panel.useProfile {
		t.Error("'p' should toggle profile mode off")
	}

	// Test 'v' toggles preview
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}}, true)
	if !panel.showPreview {
		t.Error("'v' should toggle preview on")
	}

	// Test 'tab' advances field
	initialField := panel.focusedField
	panel.Update(tea.KeyMsg{Type: tea.KeyTab}, true)
	if panel.focusedField != initialField+1 {
		t.Errorf("tab should advance field from %d to %d, got %d", initialField, initialField+1, panel.focusedField)
	}

	// Test 'esc' returns to idle
	panel.Update(tea.KeyMsg{Type: tea.KeyEscape}, true)
	if panel.Mode() != PanelIdle {
		t.Error("esc should return to idle mode")
	}
}

func TestServerPanelModes(t *testing.T) {
	panel := NewServerPanel(DefaultStyles)

	// Should start in idle mode
	if panel.Mode() != PanelIdle {
		t.Errorf("expected PanelIdle, got %d", panel.Mode())
	}

	// Switch to config mode
	panel.mode = PanelConfig
	if panel.Mode() != PanelConfig {
		t.Errorf("expected PanelConfig, got %d", panel.Mode())
	}
}

func TestServerPanelKeyHandling(t *testing.T) {
	panel := NewServerPanel(DefaultStyles)
	panel.mode = PanelConfig

	// Test 'a' toggles advanced options
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}}, true)
	if !panel.showAdvanced {
		t.Error("'a' should toggle advanced options on")
	}

	// Test 'esc' first closes advanced options
	panel.Update(tea.KeyMsg{Type: tea.KeyEscape}, true)
	if panel.showAdvanced {
		t.Error("first esc should close advanced options")
	}

	// Test 'p' toggles profile mode
	panel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}}, true)
	if !panel.useProfile {
		t.Error("'p' should toggle profile mode on")
	}

	// Test 'esc' now returns to idle (advanced is off)
	panel.Update(tea.KeyMsg{Type: tea.KeyEscape}, true)
	if panel.Mode() != PanelIdle {
		t.Error("second esc should return to idle mode")
	}
}

func TestPCAPPanelModes(t *testing.T) {
	panel := NewPCAPPanel(DefaultStyles)

	// Should start in idle mode
	if panel.Mode() != PanelIdle {
		t.Errorf("expected PanelIdle, got %d", panel.Mode())
	}
}

func TestCatalogPanelKeyHandling(t *testing.T) {
	state := &AppState{}
	panel := NewCatalogPanel(DefaultStyles, state)

	// Catalog panel starts at screen 0 (groups)
	if panel.screen != 0 {
		t.Errorf("expected screen 0, got %d", panel.screen)
	}

	// Test navigation (cursor movement)
	panel.Update(tea.KeyMsg{Type: tea.KeyDown}, true)
	// Cursor should move (if there are groups)
}

func TestClipboardCopyMessage(t *testing.T) {
	// Test the clipboard message type
	msg := clipboardCopyMsg{
		success: true,
		content: "test content",
		err:     nil,
	}
	if !msg.success {
		t.Error("success should be true")
	}
	if msg.content != "test content" {
		t.Error("content mismatch")
	}
}

func TestClientRunConfig(t *testing.T) {
	cfg := ClientRunConfig{
		TargetIP:   "192.168.1.100",
		Port:       44818,
		Scenario:   "baseline",
		DurationS:  60,
		IntervalMs: 100,
	}

	args := cfg.BuildCommandArgs()

	// Check required args
	if len(args) < 6 {
		t.Fatalf("expected at least 6 args, got %d", len(args))
	}
	if args[0] != "cipdip" {
		t.Errorf("expected first arg 'cipdip', got '%s'", args[0])
	}
	if args[1] != "client" {
		t.Errorf("expected second arg 'client', got '%s'", args[1])
	}

	// Check IP is present
	found := false
	for i, arg := range args {
		if arg == "--ip" && i+1 < len(args) && args[i+1] == "192.168.1.100" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected --ip 192.168.1.100 in args")
	}
}

func TestServerRunConfig(t *testing.T) {
	cfg := ServerRunConfig{
		ListenAddr:  "0.0.0.0",
		Port:        44818,
		Personality: "adapter",
		OutputDir:   "/tmp/output",
	}

	args := cfg.BuildCommandArgs()

	// Check required args
	if len(args) < 4 {
		t.Fatalf("expected at least 4 args, got %d", len(args))
	}
	if args[0] != "cipdip" {
		t.Errorf("expected first arg 'cipdip', got '%s'", args[0])
	}
}

func TestEmbeddedPanelCycling(t *testing.T) {
	// Test that tab cycles through embedded panels
	panels := []EmbeddedPanel{EmbedNone, EmbedClient, EmbedServer, EmbedPCAP, EmbedCatalog}

	for i := 0; i < len(panels); i++ {
		next := (EmbeddedPanel(i) + 1) % 5
		if next != panels[(i+1)%len(panels)] {
			t.Errorf("panel cycling broken at index %d", i)
		}
	}
}

func TestPanelModeNames(t *testing.T) {
	// Verify panel modes are distinct
	modes := []PanelMode{PanelIdle, PanelConfig, PanelRunning, PanelResult}
	seen := make(map[PanelMode]bool)
	for _, m := range modes {
		if seen[m] {
			t.Errorf("duplicate panel mode: %d", m)
		}
		seen[m] = true
	}
}

func TestMainScreenModelCreation(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		WorkspaceName: "test",
	}
	styles := DefaultStyles
	m := NewMainScreenModel(state, styles, nil)

	if m == nil {
		t.Fatal("NewMainScreenModel returned nil")
	}
	if m.state != state {
		t.Error("state not properly assigned")
	}
	if len(m.trafficHistory) == 0 {
		t.Error("trafficHistory should be initialized")
	}
	if len(m.serviceStats) == 0 {
		t.Error("serviceStats should be initialized")
	}
}

func TestCatalogV2ModelCreation(t *testing.T) {
	styles := DefaultStyles
	m := NewCatalogV2Model(styles)

	if m == nil {
		t.Fatal("NewCatalogV2Model returned nil")
	}
	if m.screen != CatalogScreen1Groups {
		t.Errorf("expected initial screen to be CatalogScreen1Groups, got %d", m.screen)
	}
	if m.configPort != "44818" {
		t.Errorf("expected default port 44818, got %s", m.configPort)
	}
}

func TestCatalogV2SearchFilter(t *testing.T) {
	styles := DefaultStyles
	m := NewCatalogV2Model(styles)

	// Enter search mode
	m.searchMode = true
	m.searchQuery = ""

	// Type a search query
	m.handleSearchInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	m.handleSearchInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})

	if m.searchQuery != "id" {
		t.Errorf("expected search query 'id', got '%s'", m.searchQuery)
	}

	// Test backspace
	m.handleSearchInput(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.searchQuery != "i" {
		t.Errorf("expected search query 'i' after backspace, got '%s'", m.searchQuery)
	}

	// Test escape clears search
	m.handleSearchInput(tea.KeyMsg{Type: tea.KeyEscape})
	if m.searchMode {
		t.Error("esc should exit search mode")
	}
	if m.searchQuery != "" {
		t.Error("esc should clear search query")
	}
}

func TestRunsScreenModel(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		Runs:          []string{"2024-01-01_12-00_client_baseline", "2024-01-01_11-00_server_adapter"},
	}
	styles := DefaultStyles
	m := NewRunsScreenModel(state, styles)

	if m == nil {
		t.Fatal("NewRunsScreenModel returned nil")
	}
	if m.filterType != "all" {
		t.Errorf("expected default filter 'all', got '%s'", m.filterType)
	}
}

func TestClientPanelLogView(t *testing.T) {
	panel := NewClientPanel(DefaultStyles)

	// Test AddLogLine
	panel.AddLogLine("test line 1")
	panel.AddLogLine("test line 2")

	if len(panel.logLines) != 2 {
		t.Errorf("expected 2 log lines, got %d", len(panel.logLines))
	}

	// Test ClearLog
	panel.ClearLog()
	if len(panel.logLines) != 0 {
		t.Error("ClearLog should empty log lines")
	}
	if panel.showLog {
		t.Error("ClearLog should set showLog to false")
	}

	// Test log line limit
	for i := 0; i < 150; i++ {
		panel.AddLogLine("line")
	}
	if len(panel.logLines) > panel.maxLogLines {
		t.Errorf("log lines should be capped at %d, got %d", panel.maxLogLines, len(panel.logLines))
	}
}
