package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestMainScreenNavigation(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}
	model := NewModel(state)

	tests := []struct {
		key      string
		expected Screen
	}{
		{"c", ScreenClient},
		{"s", ScreenServer},
		{"p", ScreenPCAP},
		{"k", ScreenCatalog},
		{"r", ScreenRuns},
	}

	for _, tt := range tests {
		t.Run("key_"+tt.key, func(t *testing.T) {
			// Reset to main screen
			model.screen = ScreenMain
			model.mainModel.Navigate = ScreenMain

			// Send key press
			msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(tt.key)}
			newModel, _ := model.Update(msg)
			m := newModel.(Model)

			if m.screen != tt.expected {
				t.Errorf("key %q: got screen %d, want %d", tt.key, m.screen, tt.expected)
			}
		})
	}
}

func TestGlobalKeys(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	t.Run("m_returns_to_main", func(t *testing.T) {
		model := NewModel(state)
		model.screen = ScreenClient

		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("m")}
		newModel, _ := model.Update(msg)
		m := newModel.(Model)

		if m.screen != ScreenMain {
			t.Errorf("got screen %d, want %d (ScreenMain)", m.screen, ScreenMain)
		}
	})

	t.Run("question_mark_shows_help", func(t *testing.T) {
		model := NewModel(state)
		model.showHelp = false

		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")}
		newModel, _ := model.Update(msg)
		m := newModel.(Model)

		if !m.showHelp {
			t.Error("expected showHelp to be true")
		}
	})

	t.Run("esc_clears_error", func(t *testing.T) {
		model := NewModel(state)
		model.error = "some error"

		msg := tea.KeyMsg{Type: tea.KeyEscape}
		newModel, _ := model.Update(msg)
		m := newModel.(Model)

		if m.error != "" {
			t.Errorf("got error %q, want empty", m.error)
		}
	})

	t.Run("esc_closes_help", func(t *testing.T) {
		model := NewModel(state)
		model.showHelp = true

		msg := tea.KeyMsg{Type: tea.KeyEscape}
		newModel, _ := model.Update(msg)
		m := newModel.(Model)

		if m.showHelp {
			t.Error("expected showHelp to be false")
		}
	})
}

func TestMainScreenArrowNavigation(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	t.Run("down_arrow_moves_cursor", func(t *testing.T) {
		model := NewMainScreenModel(state)
		model.cursor = 0

		msg := tea.KeyMsg{Type: tea.KeyDown}
		newModel, _ := model.Update(msg)

		if newModel.cursor != 1 {
			t.Errorf("got cursor %d, want 1", newModel.cursor)
		}
	})

	t.Run("up_arrow_moves_cursor", func(t *testing.T) {
		model := NewMainScreenModel(state)
		model.cursor = 2

		msg := tea.KeyMsg{Type: tea.KeyUp}
		newModel, _ := model.Update(msg)

		if newModel.cursor != 1 {
			t.Errorf("got cursor %d, want 1", newModel.cursor)
		}
	})

	t.Run("enter_navigates_to_selected", func(t *testing.T) {
		model := NewMainScreenModel(state)
		model.cursor = 2 // PCAP

		msg := tea.KeyMsg{Type: tea.KeyEnter}
		newModel, _ := model.Update(msg)

		if newModel.Navigate != ScreenPCAP {
			t.Errorf("got Navigate %d, want %d (ScreenPCAP)", newModel.Navigate, ScreenPCAP)
		}
	})
}

func TestClientScreenScenarioSelection(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	t.Run("space_cycles_scenario", func(t *testing.T) {
		model := NewClientScreenModel(state)
		model.focusIndex = clientFieldScenario
		model.Scenario = 0

		// Press space to cycle to next scenario
		msg := tea.KeyMsg{Type: tea.KeySpace}
		newModel, _ := model.Update(msg)

		if newModel.Scenario != 1 {
			t.Errorf("got Scenario %d, want 1", newModel.Scenario)
		}
	})

	t.Run("tab_cycles_fields", func(t *testing.T) {
		model := NewClientScreenModel(state)
		model.focusIndex = 0

		msg := tea.KeyMsg{Type: tea.KeyTab}
		newModel, _ := model.Update(msg)

		if newModel.focusIndex != 1 {
			t.Errorf("got focusIndex %d, want 1", newModel.focusIndex)
		}
	})
}

func TestClientScreenCommandPreview(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	t.Run("command_includes_ip", func(t *testing.T) {
		model := NewClientScreenModel(state)
		model.TargetIP = "192.168.1.50"
		model.Port = "44818"
		model.Scenario = 0

		cmd := model.buildCommand()
		expected := "cipdip client --ip 192.168.1.50 --scenario baseline"

		if cmd != expected {
			t.Errorf("got %q, want %q", cmd, expected)
		}
	})

	t.Run("command_includes_custom_port", func(t *testing.T) {
		model := NewClientScreenModel(state)
		model.TargetIP = "10.0.0.1"
		model.Port = "2222"
		model.Scenario = 1

		cmd := model.buildCommand()
		expected := "cipdip client --ip 10.0.0.1 --port 2222 --scenario mixed"

		if cmd != expected {
			t.Errorf("got %q, want %q", cmd, expected)
		}
	})
}

func TestServerScreenCommandPreview(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	t.Run("command_default_personality", func(t *testing.T) {
		model := NewServerScreenModel(state)
		model.Personality = 0

		cmd := model.buildCommand()
		expected := "cipdip server --personality adapter"

		if cmd != expected {
			t.Errorf("got %q, want %q", cmd, expected)
		}
	})

	t.Run("command_logix_personality", func(t *testing.T) {
		model := NewServerScreenModel(state)
		model.Personality = 1

		cmd := model.buildCommand()
		expected := "cipdip server --personality logix_like"

		if cmd != expected {
			t.Errorf("got %q, want %q", cmd, expected)
		}
	})
}

func TestPCAPScreenCommandPreview(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	tests := []struct {
		name        string
		actionIndex int
		filePath    string
		expected    string
	}{
		{"summary", 0, "test.pcap", "cipdip pcap-summary --input test.pcap"},
		{"report", 1, "test.pcap", "cipdip pcap-report --pcap-dir . --output /tmp/test/reports/pcap_report.md"},
		{"coverage", 2, "test.pcap", "cipdip pcap-coverage --pcap-dir . --output /tmp/test/reports/pcap_coverage.md"},
		{"rewrite", 4, "test.pcap", "cipdip pcap-rewrite --input test.pcap --output test_rewritten.pcap"},
		{"dump", 5, "test.pcap", "cipdip pcap-dump --input test.pcap"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := NewPCAPScreenModel(state)
			model.FilePath = tt.filePath
			model.ActionIndex = tt.actionIndex

			cmd := model.buildCommand()
			if cmd != tt.expected {
				t.Errorf("got %q, want %q", cmd, tt.expected)
			}
		})
	}
}

func TestPCAPScreenReplayCommand(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}

	t.Run("replay_with_options", func(t *testing.T) {
		model := NewPCAPScreenModel(state)
		model.FilePath = "test.pcap"
		model.ActionIndex = 3 // Replay
		model.ReplayTargetIP = "192.168.1.100"
		model.ReplayRewrite = true
		model.ReplayTiming = true

		cmd := model.buildCommand()
		expected := "cipdip pcap-replay --input test.pcap --server-ip 192.168.1.100 --rewrite --realtime"

		if cmd != expected {
			t.Errorf("got %q, want %q", cmd, expected)
		}
	})
}

func TestHelpContent(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
	}
	model := NewModel(state)

	screens := []Screen{
		ScreenMain,
		ScreenClient,
		ScreenServer,
		ScreenPCAP,
		ScreenCatalog,
		ScreenRuns,
	}

	for _, screen := range screens {
		t.Run("screen_"+string(rune('0'+screen)), func(t *testing.T) {
			model.screen = screen
			title, body := model.getHelpForScreen()

			if title == "" {
				t.Errorf("expected non-empty help title for screen %d", screen)
			}

			if body == "" {
				t.Errorf("expected non-empty help body for screen %d", screen)
			}

			if len(body) < 50 {
				t.Errorf("help for screen %d seems too short: %q", screen, body)
			}
		})
	}
}

// Integration tests

func TestWindowSizeMessage(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewModel(state)

	msg := tea.WindowSizeMsg{Width: 120, Height: 40}
	newModel, _ := model.Update(msg)
	m := newModel.(Model)

	if m.width != 120 || m.height != 40 {
		t.Errorf("got size %dx%d, want 120x40", m.width, m.height)
	}
}

func TestTickMessage(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewModel(state)

	// Tick without running operations should not panic
	msg := tickMsg{}
	newModel, cmd := model.Update(msg)
	m := newModel.(Model)

	if m.screen != ScreenMain {
		t.Errorf("screen changed unexpectedly: %d", m.screen)
	}

	// Should return a tick command for idle state
	if cmd == nil {
		t.Error("expected tick command, got nil")
	}
}

func TestErrorMessage(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewModel(state)

	msg := errorMsg("test error")
	newModel, _ := model.Update(msg)
	m := newModel.(Model)

	if m.error != "test error" {
		t.Errorf("got error %q, want %q", m.error, "test error")
	}
}

func TestClearErrorMessage(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewModel(state)
	model.error = "existing error"

	msg := clearErrorMsg{}
	newModel, _ := model.Update(msg)
	m := newModel.(Model)

	if m.error != "" {
		t.Errorf("got error %q, want empty", m.error)
	}
}

func TestRunResultMessage(t *testing.T) {
	state := &AppState{
		WorkspaceRoot:  "/tmp/test",
		ClientRunning:  true,
	}
	model := NewModel(state)
	model.clientModel.Running = true

	msg := runResultMsg{
		RunDir:   "/tmp/test/runs/test_run",
		ExitCode: 0,
		Err:      nil,
	}
	newModel, _ := model.Update(msg)
	m := newModel.(Model)

	if m.state.ClientRunning {
		t.Error("expected ClientRunning to be false")
	}
	if m.clientModel.Running {
		t.Error("expected clientModel.Running to be false")
	}
}

func TestServerStatusMessage(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		ServerRunning: true,
	}
	model := NewModel(state)
	model.serverModel.Running = true

	msg := serverStatusMsg{Stopped: true}
	newModel, _ := model.Update(msg)
	m := newModel.(Model)

	if m.state.ServerRunning {
		t.Error("expected ServerRunning to be false")
	}
	if m.serverModel.Running {
		t.Error("expected serverModel.Running to be false")
	}
}

func TestFatalErrorScreen(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewModel(state)
	model.errorFatal = true
	model.error = "Fatal error occurred"

	// Verify fatal error view renders
	view := model.View()
	if view == "" {
		t.Error("expected non-empty view")
	}

	// Key "1" should clear fatal error
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")}
	newModel, _ := model.Update(msg)
	m := newModel.(Model)

	if m.errorFatal {
		t.Error("expected errorFatal to be false")
	}
	if m.error != "" {
		t.Error("expected error to be cleared")
	}
}

func TestViewRendering(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		WorkspaceName: "Test Workspace",
	}
	model := NewModel(state)

	screens := []Screen{
		ScreenMain,
		ScreenClient,
		ScreenServer,
		ScreenPCAP,
		ScreenCatalog,
		ScreenRuns,
	}

	for _, screen := range screens {
		t.Run("render_screen_"+string(rune('0'+screen)), func(t *testing.T) {
			model.screen = screen
			view := model.View()

			if view == "" {
				t.Errorf("expected non-empty view for screen %d", screen)
			}

			// All views should include some content
			if len(view) < 100 {
				t.Errorf("view for screen %d seems too short", screen)
			}
		})
	}
}

func TestCatalogFilter(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		Catalog: []CatalogEntry{
			{Key: "identity", Name: "Identity Object", Class: "0x01"},
			{Key: "message_router", Name: "Message Router", Class: "0x02"},
			{Key: "connection_manager", Name: "Connection Manager", Class: "0x06"},
		},
	}
	model := NewCatalogScreenModel(state)

	// Type to filter
	model.Filter = "identity"
	filtered := model.filteredEntries()

	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered entry, got %d", len(filtered))
	}
	if filtered[0].Key != "identity" {
		t.Errorf("expected identity, got %s", filtered[0].Key)
	}
}

func TestRunsFilter(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		Runs: []string{
			"20260110_120000_client_baseline",
			"20260110_110000_server_adapter",
			"20260110_100000_pcap_summary",
			"20260110_090000_client_stress",
		},
	}
	model := NewRunsScreenModel(state)

	// Filter by client
	model.FilterType = "client"
	filtered := model.filteredRuns()

	if len(filtered) != 2 {
		t.Errorf("expected 2 client runs, got %d", len(filtered))
	}
}

func TestPCAPFileBrowser(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewPCAPScreenModel(state)

	// Initially not browsing
	if model.SubView == 2 {
		t.Error("expected SubView != 2 initially")
	}

	// Open file browser (will fail to load directory but shouldn't panic)
	model.openFileBrowser()

	if model.SubView != 2 {
		t.Errorf("expected SubView == 2 after openFileBrowser, got %d", model.SubView)
	}
}

func TestClientIPInput(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewClientScreenModel(state)
	model.focusIndex = clientFieldIP

	// Type IP address
	for _, ch := range "192.168.1.50" {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}}
		model, _ = model.Update(msg)
	}

	if model.TargetIP != "192.168.1.50" {
		t.Errorf("got TargetIP %q, want %q", model.TargetIP, "192.168.1.50")
	}
}

func TestClientIPBackspace(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewClientScreenModel(state)
	model.focusIndex = clientFieldIP
	model.TargetIP = "192.168.1.50"

	// Backspace
	msg := tea.KeyMsg{Type: tea.KeyBackspace}
	model, _ = model.Update(msg)

	if model.TargetIP != "192.168.1.5" {
		t.Errorf("got TargetIP %q, want %q", model.TargetIP, "192.168.1.5")
	}
}

func TestServerPersonalitySelection(t *testing.T) {
	state := &AppState{WorkspaceRoot: "/tmp/test"}
	model := NewServerScreenModel(state)
	model.focusIndex = serverFieldPersonality
	model.Personality = 0

	// Press space to cycle
	msg := tea.KeyMsg{Type: tea.KeySpace}
	model, _ = model.Update(msg)

	if model.Personality != 1 {
		t.Errorf("got Personality %d, want 1", model.Personality)
	}

	// Press space again to cycle back
	model, _ = model.Update(msg)
	if model.Personality != 0 {
		t.Errorf("got Personality %d, want 0", model.Personality)
	}
}

func TestCatalogProbeDialog(t *testing.T) {
	state := &AppState{
		WorkspaceRoot: "/tmp/test",
		Catalog: []CatalogEntry{
			{Key: "identity", Name: "Identity Object", Class: "0x01", Instance: "0x01", Attribute: "0x01", Service: "0x0E"},
		},
	}
	model := NewCatalogScreenModel(state)

	// Expand first entry
	model.expanded = true
	model.expandedIdx = 0

	// Open probe dialog
	msg := tea.KeyMsg{Type: tea.KeyEnter}
	model, _ = model.Update(msg)

	if !model.probeDialog {
		t.Error("expected probeDialog to be true")
	}

	// Type IP
	model.focusIndex = 0
	for _, ch := range "10.0.0.50" {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}}
		model, _ = model.Update(msg)
	}

	if model.ProbeIP != "10.0.0.50" {
		t.Errorf("got ProbeIP %q, want %q", model.ProbeIP, "10.0.0.50")
	}

	// Verify command includes IP
	cmd := model.buildProbeCommand()
	if cmd == "" {
		t.Error("expected non-empty probe command")
	}
}
