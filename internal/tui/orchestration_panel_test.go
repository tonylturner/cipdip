package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewOrchestrationPanel(t *testing.T) {
	styles := DefaultStyles
	panel := NewOrchestrationPanel(styles)

	if panel == nil {
		t.Fatal("NewOrchestrationPanel() returned nil")
	}

	if panel.Name() != "Orchestration" {
		t.Errorf("Name() = %s, want Orchestration", panel.Name())
	}

	if panel.Mode() != PanelIdle {
		t.Errorf("Mode() = %v, want PanelIdle", panel.Mode())
	}

	if panel.view != OrchViewController {
		t.Errorf("view = %v, want OrchViewController", panel.view)
	}
}

func TestOrchestrationPanel_Title(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)

	// Test default title
	if title := panel.Title(); title != "ORCHESTRATION" {
		t.Errorf("Title() = %s, want ORCHESTRATION", title)
	}

	// Test running title
	panel.mode = PanelRunning
	if title := panel.Title(); title != "ORCHESTRATION - RUNNING" {
		t.Errorf("Title() = %s, want ORCHESTRATION - RUNNING", title)
	}

	// Test result title
	panel.mode = PanelResult
	if title := panel.Title(); title != "ORCHESTRATION - COMPLETE" {
		t.Errorf("Title() = %s, want ORCHESTRATION - COMPLETE", title)
	}

	// Test agent view title
	panel.mode = PanelIdle
	panel.view = OrchViewAgents
	if title := panel.Title(); title != "AGENTS" {
		t.Errorf("Title() = %s, want AGENTS", title)
	}
}

func TestOrchestrationPanel_ViewToggle(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)
	panel.mode = PanelConfig

	// Should start in Controller view
	if panel.view != OrchViewController {
		t.Errorf("Initial view = %v, want OrchViewController", panel.view)
	}

	// Tab should toggle to Agent view
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("tab")}
	newPanel, _ := panel.Update(msg, true)
	panel = newPanel.(*OrchestrationPanel)

	if panel.view != OrchViewAgents {
		t.Errorf("After tab, view = %v, want OrchViewAgents", panel.view)
	}

	// Tab again should toggle back to Controller view
	newPanel, _ = panel.Update(msg, true)
	panel = newPanel.(*OrchestrationPanel)

	if panel.view != OrchViewController {
		t.Errorf("After second tab, view = %v, want OrchViewController", panel.view)
	}
}

func TestOrchestrationPanel_FieldNavigation(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)
	panel.mode = PanelConfig

	// Start at field 0
	if panel.focusedField != 0 {
		t.Errorf("Initial focusedField = %d, want 0", panel.focusedField)
	}

	// Down should move to next field
	msg := tea.KeyMsg{Type: tea.KeyDown}
	newPanel, _ := panel.Update(msg, true)
	panel = newPanel.(*OrchestrationPanel)

	if panel.focusedField != 1 {
		t.Errorf("After down, focusedField = %d, want 1", panel.focusedField)
	}

	// Up should move back
	msg = tea.KeyMsg{Type: tea.KeyUp}
	newPanel, _ = panel.Update(msg, true)
	panel = newPanel.(*OrchestrationPanel)

	if panel.focusedField != 0 {
		t.Errorf("After up, focusedField = %d, want 0", panel.focusedField)
	}
}

func TestOrchestrationPanel_ToggleFields(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)
	panel.mode = PanelConfig

	// Navigate to dryRun field (field 3)
	panel.focusedField = 3

	// Should start false
	if panel.dryRun {
		t.Error("dryRun should start false")
	}

	// Directly call handleFieldToggle to test the toggle logic
	panel.handleFieldToggle()

	if !panel.dryRun {
		t.Error("dryRun should be true after toggle")
	}

	// Toggle again should turn it back off
	panel.handleFieldToggle()

	if panel.dryRun {
		t.Error("dryRun should be false after second toggle")
	}

	// Test verbose toggle
	panel.focusedField = 4
	if panel.verbose {
		t.Error("verbose should start false")
	}

	panel.handleFieldToggle()
	if !panel.verbose {
		t.Error("verbose should be true after toggle")
	}
}

func TestOrchestrationPanel_EscapeFromConfig(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)
	panel.mode = PanelConfig

	// Escape should return to idle
	msg := tea.KeyMsg{Type: tea.KeyEscape}
	newPanel, _ := panel.Update(msg, true)
	panel = newPanel.(*OrchestrationPanel)

	if panel.mode != PanelIdle {
		t.Errorf("Mode after escape = %v, want PanelIdle", panel.mode)
	}
}

func TestOrchestrationPanel_AgentInfo(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)

	// Agent info is lazy loaded - trigger by switching to agents view
	panel.view = OrchViewAgents
	_ = panel.View(80, true) // This triggers lazy loading

	// Agent info should now be populated
	if panel.agentInfo == nil {
		t.Fatal("agentInfo should be populated after viewing agents")
	}

	// Version should be set
	if panel.agentInfo.Version == "" {
		t.Error("agentInfo.Version should not be empty")
	}

	// OS and Arch should be set
	if panel.agentInfo.OS == "" {
		t.Error("agentInfo.OS should not be empty")
	}
	if panel.agentInfo.Arch == "" {
		t.Error("agentInfo.Arch should not be empty")
	}

	// Hostname should be set
	if panel.agentInfo.Hostname == "" {
		t.Error("agentInfo.Hostname should not be empty")
	}

	// SupportedRoles should contain client and server
	foundClient := false
	foundServer := false
	for _, role := range panel.agentInfo.SupportedRoles {
		if role == "client" {
			foundClient = true
		}
		if role == "server" {
			foundServer = true
		}
	}
	if !foundClient || !foundServer {
		t.Errorf("SupportedRoles = %v, want to contain client and server", panel.agentInfo.SupportedRoles)
	}
}

func TestOrchestrationPanel_View(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)

	// Test idle view
	view := panel.View(80, false)
	if view == "" {
		t.Error("View should not be empty")
	}

	// Test config view
	panel.mode = PanelConfig
	view = panel.View(80, true)
	if view == "" {
		t.Error("Config view should not be empty")
	}

	// Test agent view
	panel.view = OrchViewAgents
	view = panel.View(80, true)
	if view == "" {
		t.Error("Agent view should not be empty")
	}
}

func TestOrchestrationPanel_ViewContent(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)

	content := panel.ViewContent(80, true)
	if content == "" {
		t.Error("ViewContent should not be empty")
	}
}

func TestGetInterfaceStatus(t *testing.T) {
	interfaces := getInterfaceStatus()

	// Should find at least loopback on most systems
	if len(interfaces) == 0 {
		t.Log("No interfaces found (may be expected in some environments)")
		return
	}

	// Each interface should have a name and at least one address
	for _, iface := range interfaces {
		if iface.Name == "" {
			t.Error("Interface name should not be empty")
		}
		if len(iface.Addresses) == 0 {
			t.Errorf("Interface %s should have at least one address", iface.Name)
		}
	}
}

func TestCheckPcapCapability(t *testing.T) {
	capable, method := checkPcapCapability()

	// Just verify it runs without error
	// Result depends on system configuration
	t.Logf("PCAP capable: %v, method: %s", capable, method)
}

func TestCanBindAddress(t *testing.T) {
	// Loopback should always be bindable
	if !canBindAddress("127.0.0.1") {
		t.Error("Should be able to bind to 127.0.0.1")
	}
}

func TestLoadManifestFiles(t *testing.T) {
	// Test with empty directory
	tmpDir := t.TempDir()
	files := LoadManifestFiles(tmpDir)

	// Should return empty list for empty directory
	if files == nil {
		files = []string{}
	}
	// The function searches for manifest files, so empty result is fine
	t.Logf("Found %d manifest files in %s", len(files), tmpDir)
}

func TestAgentMapping(t *testing.T) {
	mapping := AgentMapping{
		Role:      "server",
		Transport: "ssh://user@host",
		Status:    "pending",
	}

	if mapping.Role != "server" {
		t.Errorf("Role = %s, want server", mapping.Role)
	}
	if mapping.Transport != "ssh://user@host" {
		t.Errorf("Transport = %s, want ssh://user@host", mapping.Transport)
	}
	if mapping.Status != "pending" {
		t.Errorf("Status = %s, want pending", mapping.Status)
	}
}

func TestOrchestrationPanel_ManifestPathInput(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)
	panel.mode = PanelConfig
	panel.focusedField = 0 // manifest path field

	// Type some characters
	panel.handleFieldInput("t")
	panel.handleFieldInput("e")
	panel.handleFieldInput("s")
	panel.handleFieldInput("t")

	if panel.manifestPath != "test" {
		t.Errorf("manifestPath = %s, want test", panel.manifestPath)
	}

	// Backspace should remove character
	panel.handleFieldBackspace()
	if panel.manifestPath != "tes" {
		t.Errorf("manifestPath after backspace = %s, want tes", panel.manifestPath)
	}
}

func TestOrchestrationPanel_TimeoutInput(t *testing.T) {
	panel := NewOrchestrationPanel(DefaultStyles)
	panel.mode = PanelConfig
	panel.focusedField = 2 // timeout field
	panel.timeout = ""

	// Should only accept digits
	panel.handleFieldInput("1")
	panel.handleFieldInput("2")
	panel.handleFieldInput("a") // Should be ignored
	panel.handleFieldInput("3")

	if panel.timeout != "123" {
		t.Errorf("timeout = %s, want 123", panel.timeout)
	}
}
