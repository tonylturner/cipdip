package tui

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/manifest"
	"github.com/tturner/cipdip/internal/orch/bundle"
	"github.com/tturner/cipdip/internal/ui"
)

// OrchView represents the current sub-view of the orchestration panel.
type OrchView int

const (
	OrchViewController OrchView = iota
	OrchViewAgents          // Agent list and management
	OrchViewAgentSetup      // SSH setup wizard
	OrchViewAgentAdd        // Add new agent form
	OrchViewQuickRun        // Quick run configuration
	OrchViewManifestPicker  // Manifest file picker
)

// OrchMode represents the controller execution state.
type OrchMode int

const (
	OrchModeIdle OrchMode = iota
	OrchModeValidating
	OrchModeRunning
	OrchModeDone
	OrchModeError
)

// AgentInfo holds local agent capability information.
type AgentInfo struct {
	Version       string
	OS            string
	Arch          string
	Hostname      string
	WorkdirPath   string
	WorkdirOK     bool
	PcapCapable   bool
	PcapMethod    string
	Interfaces    []InterfaceStatus
	SupportedRoles []string
}

// InterfaceStatus holds network interface information.
type InterfaceStatus struct {
	Name      string
	Addresses []string
	CanBind   bool
}

// AgentMapping holds role to transport mapping.
type AgentMapping struct {
	Role      string
	Transport string
	Status    string // "pending", "checking", "ok", "error"
	Error     string
}

// SSHWizardStep represents steps in the SSH setup wizard.
type SSHWizardStep int

const (
	SSHStepCheckAgent SSHWizardStep = iota
	SSHStepEnterHost
	SSHStepHostKey
	SSHStepTestConnection
	SSHStepCopyID
	SSHStepVerify
	SSHStepDone
)

// OrchestrationPanel handles the orchestration panel UI.
type OrchestrationPanel struct {
	mode   PanelMode
	styles Styles

	// View toggle
	view OrchView

	// Controller state
	manifestPath    string
	manifest        *manifest.Manifest
	validationError string
	isValid         bool
	agents          []AgentMapping
	selectedAgent   int

	// Execution state
	orchMode     OrchMode
	runID        string
	bundlePath   string
	currentPhase string
	phaseError   string
	startTime    *time.Time

	// Config input
	focusedField int
	bundleDir    string
	timeout      string
	dryRun       bool
	verbose      bool

	// Agent status (for local Agent view)
	agentInfo *AgentInfo

	// Agent registry (for managing remote agents)
	agentRegistry        *ui.AgentRegistry
	registeredAgents     []*ui.Agent
	selectedAgentIdx     int
	agentCheckInProgress bool
	agentCheckMsg        string
	deleteConfirmMode    bool   // True when waiting for DELETE confirmation
	deleteConfirmInput   string // What user has typed for confirmation

	// Add agent form
	addAgentName        string
	addAgentUser        string
	addAgentHost        string
	addAgentPort        string
	addAgentDesc        string
	addAgentField       int
	addAgentError       string
	addAgentKeys        []ui.SSHKeyInfo // Available SSH keys
	addAgentKeyIdx      int             // Selected key index (0 = none/default)
	addAgentOSIdx       int             // OS index: 0=linux, 1=windows, 2=darwin

	// SSH wizard state
	sshWizardStep       SSHWizardStep
	sshAgentStatus      *ui.SSHAgentStatus
	sshKeys             []ui.SSHKeyInfo
	sshSelectedKeyIdx   int // Which key is selected (0 = first key)
	sshHostKeyType      string
	sshHostKeyFP        string
	sshHostInKnownHosts bool
	sshTestResult       string
	sshTestError        string
	sshNeedsCopyID      bool
	sshWizardMsg        string

	// Quick run configuration
	quickRunField       int      // Current field index
	quickRunServerAgent int      // Index into agent list (0=local, 1+=registered agents)
	quickRunClientAgent int      // Index into agent list
	quickRunServerProfile int    // Index into available profiles
	quickRunClientProfile int    // Index into available profiles
	quickRunScenario    int      // Index into scenarios
	quickRunTimeout     string   // Timeout in seconds
	quickRunCapture     bool     // Enable PCAP capture
	quickRunInterface   int      // Index into interfaces (0=auto, 1+=specific)
	quickRunTargetIP    string   // Target IP address
	quickRunProfiles    []string // Available profile paths
	quickRunScenarios   []string // Available scenarios
	quickRunError       string   // Error message

	// Manifest picker
	manifestFiles       []string // Available manifest files
	manifestSelectedIdx int      // Selected manifest index

	// Workspace path for agent registry
	workspacePath string

	// Run context
	runCtx    context.Context
	runCancel context.CancelFunc
}

// NewOrchestrationPanel creates a new orchestration panel.
func NewOrchestrationPanel(styles Styles) *OrchestrationPanel {
	return NewOrchestrationPanelWithWorkspace(styles, ".")
}

// NewOrchestrationPanelWithWorkspace creates a new orchestration panel with a workspace path.
func NewOrchestrationPanelWithWorkspace(styles Styles, workspacePath string) *OrchestrationPanel {
	p := &OrchestrationPanel{
		mode:          PanelIdle,
		styles:        styles,
		view:          OrchViewController,
		bundleDir:     "runs",
		timeout:       "300",
		agents:        []AgentMapping{},
		workspacePath: workspacePath,
		addAgentPort:  "22",
	}
	// Agent info and registry are loaded lazily when the panel is first viewed
	// This speeds up initial TUI startup
	return p
}

// loadAgentRegistry loads the agent registry from the workspace.
func (p *OrchestrationPanel) loadAgentRegistry() {
	registry, err := ui.LoadAgentRegistry(p.workspacePath)
	if err != nil {
		// Use empty registry on error
		p.agentRegistry = &ui.AgentRegistry{Agents: make(map[string]*ui.Agent)}
		return
	}
	p.agentRegistry = registry
	p.registeredAgents = registry.List()
}

// Name implements Panel.
func (p *OrchestrationPanel) Name() string {
	return "Orchestration"
}

// Title returns the panel title for display.
func (p *OrchestrationPanel) Title() string {
	if p.view == OrchViewAgents || p.view == OrchViewAgentSetup || p.view == OrchViewAgentAdd {
		return "AGENTS"
	}
	if p.view == OrchViewQuickRun {
		return "QUICK RUN"
	}
	switch p.mode {
	case PanelRunning:
		return "ORCHESTRATION - RUNNING"
	case PanelResult:
		return "ORCHESTRATION - COMPLETE"
	default:
		return "ORCHESTRATION"
	}
}

// ViewContent returns the panel content for display.
func (p *OrchestrationPanel) ViewContent(width int, focused bool) string {
	return p.View(width, focused)
}

// Mode implements Panel.
func (p *OrchestrationPanel) Mode() PanelMode {
	return p.mode
}

// Update implements Panel.
func (p *OrchestrationPanel) Update(msg tea.KeyMsg, focused bool) (Panel, tea.Cmd) {
	if !focused {
		return p, nil
	}

	// Lazy initialization on first interaction
	if p.agentInfo == nil {
		p.refreshAgentInfo()
	}
	if p.agentRegistry == nil {
		p.loadAgentRegistry()
	}

	key := msg.String()

	// Global panel keys
	switch key {
	case "esc":
		if p.orchMode == OrchModeRunning {
			// Cancel running operation
			if p.runCancel != nil {
				p.runCancel()
			}
			return p, nil
		}
		// Return to controller view if in a sub-view
		if p.view == OrchViewQuickRun || p.view == OrchViewAgentSetup || p.view == OrchViewAgentAdd || p.view == OrchViewManifestPicker {
			p.view = OrchViewController
			return p, nil
		}
		// Return to agents if in agents view
		if p.view == OrchViewAgents {
			p.view = OrchViewController
		}
		p.mode = PanelIdle
		return p, nil

	case "tab":
		// Toggle between Controller and Agents views
		if p.view == OrchViewController {
			p.view = OrchViewAgents
			p.loadAgentRegistry()
			p.refreshAgentInfo()
		} else if p.view == OrchViewAgents {
			p.view = OrchViewController
		}
		// Don't switch views during wizard or add form
		return p, nil
	}

	// Route to appropriate view handler
	switch p.view {
	case OrchViewAgents:
		return p.updateAgentsView(msg)
	case OrchViewAgentSetup:
		return p.updateSSHWizardView(msg)
	case OrchViewAgentAdd:
		return p.updateAddAgentView(msg)
	case OrchViewQuickRun:
		return p.updateQuickRunView(msg)
	case OrchViewManifestPicker:
		return p.updateManifestPickerView(msg)
	default:
		return p.updateControllerView(msg)
	}
}

func (p *OrchestrationPanel) updateControllerView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	switch p.mode {
	case PanelIdle:
		// Allow [n] for quick run directly from idle
		if key == "n" {
			p.startQuickRun()
			return p, nil
		}
		// Activate panel
		p.mode = PanelConfig
		return p, nil

	case PanelConfig:
		return p.handleConfigKey(key)

	case PanelRunning:
		// Allow cancel during run
		if key == "x" || key == "ctrl+c" || key == "esc" {
			if p.runCancel != nil {
				p.runCancel()
			}
			p.orchMode = OrchModeIdle
			p.mode = PanelConfig
			p.currentPhase = ""
			p.phaseError = "Cancelled by user"
		}
		return p, nil

	case PanelResult:
		switch key {
		case "enter", "r":
			// Return to config
			p.mode = PanelConfig
			p.orchMode = OrchModeIdle
		case "o":
			// Open bundle directory
			if p.bundlePath != "" {
				_ = openInEditor(p.bundlePath)
			}
		}
		return p, nil
	}

	return p, nil
}

func (p *OrchestrationPanel) handleConfigKey(key string) (Panel, tea.Cmd) {
	maxField := 4 // manifest, bundleDir, timeout, dryRun, verbose

	switch key {
	case "up", "k":
		p.focusedField--
		if p.focusedField < 0 {
			p.focusedField = maxField
		}

	case "down", "j":
		p.focusedField++
		if p.focusedField > maxField {
			p.focusedField = 0
		}

	case "left", "h":
		p.handleFieldLeft()

	case "right", "l":
		p.handleFieldRight()

	case "space":
		p.handleFieldToggle()

	case "enter":
		if p.focusedField == 0 {
			// Browse for manifest file
			p.openManifestPicker()
			return p, nil
		}
		// Start run
		if p.isValid && p.manifest != nil {
			return p.startRun()
		}

	case "d":
		// Dry run
		if p.isValid && p.manifest != nil {
			p.dryRun = true
			return p.startRun()
		}

	case "v":
		// Validate manifest
		return p.validateManifest()

	case "e":
		// Edit manifest in editor
		if p.manifestPath != "" {
			_ = openInEditor(p.manifestPath)
		}

	case "n":
		// New quick run configuration
		p.startQuickRun()
		return p, nil

	case "backspace":
		p.handleFieldBackspace()

	default:
		// Text input for editable fields
		if len(key) == 1 {
			p.handleFieldInput(key)
		}
	}

	return p, nil
}

func (p *OrchestrationPanel) handleFieldLeft() {
	switch p.focusedField {
	case 3: // dryRun toggle
		p.dryRun = !p.dryRun
	case 4: // verbose toggle
		p.verbose = !p.verbose
	}
}

func (p *OrchestrationPanel) handleFieldRight() {
	switch p.focusedField {
	case 3: // dryRun toggle
		p.dryRun = !p.dryRun
	case 4: // verbose toggle
		p.verbose = !p.verbose
	}
}

func (p *OrchestrationPanel) handleFieldToggle() {
	switch p.focusedField {
	case 3:
		p.dryRun = !p.dryRun
	case 4:
		p.verbose = !p.verbose
	}
}

func (p *OrchestrationPanel) handleFieldBackspace() {
	switch p.focusedField {
	case 0: // manifest path
		if len(p.manifestPath) > 0 {
			p.manifestPath = p.manifestPath[:len(p.manifestPath)-1]
			p.isValid = false
		}
	case 1: // bundle dir
		if len(p.bundleDir) > 0 {
			p.bundleDir = p.bundleDir[:len(p.bundleDir)-1]
		}
	case 2: // timeout
		if len(p.timeout) > 0 {
			p.timeout = p.timeout[:len(p.timeout)-1]
		}
	}
}

func (p *OrchestrationPanel) handleFieldInput(key string) {
	switch p.focusedField {
	case 0: // manifest path
		p.manifestPath += key
		p.isValid = false
	case 1: // bundle dir
		p.bundleDir += key
	case 2: // timeout
		// Only allow digits
		if key >= "0" && key <= "9" {
			p.timeout += key
		}
	}
}

func (p *OrchestrationPanel) validateManifest() (Panel, tea.Cmd) {
	if p.manifestPath == "" {
		p.validationError = "No manifest path specified"
		p.isValid = false
		return p, nil
	}

	// Load manifest
	m, err := manifest.Load(p.manifestPath)
	if err != nil {
		p.validationError = fmt.Sprintf("Load error: %v", err)
		p.isValid = false
		return p, nil
	}

	// Validate
	if err := m.Validate(); err != nil {
		p.validationError = err.Error()
		p.isValid = false
		return p, nil
	}

	p.manifest = m
	p.validationError = ""
	p.isValid = true

	// Extract agent mappings
	p.agents = p.extractAgentMappings(m)

	return p, nil
}

func (p *OrchestrationPanel) extractAgentMappings(m *manifest.Manifest) []AgentMapping {
	var mappings []AgentMapping

	if m.Roles.Server != nil {
		mappings = append(mappings, AgentMapping{
			Role:      "server",
			Transport: m.Roles.Server.Agent,
			Status:    "pending",
		})
	}

	if m.Roles.Client != nil {
		mappings = append(mappings, AgentMapping{
			Role:      "client",
			Transport: m.Roles.Client.Agent,
			Status:    "pending",
		})
	}

	return mappings
}

func (p *OrchestrationPanel) startRun() (Panel, tea.Cmd) {
	p.mode = PanelRunning
	p.orchMode = OrchModeRunning
	now := time.Now()
	p.startTime = &now
	p.currentPhase = "init"
	p.runID = p.manifest.RunID

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	p.runCtx = ctx
	p.runCancel = cancel

	// Return command to start orchestration
	// In a full implementation, this would launch the controller
	return p, func() tea.Msg {
		// Simulate orchestration phases
		return orchPhaseMsg{phase: "init", done: false}
	}
}

// updateAgentsView handles input for the agents list view.
func (p *OrchestrationPanel) updateAgentsView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	// Handle delete confirmation mode
	if p.deleteConfirmMode {
		switch key {
		case "esc":
			// Cancel delete
			p.deleteConfirmMode = false
			p.deleteConfirmInput = ""
			p.agentCheckMsg = ""
			return p, nil
		case "backspace":
			if len(p.deleteConfirmInput) > 0 {
				p.deleteConfirmInput = p.deleteConfirmInput[:len(p.deleteConfirmInput)-1]
			}
			return p, nil
		case "enter":
			// Check if DELETE was typed
			if p.deleteConfirmInput == "DELETE" {
				if p.selectedAgentIdx > 0 && p.selectedAgentIdx <= len(p.registeredAgents) {
					agent := p.registeredAgents[p.selectedAgentIdx-1]
					p.agentRegistry.Remove(agent.Name)
					_ = p.agentRegistry.Save()
					p.loadAgentRegistry()
					if p.selectedAgentIdx > len(p.registeredAgents) {
						p.selectedAgentIdx = len(p.registeredAgents)
					}
					p.agentCheckMsg = "Agent deleted"
				}
			}
			p.deleteConfirmMode = false
			p.deleteConfirmInput = ""
			return p, nil
		default:
			// Add typed character (only uppercase letters)
			if len(key) == 1 && key >= "A" && key <= "Z" {
				p.deleteConfirmInput += key
			} else if len(key) == 1 && key >= "a" && key <= "z" {
				// Convert to uppercase
				p.deleteConfirmInput += strings.ToUpper(key)
			}
			return p, nil
		}
	}

	switch key {
	case "r", "R":
		// Refresh agent info and registry
		p.refreshAgentInfo()
		p.loadAgentRegistry()

	case "up", "k":
		if p.selectedAgentIdx > 0 {
			p.selectedAgentIdx--
		}

	case "down", "j":
		maxIdx := len(p.registeredAgents)
		if p.selectedAgentIdx < maxIdx {
			p.selectedAgentIdx++
		}

	case "a":
		// Add new agent - go to add form
		p.view = OrchViewAgentAdd
		p.addAgentName = ""
		p.addAgentUser = ""
		p.addAgentHost = ""
		p.addAgentPort = "22"
		p.addAgentDesc = ""
		p.addAgentField = 0
		p.addAgentError = ""
		p.addAgentKeys, _ = ui.FindSSHKeys()
		p.addAgentKeyIdx = 0 // 0 = default (no specific key)
		p.addAgentOSIdx = 0  // 0 = linux (default)

	case "s":
		// SSH Setup wizard
		p.startSSHWizard()

	case "d":
		// Start delete confirmation for selected agent
		if p.selectedAgentIdx > 0 && p.selectedAgentIdx <= len(p.registeredAgents) {
			agent := p.registeredAgents[p.selectedAgentIdx-1]
			p.deleteConfirmMode = true
			p.deleteConfirmInput = ""
			p.agentCheckMsg = fmt.Sprintf("Delete '%s'? Type DELETE to confirm:", agent.Name)
		}

	case "c":
		// Check connectivity for selected agent
		if p.selectedAgentIdx > 0 && p.selectedAgentIdx <= len(p.registeredAgents) {
			agent := p.registeredAgents[p.selectedAgentIdx-1]
			p.checkAgentConnectivity(agent)
		}

	case "C":
		// Check all agents
		for _, agent := range p.registeredAgents {
			p.checkAgentConnectivity(agent)
		}
		_ = p.agentRegistry.Save()

	case "enter":
		// Use selected agent in manifest (copy transport to clipboard or show it)
		if p.selectedAgentIdx > 0 && p.selectedAgentIdx <= len(p.registeredAgents) {
			agent := p.registeredAgents[p.selectedAgentIdx-1]
			p.agentCheckMsg = fmt.Sprintf("Use --agent <role>=%s", agent.Transport)
		}
	}

	return p, nil
}

// updateAddAgentView handles input for the add agent form.
func (p *OrchestrationPanel) updateAddAgentView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	switch key {
	case "esc":
		p.view = OrchViewAgents
		return p, nil

	case "tab", "down":
		p.addAgentField = (p.addAgentField + 1) % 7

	case "shift+tab", "up":
		p.addAgentField--
		if p.addAgentField < 0 {
			p.addAgentField = 6
		}

	case "left":
		// Key selection (field 5)
		if p.addAgentField == 5 && len(p.addAgentKeys) > 0 {
			p.addAgentKeyIdx--
			if p.addAgentKeyIdx < 0 {
				p.addAgentKeyIdx = len(p.addAgentKeys) // Wrap to "default"
			}
		}
		// OS selection (field 6)
		if p.addAgentField == 6 {
			p.addAgentOSIdx--
			if p.addAgentOSIdx < 0 {
				p.addAgentOSIdx = 2 // Wrap to darwin
			}
		}

	case "right":
		// Key selection (field 5)
		if p.addAgentField == 5 && len(p.addAgentKeys) > 0 {
			p.addAgentKeyIdx++
			if p.addAgentKeyIdx > len(p.addAgentKeys) {
				p.addAgentKeyIdx = 0
			}
		}
		// OS selection (field 6)
		if p.addAgentField == 6 {
			p.addAgentOSIdx++
			if p.addAgentOSIdx > 2 {
				p.addAgentOSIdx = 0 // Wrap to linux
			}
		}

	case "enter":
		// Save the agent
		if p.addAgentHost == "" {
			p.addAgentError = "Host is required"
			return p, nil
		}
		if p.addAgentName == "" {
			// Generate name from host
			p.addAgentName = strings.Split(p.addAgentHost, ".")[0]
		}

		// Build transport
		info := &ui.SSHInfo{
			User: p.addAgentUser,
			Host: p.addAgentHost,
			Port: p.addAgentPort,
		}
		if info.Port == "" {
			info.Port = "22"
		}

		// Add selected key if not default
		if p.addAgentKeyIdx > 0 && p.addAgentKeyIdx <= len(p.addAgentKeys) {
			info.KeyFile = p.addAgentKeys[p.addAgentKeyIdx-1].Path
		}

		// Set OS if not linux (default)
		osNames := []string{"linux", "windows", "darwin"}
		if p.addAgentOSIdx > 0 {
			info.OS = osNames[p.addAgentOSIdx]
		}

		agent := &ui.Agent{
			Name:        p.addAgentName,
			Transport:   info.ToTransport(),
			Description: p.addAgentDesc,
			Status:      ui.AgentStatusUnknown,
		}

		p.agentRegistry.Add(agent)
		if err := p.agentRegistry.Save(); err != nil {
			p.addAgentError = fmt.Sprintf("Save failed: %v", err)
			return p, nil
		}

		p.loadAgentRegistry()
		p.view = OrchViewAgents
		return p, nil

	case "backspace":
		p.handleAddAgentBackspace()

	default:
		if len(key) == 1 {
			p.handleAddAgentInput(key)
		}
	}

	return p, nil
}

func (p *OrchestrationPanel) handleAddAgentBackspace() {
	switch p.addAgentField {
	case 0:
		if len(p.addAgentName) > 0 {
			p.addAgentName = p.addAgentName[:len(p.addAgentName)-1]
		}
	case 1:
		if len(p.addAgentUser) > 0 {
			p.addAgentUser = p.addAgentUser[:len(p.addAgentUser)-1]
		}
	case 2:
		if len(p.addAgentHost) > 0 {
			p.addAgentHost = p.addAgentHost[:len(p.addAgentHost)-1]
		}
	case 3:
		if len(p.addAgentPort) > 0 {
			p.addAgentPort = p.addAgentPort[:len(p.addAgentPort)-1]
		}
	case 4:
		if len(p.addAgentDesc) > 0 {
			p.addAgentDesc = p.addAgentDesc[:len(p.addAgentDesc)-1]
		}
	}
}

func (p *OrchestrationPanel) handleAddAgentInput(key string) {
	switch p.addAgentField {
	case 0:
		p.addAgentName += key
	case 1:
		p.addAgentUser += key
	case 2:
		p.addAgentHost += key
	case 3:
		if key >= "0" && key <= "9" {
			p.addAgentPort += key
		}
	case 4:
		p.addAgentDesc += key
	}
}

// startSSHWizard initializes and starts the SSH setup wizard.
func (p *OrchestrationPanel) startSSHWizard() {
	p.view = OrchViewAgentSetup
	p.sshWizardStep = SSHStepCheckAgent
	p.sshWizardMsg = ""

	// Check SSH agent status
	p.sshAgentStatus = ui.CheckSSHAgent()

	// Find SSH keys
	p.sshKeys, _ = ui.FindSSHKeys()

	// Reset form fields
	p.addAgentUser = ""
	p.addAgentHost = ""
	p.addAgentPort = "22"
	p.addAgentName = ""
}

// updateSSHWizardView handles input for the SSH setup wizard.
func (p *OrchestrationPanel) updateSSHWizardView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	switch key {
	case "esc":
		p.view = OrchViewAgents
		return p, nil
	}

	// Handle step-specific keys (each step handles its own navigation)
	switch p.sshWizardStep {
	case SSHStepCheckAgent:
		return p.handleSSHStepCheckAgent(key)
	case SSHStepEnterHost:
		return p.handleSSHStepEnterHost(key)
	case SSHStepHostKey:
		return p.handleSSHStepHostKey(key)
	case SSHStepTestConnection:
		return p.handleSSHStepTestConnection(key)
	case SSHStepCopyID:
		return p.handleSSHStepCopyID(key)
	case SSHStepVerify:
		return p.handleSSHStepVerify(key)
	case SSHStepDone:
		if key == "enter" {
			p.view = OrchViewAgents
		}
		return p, nil
	}

	return p, nil
}

func (p *OrchestrationPanel) handleSSHStepCheckAgent(key string) (Panel, tea.Cmd) {
	switch key {
	case "left", "backspace":
		// Go back to agents view
		p.view = OrchViewAgents
		return p, nil

	case "up", "k":
		// Select previous key
		if len(p.sshKeys) > 0 && p.sshSelectedKeyIdx > 0 {
			p.sshSelectedKeyIdx--
		}

	case "down", "j":
		// Select next key
		if len(p.sshKeys) > 0 && p.sshSelectedKeyIdx < len(p.sshKeys)-1 {
			p.sshSelectedKeyIdx++
		}

	case "enter", "right":
		// If no keys, offer to generate
		if len(p.sshKeys) == 0 {
			p.sshWizardMsg = "No SSH keys found. Press [g] to generate one."
			return p, nil
		}
		p.sshWizardStep = SSHStepEnterHost
		p.sshWizardMsg = ""

	case "g", "G":
		// Generate new SSH key (works even if keys exist)
		home, _ := os.UserHomeDir()
		keyPath := filepath.Join(home, ".ssh", "id_ed25519_cipdip")
		hostname, _ := os.Hostname()
		comment := fmt.Sprintf("cipdip@%s", hostname)

		if err := ui.GenerateSSHKey(keyPath, comment); err != nil {
			p.sshWizardMsg = fmt.Sprintf("Key generation failed: %v", err)
		} else {
			p.sshWizardMsg = fmt.Sprintf("Generated: %s (no passphrase)", keyPath)
			p.sshKeys, _ = ui.FindSSHKeys()
			// Select the new key
			for i, k := range p.sshKeys {
				if k.Path == keyPath {
					p.sshSelectedKeyIdx = i
					break
				}
			}
		}

	case "y", "Y":
		// Legacy: same as 'g' when no keys
		if len(p.sshKeys) == 0 {
			home, _ := os.UserHomeDir()
			keyPath := filepath.Join(home, ".ssh", "id_ed25519_cipdip")
			hostname, _ := os.Hostname()
			comment := fmt.Sprintf("cipdip@%s", hostname)

			if err := ui.GenerateSSHKey(keyPath, comment); err != nil {
				p.sshWizardMsg = fmt.Sprintf("Key generation failed: %v", err)
			} else {
				p.sshWizardMsg = fmt.Sprintf("Generated: %s", keyPath)
				p.sshKeys, _ = ui.FindSSHKeys()
			}
		}

	case "n", "N":
		if len(p.sshKeys) == 0 {
			p.sshWizardMsg = "SSH key required for key-based authentication"
		}
	}
	return p, nil
}

func (p *OrchestrationPanel) handleSSHStepEnterHost(key string) (Panel, tea.Cmd) {
	switch key {
	case "left":
		// OS selection on field 4
		if p.addAgentField == 4 {
			p.addAgentOSIdx--
			if p.addAgentOSIdx < 0 {
				p.addAgentOSIdx = 2 // Wrap to darwin
			}
			return p, nil
		}
		// Go back to previous step
		p.sshWizardStep = SSHStepCheckAgent
		p.sshWizardMsg = ""
		return p, nil

	case "right":
		// OS selection on field 4
		if p.addAgentField == 4 {
			p.addAgentOSIdx++
			if p.addAgentOSIdx > 2 {
				p.addAgentOSIdx = 0 // Wrap to linux
			}
			return p, nil
		}

	case "enter":
		if p.addAgentHost == "" {
			p.sshWizardMsg = "Host is required"
			return p, nil
		}
		// Check host key
		p.sshWizardStep = SSHStepHostKey
		p.sshWizardMsg = "Checking host key..."

		// Get host key
		keyType, fp, err := ui.GetHostKey(p.addAgentHost, p.addAgentPort)
		if err != nil {
			p.sshWizardMsg = fmt.Sprintf("Could not get host key: %v", err)
			return p, nil
		}
		p.sshHostKeyType = keyType
		p.sshHostKeyFP = fp

		// Check if in known_hosts
		p.sshHostInKnownHosts, _ = ui.CheckHostInKnownHosts(p.addAgentHost, p.addAgentPort)
		p.sshWizardMsg = ""

	case "tab", "down":
		p.addAgentField = (p.addAgentField + 1) % 5

	case "shift+tab", "up":
		p.addAgentField--
		if p.addAgentField < 0 {
			p.addAgentField = 4
		}

	case "backspace":
		// Delete character from current field
		switch p.addAgentField {
		case 0:
			if len(p.addAgentUser) > 0 {
				p.addAgentUser = p.addAgentUser[:len(p.addAgentUser)-1]
			}
		case 1:
			if len(p.addAgentHost) > 0 {
				p.addAgentHost = p.addAgentHost[:len(p.addAgentHost)-1]
			}
		case 2:
			if len(p.addAgentPort) > 0 {
				p.addAgentPort = p.addAgentPort[:len(p.addAgentPort)-1]
			}
		case 3:
			if len(p.addAgentName) > 0 {
				p.addAgentName = p.addAgentName[:len(p.addAgentName)-1]
			}
		}

	default:
		// Text input - single character keys
		if len(key) == 1 {
			switch p.addAgentField {
			case 0:
				p.addAgentUser += key
			case 1:
				p.addAgentHost += key
			case 2:
				if key >= "0" && key <= "9" {
					p.addAgentPort += key
				}
			case 3:
				p.addAgentName += key
			}
		}
	}
	return p, nil
}

func (p *OrchestrationPanel) handleSSHStepHostKey(key string) (Panel, tea.Cmd) {
	switch key {
	case "left", "backspace":
		p.sshWizardStep = SSHStepEnterHost
		p.sshWizardMsg = ""
		return p, nil

	case "y", "Y":
		// Add to known_hosts
		if err := ui.AddToKnownHosts(p.addAgentHost, p.addAgentPort); err != nil {
			p.sshWizardMsg = fmt.Sprintf("Failed to add host key: %v", err)
			return p, nil
		}
		p.sshHostInKnownHosts = true
		p.sshWizardMsg = "Host key added to known_hosts"
		p.sshWizardStep = SSHStepTestConnection

	case "enter", "right":
		if p.sshHostInKnownHosts {
			p.sshWizardStep = SSHStepTestConnection
			p.sshWizardMsg = ""
		} else {
			p.sshWizardMsg = "Add host to known_hosts? [y] or skip [s]"
		}

	case "s", "S":
		// Skip - continue without adding to known_hosts (insecure)
		p.sshWizardStep = SSHStepTestConnection
		p.sshWizardMsg = "Warning: Host not in known_hosts"
	}
	return p, nil
}

func (p *OrchestrationPanel) handleSSHStepTestConnection(key string) (Panel, tea.Cmd) {
	switch key {
	case "left", "backspace":
		p.sshWizardStep = SSHStepHostKey
		p.sshWizardMsg = ""
		return p, nil

	case "enter", "t", "T":
		// Test connection
		p.sshWizardMsg = "Testing connection..."

		// Get selected key file
		var keyFile string
		if p.sshSelectedKeyIdx >= 0 && p.sshSelectedKeyIdx < len(p.sshKeys) {
			keyFile = p.sshKeys[p.sshSelectedKeyIdx].Path
		}

		err := ui.TestSSHConnection(p.addAgentUser, p.addAgentHost, p.addAgentPort, keyFile)
		if err != nil {
			p.sshTestError = err.Error()
			p.sshNeedsCopyID = true
			p.sshWizardMsg = "Connection failed - may need to copy SSH key"
			p.sshWizardStep = SSHStepCopyID
		} else {
			p.sshTestResult = "Connection successful!"
			p.sshTestError = ""
			p.sshWizardStep = SSHStepVerify
			p.sshWizardMsg = ""
		}

	case "right", "s", "S":
		// Skip test
		p.sshWizardStep = SSHStepVerify
	}
	return p, nil
}

func (p *OrchestrationPanel) handleSSHStepCopyID(key string) (Panel, tea.Cmd) {
	switch key {
	case "left", "backspace":
		p.sshWizardStep = SSHStepTestConnection
		p.sshWizardMsg = ""
		return p, nil

	case "y", "Y", "enter":
		// Build ssh-copy-id command using selected key
		var keyFile string
		if len(p.sshKeys) > 0 && p.sshSelectedKeyIdx < len(p.sshKeys) {
			keyFile = p.sshKeys[p.sshSelectedKeyIdx].Path + ".pub"
		}

		// Use tea.ExecProcess to properly suspend TUI and run the command
		cmd := p.buildSSHCopyIDCmd(keyFile)
		p.sshWizardMsg = "Running ssh-copy-id..."
		return p, cmd

	case "n", "N", "s", "right":
		// Skip
		p.sshWizardStep = SSHStepVerify
		p.sshWizardMsg = "Skipped ssh-copy-id"
	}
	return p, nil
}

// buildSSHCopyIDCmd creates a tea.Cmd that runs ssh-copy-id with proper terminal handling.
func (p *OrchestrationPanel) buildSSHCopyIDCmd(keyFile string) tea.Cmd {
	args := []string{}

	if keyFile != "" {
		args = append(args, "-i", keyFile)
	}

	if p.addAgentPort != "" && p.addAgentPort != "22" {
		args = append(args, "-p", p.addAgentPort)
	}

	target := p.addAgentHost
	if p.addAgentUser != "" {
		target = p.addAgentUser + "@" + p.addAgentHost
	}
	args = append(args, target)

	cmd := exec.Command("ssh-copy-id", args...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return sshCopyIDResultMsg{err: err}
	})
}

// sshCopyIDResultMsg is sent when ssh-copy-id completes.
type sshCopyIDResultMsg struct {
	err error
}

func (p *OrchestrationPanel) handleSSHStepVerify(key string) (Panel, tea.Cmd) {
	switch key {
	case "left", "backspace":
		p.sshWizardStep = SSHStepTestConnection
		p.sshWizardMsg = ""
		return p, nil

	case "enter", "v", "V":
		// Final verification and save
		var keyFile string
		if p.sshSelectedKeyIdx >= 0 && p.sshSelectedKeyIdx < len(p.sshKeys) {
			keyFile = p.sshKeys[p.sshSelectedKeyIdx].Path
		}

		err := ui.TestSSHConnection(p.addAgentUser, p.addAgentHost, p.addAgentPort, keyFile)
		if err != nil {
			p.sshWizardMsg = fmt.Sprintf("Verification failed: %v", err)
			return p, nil
		}

		// Save agent
		if p.addAgentName == "" {
			p.addAgentName = strings.Split(p.addAgentHost, ".")[0]
		}

		info := &ui.SSHInfo{
			User: p.addAgentUser,
			Host: p.addAgentHost,
			Port: p.addAgentPort,
		}
		// Set OS if not linux (default)
		osNames := []string{"linux", "windows", "darwin"}
		if p.addAgentOSIdx > 0 {
			info.OS = osNames[p.addAgentOSIdx]
		}
		// Add selected key if available
		if p.sshSelectedKeyIdx >= 0 && p.sshSelectedKeyIdx < len(p.sshKeys) {
			info.KeyFile = p.sshKeys[p.sshSelectedKeyIdx].Path
		}

		agent := &ui.Agent{
			Name:      p.addAgentName,
			Transport: info.ToTransport(),
			Status:    ui.AgentStatusOK,
			LastCheck: time.Now(),
		}

		p.agentRegistry.Add(agent)
		if err := p.agentRegistry.Save(); err != nil {
			p.sshWizardMsg = fmt.Sprintf("Save failed: %v", err)
			return p, nil
		}

		p.loadAgentRegistry()
		p.sshWizardStep = SSHStepDone
		p.sshWizardMsg = fmt.Sprintf("Agent '%s' added successfully!", p.addAgentName)

	case "s":
		// Save without verification
		if p.addAgentName == "" {
			p.addAgentName = strings.Split(p.addAgentHost, ".")[0]
		}

		info := &ui.SSHInfo{
			User: p.addAgentUser,
			Host: p.addAgentHost,
			Port: p.addAgentPort,
		}
		// Set OS if not linux (default)
		osNames := []string{"linux", "windows", "darwin"}
		if p.addAgentOSIdx > 0 {
			info.OS = osNames[p.addAgentOSIdx]
		}
		// Add selected key if available
		if p.sshSelectedKeyIdx >= 0 && p.sshSelectedKeyIdx < len(p.sshKeys) {
			info.KeyFile = p.sshKeys[p.sshSelectedKeyIdx].Path
		}

		agent := &ui.Agent{
			Name:      p.addAgentName,
			Transport: info.ToTransport(),
			Status:    ui.AgentStatusUnknown,
		}

		p.agentRegistry.Add(agent)
		_ = p.agentRegistry.Save()
		p.loadAgentRegistry()
		p.sshWizardStep = SSHStepDone
		p.sshWizardMsg = fmt.Sprintf("Agent '%s' added (not verified)", p.addAgentName)
	}
	return p, nil
}

// checkAgentConnectivity checks the connectivity of a remote agent.
func (p *OrchestrationPanel) checkAgentConnectivity(agent *ui.Agent) {
	info, err := ui.ParseSSHTransport(agent.Transport)
	if err != nil {
		agent.Status = ui.AgentStatusError
		agent.StatusMsg = err.Error()
		return
	}

	err = ui.TestSSHConnection(info.User, info.Host, info.Port, info.KeyFile)
	if err != nil {
		agent.Status = ui.AgentStatusUnreachable
		agent.StatusMsg = err.Error()
	} else {
		agent.Status = ui.AgentStatusOK
		agent.StatusMsg = "Connected"
	}
	agent.LastCheck = time.Now()
}

func (p *OrchestrationPanel) refreshAgentInfo() {
	hostname, _ := os.Hostname()

	info := &AgentInfo{
		Version:        version,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Hostname:       hostname,
		SupportedRoles: []string{"client", "server"},
	}

	// Check workdir
	workdir := filepath.Join(os.TempDir(), "cipdip-agent")
	info.WorkdirPath = workdir
	if err := os.MkdirAll(workdir, 0755); err == nil {
		// Test write
		testFile := filepath.Join(workdir, ".test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err == nil {
			os.Remove(testFile)
			info.WorkdirOK = true
		}
	}

	// Check PCAP capability
	info.PcapCapable, info.PcapMethod = checkPcapCapability()

	// Get network interfaces
	info.Interfaces = getInterfaceStatus()

	p.agentInfo = info
}

func checkPcapCapability() (bool, string) {
	// Check for tcpdump
	if _, err := exec.LookPath("tcpdump"); err == nil {
		return true, "tcpdump"
	}
	// Check for tshark
	if _, err := exec.LookPath("tshark"); err == nil {
		return true, "tshark"
	}
	// Check for dumpcap
	if _, err := exec.LookPath("dumpcap"); err == nil {
		return true, "dumpcap"
	}
	return false, ""
}

func getInterfaceStatus() []InterfaceStatus {
	var result []InterfaceStatus

	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range ifaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var addrStrs []string
		for _, addr := range addrs {
			// Get IP from addr
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			addrStrs = append(addrStrs, ip.String())
		}

		if len(addrStrs) == 0 {
			continue
		}

		status := InterfaceStatus{
			Name:      iface.Name,
			Addresses: addrStrs,
			CanBind:   canBindAddress(addrStrs[0]),
		}
		result = append(result, status)
	}

	return result
}

func canBindAddress(addr string) bool {
	ln, err := net.Listen("tcp", addr+":0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}

// View implements Panel.
func (p *OrchestrationPanel) View(width int, focused bool) string {
	// Ensure data is loaded before rendering views that need it
	if p.view == OrchViewAgents || p.view == OrchViewAgentSetup || p.view == OrchViewAgentAdd {
		if p.agentInfo == nil {
			p.refreshAgentInfo()
		}
		if p.agentRegistry == nil {
			p.loadAgentRegistry()
		}
	}

	switch p.view {
	case OrchViewAgents:
		return p.renderAgentsView(width, focused)
	case OrchViewAgentSetup:
		return p.renderSSHWizardView(width, focused)
	case OrchViewAgentAdd:
		return p.renderAddAgentView(width, focused)
	case OrchViewQuickRun:
		return p.renderQuickRunView(width, focused)
	case OrchViewManifestPicker:
		return p.renderManifestPickerView(width, focused)
	default:
		return p.renderControllerView(width, focused)
	}
}

func (p *OrchestrationPanel) renderControllerView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	// Header with view tabs
	controllerTab := "Controller"
	agentTab := "Agents"
	if p.view == OrchViewController {
		controllerTab = s.Selected.Render("[Controller]")
		agentTab = s.Dim.Render(" Agents ")
	} else {
		controllerTab = s.Dim.Render(" Controller ")
		agentTab = s.Selected.Render("[Agents]")
	}
	b.WriteString(s.Header.Render("ORCHESTRATION") + "  " + controllerTab + " | " + agentTab + "\n\n")

	switch p.mode {
	case PanelIdle:
		b.WriteString(s.Dim.Render("Press any key to configure orchestration...\n\n"))
		b.WriteString(s.Dim.Render("[n] Quick Run - configure a test without YAML"))

	case PanelConfig:
		b.WriteString(p.renderConfigView(width, focused))

	case PanelRunning:
		b.WriteString(p.renderRunningView(width))

	case PanelResult:
		b.WriteString(p.renderResultView(width))
	}

	return b.String()
}

func (p *OrchestrationPanel) renderConfigView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	// Manifest field
	manifestLabel := "Manifest:"
	manifestValue := p.manifestPath
	if manifestValue == "" {
		manifestValue = "(enter path or press Enter to browse)"
	}
	if p.focusedField == 0 {
		b.WriteString(s.Selected.Render(manifestLabel) + " " + s.Selected.Render(manifestValue) + "\n")
	} else {
		b.WriteString(s.Label.Render(manifestLabel) + " " + manifestValue + "\n")
	}

	// Validation status
	if p.manifestPath != "" {
		if p.isValid {
			b.WriteString(s.Success.Render("  ✓ Valid") + "\n")
		} else if p.validationError != "" {
			b.WriteString(s.Error.Render("  ✗ " + p.validationError) + "\n")
		} else {
			b.WriteString(s.Dim.Render("  Press 'v' to validate") + "\n")
		}
	}
	b.WriteString("\n")

	// Bundle directory
	bundleLabel := "Bundle Dir:"
	if p.focusedField == 1 {
		b.WriteString(s.Selected.Render(bundleLabel) + " " + s.Selected.Render(p.bundleDir) + "\n")
	} else {
		b.WriteString(s.Label.Render(bundleLabel) + " " + p.bundleDir + "\n")
	}

	// Timeout
	timeoutLabel := "Timeout (s):"
	if p.focusedField == 2 {
		b.WriteString(s.Selected.Render(timeoutLabel) + " " + s.Selected.Render(p.timeout) + "\n")
	} else {
		b.WriteString(s.Label.Render(timeoutLabel) + " " + p.timeout + "\n")
	}

	// Dry run toggle
	dryRunLabel := "Dry Run:"
	dryRunValue := "[ ]"
	if p.dryRun {
		dryRunValue = "[✓]"
	}
	if p.focusedField == 3 {
		b.WriteString(s.Selected.Render(dryRunLabel) + " " + s.Selected.Render(dryRunValue) + "\n")
	} else {
		b.WriteString(s.Label.Render(dryRunLabel) + " " + dryRunValue + "\n")
	}

	// Verbose toggle
	verboseLabel := "Verbose:"
	verboseValue := "[ ]"
	if p.verbose {
		verboseValue = "[✓]"
	}
	if p.focusedField == 4 {
		b.WriteString(s.Selected.Render(verboseLabel) + " " + s.Selected.Render(verboseValue) + "\n")
	} else {
		b.WriteString(s.Label.Render(verboseLabel) + " " + verboseValue + "\n")
	}

	// Agent mappings (if manifest is loaded)
	if p.manifest != nil && len(p.agents) > 0 {
		b.WriteString("\n" + s.Header.Render("Agents:") + "\n")
		for _, agent := range p.agents {
			statusIcon := "○"
			statusStyle := s.Dim
			switch agent.Status {
			case "ok":
				statusIcon = "✓"
				statusStyle = s.Success
			case "error":
				statusIcon = "✗"
				statusStyle = s.Error
			case "checking":
				statusIcon = "◐"
				statusStyle = s.Info
			}
			b.WriteString(fmt.Sprintf("  %s %s: %s\n",
				statusStyle.Render(statusIcon),
				s.Label.Render(agent.Role),
				agent.Transport))
		}
	}

	// Actions
	b.WriteString("\n" + s.Dim.Render("────────────────────────────────────────") + "\n")
	actions := []string{"[Enter] Start", "[d] Dry Run", "[v] Validate", "[e] Edit"}
	if p.isValid {
		b.WriteString(strings.Join(actions, "  "))
	} else {
		b.WriteString(s.Dim.Render("[v] Validate") + "  " + s.Dim.Render("[e] Edit"))
	}
	b.WriteString("\n" + s.Dim.Render("[n] Quick Run  [Tab] Manage Agents  [Esc] Close"))

	return b.String()
}

func (p *OrchestrationPanel) renderRunningView(width int) string {
	var b strings.Builder
	s := p.styles

	b.WriteString(s.Header.Render("Run ID:") + " " + p.runID + "\n")

	// Phase display
	phases := []string{"init", "stage", "server_start", "server_ready", "client_start", "client_done", "server_stop", "collect", "bundle"}
	currentIdx := 0
	for i, phase := range phases {
		if phase == p.currentPhase {
			currentIdx = i
			break
		}
	}

	b.WriteString(s.Label.Render("Phase:") + " ")
	for i := range phases {
		if i < currentIdx {
			b.WriteString(s.Success.Render("✓"))
		} else if i == currentIdx {
			b.WriteString(s.Info.Render("▶"))
		} else {
			b.WriteString(s.Dim.Render("○"))
		}
	}
	b.WriteString(" " + s.Selected.Render(p.currentPhase) + "\n")

	// Elapsed time
	if p.startTime != nil {
		elapsed := time.Since(*p.startTime)
		b.WriteString(s.Label.Render("Elapsed:") + " " + formatDuration(elapsed.Seconds()) + "\n")
	}

	// Actions
	b.WriteString("\n" + s.Dim.Render("[x] Stop") + "\n")

	return b.String()
}

func (p *OrchestrationPanel) renderResultView(width int) string {
	var b strings.Builder
	s := p.styles

	if p.orchMode == OrchModeError {
		b.WriteString(s.Error.Render("Run Failed") + "\n\n")
		b.WriteString(s.Label.Render("Error:") + " " + p.phaseError + "\n")
	} else {
		b.WriteString(s.Success.Render("Run Complete") + "\n\n")
	}

	b.WriteString(s.Label.Render("Run ID:") + " " + p.runID + "\n")
	if p.bundlePath != "" {
		b.WriteString(s.Label.Render("Bundle:") + " " + p.bundlePath + "\n")
	}

	// Actions
	b.WriteString("\n" + s.Dim.Render("[Enter] New Run  [o] Open Bundle") + "\n")

	return b.String()
}

func (p *OrchestrationPanel) renderAgentsView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	// Header with view tabs
	controllerTab := s.Dim.Render(" Controller ")
	agentTab := s.Selected.Render("[Agents]")
	b.WriteString(s.Header.Render("ORCHESTRATION") + "  " + controllerTab + " | " + agentTab + "\n\n")

	// Content buffer for height management
	var content strings.Builder

	// Registered agents list
	content.WriteString(s.Header.Render("Registered Agents:") + "\n")

	// Local agent (always first)
	localSelected := p.selectedAgentIdx == 0
	localMarker := "  "
	if localSelected {
		localMarker = s.Selected.Render("▸ ")
	}
	localStatus := s.Success.Render("✓")
	if p.agentInfo != nil && !p.agentInfo.WorkdirOK {
		localStatus = s.Warning.Render("!")
	}
	localLine := fmt.Sprintf("%s%s %-16s %s", localMarker, localStatus, "local", s.Dim.Render("(this machine)"))
	if localSelected {
		content.WriteString(s.Selected.Render(localLine) + "\n")
	} else {
		content.WriteString(localLine + "\n")
	}

	// Registered remote agents
	for i, agent := range p.registeredAgents {
		idx := i + 1
		selected := p.selectedAgentIdx == idx
		marker := "  "
		if selected {
			marker = s.Selected.Render("▸ ")
		}

		statusIcon := s.Dim.Render("○")
		switch agent.Status {
		case ui.AgentStatusOK:
			statusIcon = s.Success.Render("✓")
		case ui.AgentStatusUnreachable:
			statusIcon = s.Error.Render("✗")
		case ui.AgentStatusError:
			statusIcon = s.Error.Render("!")
		}

		line := fmt.Sprintf("%s%s %-16s %s", marker, statusIcon, agent.Name, agent.Transport)
		if selected {
			content.WriteString(s.Selected.Render(line) + "\n")
		} else {
			content.WriteString(line + "\n")
		}
	}

	if len(p.registeredAgents) == 0 {
		content.WriteString(s.Dim.Render("  No remote agents registered") + "\n")
	}

	// Selected agent details
	content.WriteString("\n")
	if p.selectedAgentIdx == 0 {
		// Local agent details
		content.WriteString(s.Header.Render("Local Agent Details:") + "\n")
		if p.agentInfo != nil {
			content.WriteString(s.Label.Render("  Version:") + "    " + p.agentInfo.Version + "\n")
			content.WriteString(s.Label.Render("  OS/Arch:") + "    " + p.agentInfo.OS + "/" + p.agentInfo.Arch + "\n")
			content.WriteString(s.Label.Render("  Hostname:") + "   " + p.agentInfo.Hostname + "\n")
			pcapStatus := "Not available"
			if p.agentInfo.PcapCapable {
				pcapStatus = "Available (" + p.agentInfo.PcapMethod + ")"
			}
			content.WriteString(s.Label.Render("  PCAP:") + "       " + pcapStatus + "\n")
		}
	} else if p.selectedAgentIdx <= len(p.registeredAgents) {
		agent := p.registeredAgents[p.selectedAgentIdx-1]
		content.WriteString(s.Header.Render("Agent Details:") + " " + agent.Name + "\n")
		content.WriteString(s.Label.Render("  Transport:") + "  " + agent.Transport + "\n")
		if agent.Description != "" {
			content.WriteString(s.Label.Render("  Description:") + " " + agent.Description + "\n")
		}
		content.WriteString(s.Label.Render("  Status:") + "     " + string(agent.Status) + "\n")
		if agent.StatusMsg != "" {
			content.WriteString(s.Label.Render("  Message:") + "    " + agent.StatusMsg + "\n")
		}
		if !agent.LastCheck.IsZero() {
			content.WriteString(s.Label.Render("  Last Check:") + " " + agent.LastCheck.Format("2006-01-02 15:04:05") + "\n")
		}
	}

	// Status message or delete confirmation
	if p.deleteConfirmMode {
		content.WriteString("\n" + s.Warning.Render(p.agentCheckMsg) + "\n")
		content.WriteString(s.Selected.Render("  > " + p.deleteConfirmInput + "_") + "\n")
		content.WriteString(s.Dim.Render("  [Enter] Confirm  [Esc] Cancel") + "\n")
	} else if p.agentCheckMsg != "" {
		content.WriteString("\n" + s.Info.Render(p.agentCheckMsg) + "\n")
	}

	// Actions footer
	content.WriteString("\n" + s.Dim.Render("─────────────────────────────────────────────") + "\n")
	if !p.deleteConfirmMode {
		content.WriteString("[a] Add  [d] Delete  [c] Check  [C] Check All  [s] SSH Setup\n")
		content.WriteString("[R] Refresh  [Tab] Controller  [Enter] Use in manifest\n")
	}

	// Normalize to fixed height (20 lines)
	contentLines := strings.Split(content.String(), "\n")
	fixedHeight := 20
	for len(contentLines) < fixedHeight {
		contentLines = append(contentLines, "")
	}
	if len(contentLines) > fixedHeight {
		contentLines = contentLines[:fixedHeight]
	}

	b.WriteString(strings.Join(contentLines, "\n"))

	return b.String()
}

func (p *OrchestrationPanel) renderAddAgentView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	b.WriteString(s.Header.Render("ADD AGENT") + "\n\n")

	// Content buffer for height management
	var content strings.Builder

	// Form fields (text input fields)
	fields := []struct {
		label string
		value string
	}{
		{"Name:", p.addAgentName},
		{"User:", p.addAgentUser},
		{"Host:", p.addAgentHost},
		{"Port:", p.addAgentPort},
		{"Description:", p.addAgentDesc},
	}

	for i, field := range fields {
		label := s.Label.Render(field.label)
		value := field.value
		if value == "" {
			value = s.Dim.Render("(empty)")
		}

		if i == p.addAgentField {
			content.WriteString(s.Selected.Render(fmt.Sprintf("▸ %-12s %s", field.label, value)) + "\n")
		} else {
			content.WriteString(fmt.Sprintf("  %-12s %s\n", label, value))
		}
	}

	// SSH Key field (field 5) - uses left/right arrows to cycle
	keyLabel := s.Label.Render("SSH Key:")
	var keyValue string
	if p.addAgentKeyIdx == 0 {
		keyValue = "(default)"
	} else if p.addAgentKeyIdx <= len(p.addAgentKeys) {
		key := p.addAgentKeys[p.addAgentKeyIdx-1]
		keyValue = fmt.Sprintf("%s (%s)", key.Name, key.Type)
	}
	if p.addAgentField == 5 {
		hint := ""
		if len(p.addAgentKeys) > 0 {
			hint = " [←/→ to change]"
		}
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ %-12s %s%s", "SSH Key:", keyValue, hint)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %-12s %s\n", keyLabel, keyValue))
	}

	// OS field (field 6) - uses left/right arrows to cycle
	osNames := []string{"linux", "windows", "darwin"}
	osLabel := s.Label.Render("OS:")
	osValue := osNames[p.addAgentOSIdx]
	if p.addAgentField == 6 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ %-12s %s [←/→ to change]", "OS:", osValue)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %-12s %s\n", osLabel, osValue))
	}

	// Error message
	if p.addAgentError != "" {
		content.WriteString("\n" + s.Error.Render("Error: "+p.addAgentError) + "\n")
	}

	// Preview
	if p.addAgentHost != "" {
		info := &ui.SSHInfo{
			User: p.addAgentUser,
			Host: p.addAgentHost,
			Port: p.addAgentPort,
		}
		if p.addAgentKeyIdx > 0 && p.addAgentKeyIdx <= len(p.addAgentKeys) {
			info.KeyFile = p.addAgentKeys[p.addAgentKeyIdx-1].Path
		}
		if p.addAgentOSIdx > 0 {
			info.OS = osNames[p.addAgentOSIdx]
		}
		content.WriteString("\n" + s.Dim.Render("Transport: "+info.ToTransport()) + "\n")
	}

	// Actions
	content.WriteString("\n" + s.Dim.Render("[Enter] Save  [Tab] Next  [←/→] Key  [Esc] Cancel") + "\n")

	// Normalize to fixed height (18 lines)
	contentLines := strings.Split(content.String(), "\n")
	fixedHeight := 18
	for len(contentLines) < fixedHeight {
		contentLines = append(contentLines, "")
	}
	if len(contentLines) > fixedHeight {
		contentLines = contentLines[:fixedHeight]
	}

	b.WriteString(strings.Join(contentLines, "\n"))

	return b.String()
}

func (p *OrchestrationPanel) renderSSHWizardView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	b.WriteString(s.Header.Render("SSH SETUP WIZARD") + "\n\n")

	// Progress bar
	steps := []string{"Agent", "Host", "Key", "Test", "Copy", "Verify", "Done"}
	for i := range steps {
		if i < int(p.sshWizardStep) {
			b.WriteString(s.Success.Render("✓"))
		} else if i == int(p.sshWizardStep) {
			b.WriteString(s.Info.Render("▶"))
		} else {
			b.WriteString(s.Dim.Render("○"))
		}
		b.WriteString(" ")
	}
	b.WriteString("\n")
	for i, step := range steps {
		if i == int(p.sshWizardStep) {
			b.WriteString(s.Selected.Render(step))
		} else {
			b.WriteString(s.Dim.Render(step))
		}
		b.WriteString("  ")
	}
	b.WriteString("\n\n")

	// Step content - rendered to a separate buffer for height management
	var stepContent strings.Builder

	switch p.sshWizardStep {
	case SSHStepCheckAgent:
		stepContent.WriteString(s.Header.Render("Step 1: Check SSH Agent") + "\n\n")

		if p.sshAgentStatus != nil && p.sshAgentStatus.Running {
			stepContent.WriteString(s.Success.Render("✓ SSH Agent Running") + "\n")
			stepContent.WriteString(s.Label.Render("  Socket:") + " " + p.sshAgentStatus.SocketPath + "\n")
			stepContent.WriteString(s.Label.Render("  Keys:") + fmt.Sprintf("   %d loaded\n", p.sshAgentStatus.KeyCount))
		} else {
			stepContent.WriteString(s.Warning.Render("! SSH Agent not running") + "\n")
			stepContent.WriteString(s.Dim.Render("  Run: eval \"$(ssh-agent -s)\" && ssh-add") + "\n")
		}

		stepContent.WriteString("\n" + s.Header.Render("SSH Keys (↑/↓ to select):") + "\n")
		if len(p.sshKeys) == 0 {
			stepContent.WriteString(s.Warning.Render("  No SSH keys found in ~/.ssh/") + "\n")
		} else {
			for i, key := range p.sshKeys {
				marker := "  "
				if i == p.sshSelectedKeyIdx {
					marker = s.Selected.Render("▸ ")
				}
				pubStatus := ""
				if key.HasPub {
					pubStatus = s.Dim.Render(" (.pub)")
				}
				keyLine := fmt.Sprintf("%s%s%s", marker, key.Path, pubStatus)
				if i == p.sshSelectedKeyIdx {
					stepContent.WriteString(s.Selected.Render(keyLine) + "\n")
				} else {
					stepContent.WriteString(keyLine + "\n")
				}
			}
		}

		if len(p.sshKeys) == 0 {
			stepContent.WriteString("\n" + s.Dim.Render("[g] Generate new key  [Enter] Continue") + "\n")
		} else {
			stepContent.WriteString("\n" + s.Dim.Render("[Enter] Use selected  [g] Generate new key") + "\n")
		}

	case SSHStepEnterHost:
		stepContent.WriteString(s.Header.Render("Step 2: Remote Host") + "\n\n")

		fields := []struct {
			label string
			value string
		}{
			{"Username:", p.addAgentUser},
			{"Host:", p.addAgentHost},
			{"Port:", p.addAgentPort},
			{"Agent Name:", p.addAgentName},
		}

		for i, field := range fields {
			value := field.value
			if value == "" {
				value = s.Dim.Render("(empty)")
			}

			if i == p.addAgentField {
				stepContent.WriteString(s.Selected.Render(fmt.Sprintf("▸ %-12s %s", field.label, value)) + "\n")
			} else {
				stepContent.WriteString(fmt.Sprintf("  %-12s %s\n", s.Label.Render(field.label), value))
			}
		}

		// OS field (field 4) - uses left/right arrows to cycle
		osNames := []string{"linux", "windows", "darwin"}
		osLabel := s.Label.Render("OS:")
		osValue := osNames[p.addAgentOSIdx]
		if p.addAgentField == 4 {
			stepContent.WriteString(s.Selected.Render(fmt.Sprintf("▸ %-12s %s [←/→]", "OS:", osValue)) + "\n")
		} else {
			stepContent.WriteString(fmt.Sprintf("  %-12s %s\n", osLabel, osValue))
		}

		stepContent.WriteString("\n" + s.Dim.Render("[Tab] Next field  [←/→] Change OS  [Enter] Continue") + "\n")

	case SSHStepHostKey:
		stepContent.WriteString(s.Header.Render("Step 3: Host Key Verification") + "\n\n")

		stepContent.WriteString(s.Label.Render("Host:") + " " + p.addAgentHost + "\n")
		stepContent.WriteString(s.Label.Render("Key Type:") + " " + p.sshHostKeyType + "\n")
		if p.sshHostKeyFP != "" {
			stepContent.WriteString(s.Label.Render("Fingerprint:") + "\n  " + p.sshHostKeyFP + "\n")
		}

		stepContent.WriteString("\n")
		if p.sshHostInKnownHosts {
			stepContent.WriteString(s.Success.Render("✓ Host is in known_hosts") + "\n")
			stepContent.WriteString(s.Dim.Render("[Enter] Continue") + "\n")
		} else {
			stepContent.WriteString(s.Warning.Render("! Host not in known_hosts") + "\n")
			stepContent.WriteString(s.Dim.Render("[y] Add to known_hosts  [s] Skip (insecure)") + "\n")
		}

	case SSHStepTestConnection:
		stepContent.WriteString(s.Header.Render("Step 4: Test Connection") + "\n\n")

		target := p.addAgentHost
		if p.addAgentUser != "" {
			target = p.addAgentUser + "@" + target
		}
		stepContent.WriteString(s.Label.Render("Testing:") + " ssh " + target + "\n\n")

		stepContent.WriteString(s.Dim.Render("[Enter] Test connection  [→] Skip") + "\n")

	case SSHStepCopyID:
		stepContent.WriteString(s.Header.Render("Step 5: Copy SSH Key") + "\n\n")

		if p.sshTestError != "" {
			stepContent.WriteString(s.Error.Render("Connection failed:") + "\n")
			stepContent.WriteString("  " + p.sshTestError + "\n\n")
		}

		stepContent.WriteString("To enable key-based authentication, your public key needs\n")
		stepContent.WriteString("to be copied to the remote server.\n\n")

		if len(p.sshKeys) > 0 && p.sshSelectedKeyIdx < len(p.sshKeys) {
			stepContent.WriteString(s.Label.Render("Key to copy:") + " " + p.sshKeys[p.sshSelectedKeyIdx].Path + ".pub\n")
		}

		stepContent.WriteString("\n" + s.Warning.Render("WARNING: Password prompt will appear BELOW this window.") + "\n")
		stepContent.WriteString(s.Warning.Render("Look at your terminal for the ssh-copy-id prompt.") + "\n\n")
		stepContent.WriteString(s.Dim.Render("[y] Run ssh-copy-id  [n] Skip") + "\n")

	case SSHStepVerify:
		stepContent.WriteString(s.Header.Render("Step 6: Verify & Save") + "\n\n")

		if p.addAgentName == "" {
			p.addAgentName = strings.Split(p.addAgentHost, ".")[0]
		}

		info := &ui.SSHInfo{
			User: p.addAgentUser,
			Host: p.addAgentHost,
			Port: p.addAgentPort,
		}

		stepContent.WriteString(s.Label.Render("Agent Name:") + " " + p.addAgentName + "\n")
		stepContent.WriteString(s.Label.Render("Transport:") + "  " + info.ToTransport() + "\n")

		stepContent.WriteString("\n" + s.Dim.Render("[Enter] Verify & Save  [s] Save without verify") + "\n")

		// Add tip about passphrase keys
		stepContent.WriteString("\n" + s.Dim.Render("Tip: If verify fails with 'exit 255', your key may have a") + "\n")
		stepContent.WriteString(s.Dim.Render("passphrase. Run: ssh-add ~/.ssh/id_ed25519") + "\n")

	case SSHStepDone:
		stepContent.WriteString(s.Success.Render("Setup Complete!") + "\n\n")
		stepContent.WriteString(s.Dim.Render("[Enter] Return to agent list") + "\n")
	}

	// Message
	if p.sshWizardMsg != "" {
		stepContent.WriteString("\n" + s.Info.Render(p.sshWizardMsg) + "\n")
	}

	// Navigation footer
	stepContent.WriteString("\n" + s.Dim.Render("[←] Back  [Esc] Cancel") + "\n")

	// Normalize content to fixed height (18 lines for step content area)
	// This prevents graphical artifacts when switching steps
	contentLines := strings.Split(stepContent.String(), "\n")
	fixedHeight := 18
	for len(contentLines) < fixedHeight {
		contentLines = append(contentLines, "")
	}
	if len(contentLines) > fixedHeight {
		contentLines = contentLines[:fixedHeight]
	}

	b.WriteString(strings.Join(contentLines, "\n"))

	return b.String()
}


// orchPhaseMsg is sent when orchestration phase changes.
type orchPhaseMsg struct {
	phase string
	done  bool
	err   error
}

// version is defined in main.go but we need it here
var version = "0.2.1"

// LoadManifestFiles returns a list of manifest files in the workspace.
func LoadManifestFiles(workspaceRoot string) []string {
	var manifests []string

	// Check common locations
	patterns := []string{
		filepath.Join(workspaceRoot, "*.yaml"),
		filepath.Join(workspaceRoot, "manifests", "*.yaml"),
		filepath.Join(workspaceRoot, "manifest*.yaml"),
	}

	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			// Skip non-manifest files
			base := filepath.Base(m)
			if strings.HasPrefix(base, "manifest") || strings.Contains(base, "run") {
				manifests = append(manifests, m)
			}
		}
	}

	return manifests
}

// verifyBundle opens a bundle and verifies it.
func verifyBundle(path string) (*bundle.VerifyResult, error) {
	b, err := bundle.Open(path)
	if err != nil {
		return nil, err
	}
	return b.Verify(bundle.DefaultVerifyOptions())
}

// getAvailableScenarios returns a list of known scenario names.
func getAvailableScenarios() []string {
	return []string{
		"baseline",
		"mixed",
		"stress",
		"io",
		"churn",
		"dpi_explicit",
		"edge_valid",
		"edge_vendor",
		"rockwell",
		"vendor_variants",
		"mixed_state",
		"unconnected_send",
	}
}

// findProfileFiles looks for profile YAML files in common locations.
func findProfileFiles(workspaceRoot string) []string {
	var profiles []string

	// Check common locations
	searchPaths := []string{
		filepath.Join(workspaceRoot, "profiles"),
		"profiles",
		filepath.Join(workspaceRoot, "workspaces", "workspace", "profiles"),
	}

	for _, searchPath := range searchPaths {
		pattern := filepath.Join(searchPath, "*.yaml")
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			// Skip non-profile files
			base := filepath.Base(m)
			if !strings.HasPrefix(base, "manifest") {
				profiles = append(profiles, m)
			}
		}
	}

	return profiles
}

// startQuickRun initializes the quick run configuration view.
func (p *OrchestrationPanel) startQuickRun() {
	p.view = OrchViewQuickRun
	p.quickRunField = 0
	p.quickRunServerAgent = 0 // Local by default
	p.quickRunClientAgent = 0 // Local by default
	p.quickRunServerProfile = 0
	p.quickRunClientProfile = 0
	p.quickRunScenario = 0
	p.quickRunTimeout = "60"
	p.quickRunCapture = false
	p.quickRunInterface = 0 // 0 = auto
	p.quickRunTargetIP = "127.0.0.1"
	p.quickRunError = ""

	// Load available scenarios
	p.quickRunScenarios = getAvailableScenarios()

	// Find profile files
	p.quickRunProfiles = findProfileFiles(p.workspacePath)
	if len(p.quickRunProfiles) == 0 {
		// Add a placeholder
		p.quickRunProfiles = []string{"(no profiles found)"}
	}

	// Make sure agent registry is loaded
	if p.agentRegistry == nil {
		p.loadAgentRegistry()
	}

	// Load agent info for interfaces
	if p.agentInfo == nil {
		p.refreshAgentInfo()
	}
}

// updateQuickRunView handles input for the quick run configuration view.
func (p *OrchestrationPanel) updateQuickRunView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	// Fields: 0=server agent, 1=client agent, 2=scenario, 3=profile, 4=duration, 5=target IP, 6=capture, 7=interface
	maxField := 6
	if p.quickRunCapture {
		maxField = 7 // Show interface field when capture is enabled
	}

	switch key {
	case "esc":
		p.view = OrchViewController
		return p, nil

	case "up", "k":
		p.quickRunField--
		if p.quickRunField < 0 {
			p.quickRunField = maxField
		}
		// Skip interface field if capture is disabled
		if p.quickRunField == 7 && !p.quickRunCapture {
			p.quickRunField = 6
		}

	case "down", "j":
		p.quickRunField++
		if p.quickRunField > maxField {
			p.quickRunField = 0
		}

	case "left", "h":
		p.handleQuickRunLeft()

	case "right", "l":
		p.handleQuickRunRight()

	case " ", "space":
		if p.quickRunField == 6 { // capture toggle
			p.quickRunCapture = !p.quickRunCapture
		}

	case "enter":
		// Generate and start run
		return p.generateQuickRunManifest()

	case "backspace":
		if p.quickRunField == 4 { // duration
			if len(p.quickRunTimeout) > 0 {
				p.quickRunTimeout = p.quickRunTimeout[:len(p.quickRunTimeout)-1]
			}
		} else if p.quickRunField == 5 { // target IP
			if len(p.quickRunTargetIP) > 0 {
				p.quickRunTargetIP = p.quickRunTargetIP[:len(p.quickRunTargetIP)-1]
			}
		}

	default:
		// Text input for editable fields
		if len(key) == 1 {
			if p.quickRunField == 4 { // duration - only digits
				if key >= "0" && key <= "9" {
					p.quickRunTimeout += key
				}
			} else if p.quickRunField == 5 { // target IP
				// Allow digits and dots for IP
				if (key >= "0" && key <= "9") || key == "." {
					p.quickRunTargetIP += key
				}
			}
		}
	}

	return p, nil
}

// handleQuickRunLeft handles left arrow in quick run view.
func (p *OrchestrationPanel) handleQuickRunLeft() {
	totalAgents := 1 + len(p.registeredAgents) // local + registered

	switch p.quickRunField {
	case 0: // server agent
		p.quickRunServerAgent--
		if p.quickRunServerAgent < 0 {
			p.quickRunServerAgent = totalAgents - 1
		}
	case 1: // client agent
		p.quickRunClientAgent--
		if p.quickRunClientAgent < 0 {
			p.quickRunClientAgent = totalAgents - 1
		}
	case 2: // scenario
		p.quickRunScenario--
		if p.quickRunScenario < 0 {
			p.quickRunScenario = len(p.quickRunScenarios) - 1
		}
	case 3: // profile
		p.quickRunServerProfile--
		if p.quickRunServerProfile < 0 {
			p.quickRunServerProfile = len(p.quickRunProfiles) - 1
		}
	case 6: // capture toggle
		p.quickRunCapture = !p.quickRunCapture
	case 7: // interface
		totalIfaces := 1 + len(p.agentInfo.Interfaces) // auto + interfaces
		p.quickRunInterface--
		if p.quickRunInterface < 0 {
			p.quickRunInterface = totalIfaces - 1
		}
	}
}

// handleQuickRunRight handles right arrow in quick run view.
func (p *OrchestrationPanel) handleQuickRunRight() {
	totalAgents := 1 + len(p.registeredAgents) // local + registered

	switch p.quickRunField {
	case 0: // server agent
		p.quickRunServerAgent++
		if p.quickRunServerAgent >= totalAgents {
			p.quickRunServerAgent = 0
		}
	case 1: // client agent
		p.quickRunClientAgent++
		if p.quickRunClientAgent >= totalAgents {
			p.quickRunClientAgent = 0
		}
	case 2: // scenario
		p.quickRunScenario++
		if p.quickRunScenario >= len(p.quickRunScenarios) {
			p.quickRunScenario = 0
		}
	case 3: // profile
		p.quickRunServerProfile++
		if p.quickRunServerProfile >= len(p.quickRunProfiles) {
			p.quickRunServerProfile = 0
		}
	case 6: // capture toggle
		p.quickRunCapture = !p.quickRunCapture
	case 7: // interface
		totalIfaces := 1 + len(p.agentInfo.Interfaces) // auto + interfaces
		p.quickRunInterface++
		if p.quickRunInterface >= totalIfaces {
			p.quickRunInterface = 0
		}
	}
}

// getAgentName returns the display name for an agent index.
func (p *OrchestrationPanel) getAgentName(idx int) string {
	if idx == 0 {
		return "local"
	}
	if idx-1 < len(p.registeredAgents) {
		return p.registeredAgents[idx-1].Name
	}
	return "unknown"
}

// getAgentTransport returns the transport string for an agent index.
// Automatically appends ?os=windows if the agent is detected as Windows.
func (p *OrchestrationPanel) getAgentTransport(idx int) string {
	if idx == 0 {
		return "local"
	}
	if idx-1 < len(p.registeredAgents) {
		agent := p.registeredAgents[idx-1]
		transport := agent.Transport

		// Auto-append ?os=windows if agent OS is Windows (detected from OSArch)
		if strings.HasPrefix(strings.ToLower(agent.OSArch), "windows") {
			// Only add if not already present
			if !strings.Contains(transport, "os=") {
				if strings.Contains(transport, "?") {
					transport += "&os=windows"
				} else {
					transport += "?os=windows"
				}
			}
		}

		return transport
	}
	return "local"
}

// generateQuickRunManifest creates a manifest from quick run settings.
func (p *OrchestrationPanel) generateQuickRunManifest() (Panel, tea.Cmd) {
	// Get target IP
	targetIP := p.quickRunTargetIP
	if targetIP == "" {
		targetIP = "127.0.0.1"
	}

	// Build profile path
	profilePath := ""
	if p.quickRunServerProfile < len(p.quickRunProfiles) && !strings.HasPrefix(p.quickRunProfiles[p.quickRunServerProfile], "(") {
		profilePath = p.quickRunProfiles[p.quickRunServerProfile]
	}

	// Get duration from timeout
	duration := 60
	if p.quickRunTimeout != "" {
		fmt.Sscanf(p.quickRunTimeout, "%d", &duration)
	}

	// Create manifest
	m := &manifest.Manifest{
		APIVersion: manifest.APIVersion,
		RunID:      "auto",
		Profile: manifest.ProfileConfig{
			Path:         profilePath,
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				ServerListenIP: targetIP,
				TargetIP:       targetIP,
				TargetPort:     44818,
			},
		},
		Roles: manifest.RolesConfig{
			Server: &manifest.ServerRoleConfig{
				Agent:       p.getAgentTransport(p.quickRunServerAgent),
				Mode:        "emulator",
				Personality: "adapter",
			},
			Client: &manifest.ClientRoleConfig{
				Agent:           p.getAgentTransport(p.quickRunClientAgent),
				Scenario:        p.quickRunScenarios[p.quickRunScenario],
				DurationSeconds: duration,
				IntervalMs:      100,
			},
		},
		Readiness: manifest.ReadinessConfig{
			Method:         "structured_stdout",
			TimeoutSeconds: 30,
		},
		Artifacts: manifest.ArtifactsConfig{
			BundleFormat: "dir",
		},
	}

	// Save manifest to temp file
	manifestPath := filepath.Join(p.workspacePath, "manifests", fmt.Sprintf("quickrun_%s.yaml", time.Now().Format("20060102_150405")))
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0755); err != nil {
		p.quickRunError = fmt.Sprintf("Failed to create manifests directory: %v", err)
		return p, nil
	}

	if err := m.SaveYAML(manifestPath); err != nil {
		p.quickRunError = fmt.Sprintf("Failed to save manifest: %v", err)
		return p, nil
	}

	// Set up for execution
	p.manifest = m
	p.manifestPath = manifestPath
	p.isValid = true
	p.view = OrchViewController
	p.mode = PanelConfig

	// Extract agent mappings
	p.agents = p.extractAgentMappings(m)

	return p, nil
}

// getInterfaceName returns the display name for an interface index.
func (p *OrchestrationPanel) getInterfaceName(idx int) string {
	if idx == 0 {
		return "auto"
	}
	if p.agentInfo != nil && idx-1 < len(p.agentInfo.Interfaces) {
		iface := p.agentInfo.Interfaces[idx-1]
		if len(iface.Addresses) > 0 {
			return fmt.Sprintf("%s (%s)", iface.Name, iface.Addresses[0])
		}
		return iface.Name
	}
	return "auto"
}

// renderQuickRunView renders the quick run configuration form.
func (p *OrchestrationPanel) renderQuickRunView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	b.WriteString(s.Header.Render("QUICK RUN CONFIGURATION") + "\n\n")

	// Content buffer for height management
	var content strings.Builder

	content.WriteString(s.Dim.Render("Configure a test run without editing YAML files.") + "\n")
	content.WriteString(s.Dim.Render("Use ←/→ to change values, ↑/↓ to navigate, Space to toggle.") + "\n\n")

	// Server agent field (0)
	serverAgentName := p.getAgentName(p.quickRunServerAgent)
	if p.quickRunField == 0 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Server Agent:   < %s >", serverAgentName)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s   %s\n", s.Label.Render("Server Agent:"), serverAgentName))
	}

	// Client agent field (1)
	clientAgentName := p.getAgentName(p.quickRunClientAgent)
	if p.quickRunField == 1 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Client Agent:   < %s >", clientAgentName)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s   %s\n", s.Label.Render("Client Agent:"), clientAgentName))
	}

	content.WriteString("\n")

	// Scenario field (2)
	scenarioName := ""
	if p.quickRunScenario < len(p.quickRunScenarios) {
		scenarioName = p.quickRunScenarios[p.quickRunScenario]
	}
	if p.quickRunField == 2 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Scenario:       < %s >", scenarioName)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s       %s\n", s.Label.Render("Scenario:"), scenarioName))
	}

	// Profile field (3)
	profileName := "(none)"
	if p.quickRunServerProfile < len(p.quickRunProfiles) {
		profileName = filepath.Base(p.quickRunProfiles[p.quickRunServerProfile])
	}
	if p.quickRunField == 3 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Profile:        < %s >", profileName)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s        %s\n", s.Label.Render("Profile:"), profileName))
	}

	// Duration field (4)
	if p.quickRunField == 4 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Duration (s):   %s_", p.quickRunTimeout)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s   %s\n", s.Label.Render("Duration (s):"), p.quickRunTimeout))
	}

	// Target IP field (5) - used for both server listen and client target
	if p.quickRunField == 5 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Target IP:      %s_", p.quickRunTargetIP)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s      %s\n", s.Label.Render("Target IP:"), p.quickRunTargetIP))
	}

	content.WriteString("\n")

	// PCAP Capture toggle (6)
	captureValue := "[ ] Off"
	if p.quickRunCapture {
		captureValue = "[✓] On"
	}
	if p.quickRunField == 6 {
		content.WriteString(s.Selected.Render(fmt.Sprintf("▸ PCAP Capture:   %s", captureValue)) + "\n")
	} else {
		content.WriteString(fmt.Sprintf("  %s   %s\n", s.Label.Render("PCAP Capture:"), captureValue))
	}

	// Interface field (7) - only shown when capture is enabled
	if p.quickRunCapture {
		interfaceName := p.getInterfaceName(p.quickRunInterface)
		if p.quickRunField == 7 {
			content.WriteString(s.Selected.Render(fmt.Sprintf("▸ Interface:      < %s >", interfaceName)) + "\n")
		} else {
			content.WriteString(fmt.Sprintf("  %s      %s\n", s.Label.Render("Interface:"), interfaceName))
		}

		// Show PCAP output paths
		runID := time.Now().Format("2006-01-02_15-04-05")
		pcapDir := filepath.Join("runs", runID, "pcap")
		content.WriteString(s.Dim.Render(fmt.Sprintf("  Output: %s/server.pcap", pcapDir)) + "\n")
		content.WriteString(s.Dim.Render(fmt.Sprintf("          %s/client.pcap", pcapDir)) + "\n")
	}

	// Summary
	content.WriteString("\n" + s.Dim.Render("─────────────────────────────────────────────") + "\n")
	content.WriteString(s.Header.Render("Summary:") + "\n")
	content.WriteString(fmt.Sprintf("  Server: %s will run emulator (%s)\n", serverAgentName, "adapter"))
	content.WriteString(fmt.Sprintf("  Client: %s will run scenario '%s'\n", clientAgentName, scenarioName))
	content.WriteString(fmt.Sprintf("  Target: %s:44818 for %ss\n", p.quickRunTargetIP, p.quickRunTimeout))
	if p.quickRunCapture {
		content.WriteString(fmt.Sprintf("  Capture: %s\n", p.getInterfaceName(p.quickRunInterface)))
	}

	// Error message
	if p.quickRunError != "" {
		content.WriteString("\n" + s.Error.Render("Error: "+p.quickRunError) + "\n")
	}

	// Actions
	content.WriteString("\n" + s.Dim.Render("[Enter] Generate & Run  [Space] Toggle  [Esc] Cancel") + "\n")

	// Normalize to fixed height
	contentLines := strings.Split(content.String(), "\n")
	fixedHeight := 26
	for len(contentLines) < fixedHeight {
		contentLines = append(contentLines, "")
	}
	if len(contentLines) > fixedHeight {
		contentLines = contentLines[:fixedHeight]
	}

	b.WriteString(strings.Join(contentLines, "\n"))

	return b.String()
}

// openManifestPicker opens the manifest file picker view.
func (p *OrchestrationPanel) openManifestPicker() {
	p.view = OrchViewManifestPicker
	p.manifestSelectedIdx = 0

	// Find manifest files
	p.manifestFiles = findManifestFiles(p.workspacePath)
}

// findManifestFiles looks for manifest YAML files in common locations.
func findManifestFiles(workspaceRoot string) []string {
	var manifests []string

	// Check common locations
	searchPaths := []string{
		filepath.Join(workspaceRoot, "manifests"),
		"manifests",
		workspaceRoot,
		".",
	}

	for _, searchPath := range searchPaths {
		pattern := filepath.Join(searchPath, "*.yaml")
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			base := filepath.Base(m)
			// Include files that look like manifests
			if strings.Contains(base, "manifest") || strings.Contains(base, "quickrun") || strings.Contains(base, "run") {
				// Check if not already in list
				found := false
				for _, existing := range manifests {
					if existing == m {
						found = true
						break
					}
				}
				if !found {
					manifests = append(manifests, m)
				}
			}
		}
	}

	return manifests
}

// updateManifestPickerView handles input for the manifest picker view.
func (p *OrchestrationPanel) updateManifestPickerView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	switch key {
	case "esc":
		p.view = OrchViewController
		return p, nil

	case "up", "k":
		if p.manifestSelectedIdx > 0 {
			p.manifestSelectedIdx--
		}

	case "down", "j":
		if p.manifestSelectedIdx < len(p.manifestFiles)-1 {
			p.manifestSelectedIdx++
		}

	case "enter":
		if len(p.manifestFiles) > 0 && p.manifestSelectedIdx < len(p.manifestFiles) {
			p.manifestPath = p.manifestFiles[p.manifestSelectedIdx]
			p.isValid = false
			p.view = OrchViewController
			// Auto-validate
			p.validateManifest()
		}
		return p, nil
	}

	return p, nil
}

// renderManifestPickerView renders the manifest file picker.
func (p *OrchestrationPanel) renderManifestPickerView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	b.WriteString(s.Header.Render("SELECT MANIFEST") + "\n\n")

	var content strings.Builder

	if len(p.manifestFiles) == 0 {
		content.WriteString(s.Dim.Render("No manifest files found.") + "\n")
		content.WriteString(s.Dim.Render("Create one with [n] Quick Run or manually.") + "\n")
	} else {
		content.WriteString(s.Dim.Render("↑/↓ select, Enter load, Esc cancel") + "\n\n")

		// Calculate column widths
		listWidth := 40
		if width > 80 {
			listWidth = 45
		}

		// Build file list
		var fileLines []string
		for i, file := range p.manifestFiles {
			marker := "  "
			if i == p.manifestSelectedIdx {
				marker = "▸ "
			}

			// Show relative path if possible
			displayPath := file
			if rel, err := filepath.Rel(".", file); err == nil && !strings.HasPrefix(rel, "..") {
				displayPath = rel
			}

			// Truncate if too long
			if len(displayPath) > listWidth-4 {
				displayPath = "..." + displayPath[len(displayPath)-listWidth+7:]
			}

			line := fmt.Sprintf("%s%s", marker, displayPath)
			if i == p.manifestSelectedIdx {
				fileLines = append(fileLines, s.Selected.Render(line))
			} else {
				fileLines = append(fileLines, line)
			}
		}

		// Build preview for selected manifest
		var previewLines []string
		if p.manifestSelectedIdx < len(p.manifestFiles) {
			previewLines = p.getManifestPreview(p.manifestFiles[p.manifestSelectedIdx])
		}

		// Render side by side
		maxLines := len(fileLines)
		if len(previewLines) > maxLines {
			maxLines = len(previewLines)
		}

		for i := 0; i < maxLines; i++ {
			fileLine := ""
			if i < len(fileLines) {
				fileLine = fileLines[i]
			}

			previewLine := ""
			if i < len(previewLines) {
				previewLine = previewLines[i]
			}

			// Pad file line to fixed width (approximate since we have ANSI codes)
			content.WriteString(fmt.Sprintf("%-42s │ %s\n", fileLine, previewLine))
		}
	}

	content.WriteString("\n" + s.Dim.Render("[Enter] Select  [Esc] Cancel") + "\n")

	// Normalize to fixed height
	contentLines := strings.Split(content.String(), "\n")
	fixedHeight := 20
	for len(contentLines) < fixedHeight {
		contentLines = append(contentLines, "")
	}
	if len(contentLines) > fixedHeight {
		contentLines = contentLines[:fixedHeight]
	}

	b.WriteString(strings.Join(contentLines, "\n"))

	return b.String()
}

// getManifestPreview returns preview lines for a manifest file.
func (p *OrchestrationPanel) getManifestPreview(path string) []string {
	s := p.styles
	var lines []string

	m, err := manifest.Load(path)
	if err != nil {
		lines = append(lines, s.Error.Render("Error loading manifest"))
		lines = append(lines, s.Dim.Render(err.Error()))
		return lines
	}

	lines = append(lines, s.Header.Render("Preview:"))
	lines = append(lines, "")

	// Run ID
	if m.RunID != "" && m.RunID != "auto" {
		lines = append(lines, s.Label.Render("Run ID: ")+m.RunID)
	}

	// Server role
	if m.Roles.Server != nil {
		lines = append(lines, s.Label.Render("Server: ")+m.Roles.Server.Agent)
		if m.Roles.Server.Personality != "" {
			lines = append(lines, s.Dim.Render("  personality: ")+m.Roles.Server.Personality)
		}
	}

	// Client role
	if m.Roles.Client != nil {
		lines = append(lines, s.Label.Render("Client: ")+m.Roles.Client.Agent)
		lines = append(lines, s.Dim.Render("  scenario: ")+m.Roles.Client.Scenario)
		lines = append(lines, s.Dim.Render(fmt.Sprintf("  duration: %ds", m.Roles.Client.DurationSeconds)))
	}

	// Network
	if m.Network.DataPlane.TargetIP != "" {
		lines = append(lines, s.Label.Render("Target: ")+fmt.Sprintf("%s:%d", m.Network.DataPlane.TargetIP, m.Network.DataPlane.TargetPort))
	}

	// Profile
	if m.Profile.Path != "" {
		lines = append(lines, s.Label.Render("Profile: ")+filepath.Base(m.Profile.Path))
	}

	return lines
}
