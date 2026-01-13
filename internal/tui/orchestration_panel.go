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
)

// OrchView represents the current sub-view of the orchestration panel.
type OrchView int

const (
	OrchViewController OrchView = iota
	OrchViewAgent
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
	orchMode    OrchMode
	runID       string
	bundlePath  string
	currentPhase string
	phaseError  string
	startTime   *time.Time

	// Config input
	focusedField int
	bundleDir    string
	timeout      string
	dryRun       bool
	verbose      bool

	// Agent status (for Agent view)
	agentInfo *AgentInfo

	// Run context
	runCtx    context.Context
	runCancel context.CancelFunc
}

// NewOrchestrationPanel creates a new orchestration panel.
func NewOrchestrationPanel(styles Styles) *OrchestrationPanel {
	p := &OrchestrationPanel{
		mode:      PanelIdle,
		styles:    styles,
		view:      OrchViewController,
		bundleDir: "runs",
		timeout:   "300",
		agents:    []AgentMapping{},
	}
	// Load agent info on creation
	p.refreshAgentInfo()
	return p
}

// Name implements Panel.
func (p *OrchestrationPanel) Name() string {
	return "Orchestration"
}

// Title returns the panel title for display.
func (p *OrchestrationPanel) Title() string {
	if p.view == OrchViewAgent {
		return "AGENT STATUS"
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
		p.mode = PanelIdle
		return p, nil

	case "tab":
		// Toggle between Controller and Agent views
		if p.view == OrchViewController {
			p.view = OrchViewAgent
			p.refreshAgentInfo()
		} else {
			p.view = OrchViewController
		}
		return p, nil
	}

	// Route to appropriate view handler
	if p.view == OrchViewAgent {
		return p.updateAgentView(msg)
	}
	return p.updateControllerView(msg)
}

func (p *OrchestrationPanel) updateControllerView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	switch p.mode {
	case PanelIdle:
		// Activate panel
		p.mode = PanelConfig
		return p, nil

	case PanelConfig:
		return p.handleConfigKey(key)

	case PanelRunning:
		// Only allow cancel during run
		if key == "x" || key == "ctrl+c" {
			if p.runCancel != nil {
				p.runCancel()
			}
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

func (p *OrchestrationPanel) updateAgentView(msg tea.KeyMsg) (Panel, tea.Cmd) {
	key := msg.String()

	switch key {
	case "r", "R":
		// Refresh agent info
		p.refreshAgentInfo()
	}

	return p, nil
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
	if p.view == OrchViewAgent {
		return p.renderAgentView(width, focused)
	}
	return p.renderControllerView(width, focused)
}

func (p *OrchestrationPanel) renderControllerView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	// Header with view tabs
	controllerTab := "Controller"
	agentTab := "Agent"
	if p.view == OrchViewController {
		controllerTab = s.Selected.Render("[Controller]")
		agentTab = s.Dim.Render(" Agent ")
	} else {
		controllerTab = s.Dim.Render(" Controller ")
		agentTab = s.Selected.Render("[Agent]")
	}
	b.WriteString(s.Header.Render("ORCHESTRATION") + "  " + controllerTab + " | " + agentTab + "\n\n")

	switch p.mode {
	case PanelIdle:
		b.WriteString(s.Dim.Render("Press any key to configure orchestration..."))

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

func (p *OrchestrationPanel) renderAgentView(width int, focused bool) string {
	var b strings.Builder
	s := p.styles

	// Header with view tabs
	controllerTab := s.Dim.Render(" Controller ")
	agentTab := s.Selected.Render("[Agent]")
	b.WriteString(s.Header.Render("ORCHESTRATION") + "  " + controllerTab + " | " + agentTab + "\n\n")

	if p.agentInfo == nil {
		b.WriteString(s.Dim.Render("Loading agent info..."))
		return b.String()
	}

	info := p.agentInfo

	// Version info
	b.WriteString(s.Header.Render("Local Agent Status") + "\n\n")
	b.WriteString(s.Label.Render("cipdip version:") + "  " + info.Version + "\n")
	b.WriteString(s.Label.Render("OS/Arch:") + "         " + info.OS + "/" + info.Arch + "\n")
	b.WriteString(s.Label.Render("Hostname:") + "        " + info.Hostname + "\n")

	// Workdir
	workdirStatus := s.Success.Render("✓ Writable")
	if !info.WorkdirOK {
		workdirStatus = s.Error.Render("✗ Not writable")
	}
	b.WriteString(s.Label.Render("Workdir:") + "         " + info.WorkdirPath + " " + workdirStatus + "\n")

	// PCAP capability
	pcapStatus := s.Error.Render("✗ Not available")
	if info.PcapCapable {
		pcapStatus = s.Success.Render("✓ Available (" + info.PcapMethod + ")")
	}
	b.WriteString(s.Label.Render("PCAP Capture:") + "    " + pcapStatus + "\n")

	// Network interfaces
	b.WriteString("\n" + s.Header.Render("Network Interfaces:") + "\n")
	if len(info.Interfaces) == 0 {
		b.WriteString(s.Dim.Render("  No interfaces found") + "\n")
	} else {
		for _, iface := range info.Interfaces {
			bindStatus := s.Success.Render("✓")
			if !iface.CanBind {
				bindStatus = s.Error.Render("✗")
			}
			addrs := strings.Join(iface.Addresses, ", ")
			b.WriteString(fmt.Sprintf("  %s %-8s %s\n", bindStatus, iface.Name+":", addrs))
		}
	}

	// Supported roles
	b.WriteString("\n" + s.Label.Render("Supported Roles:") + " " + strings.Join(info.SupportedRoles, ", ") + "\n")

	// Actions
	b.WriteString("\n" + s.Dim.Render("[R] Refresh  [Tab] Controller View") + "\n")

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
