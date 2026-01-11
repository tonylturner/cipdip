package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// PCAPScreenModel handles the PCAP tools screen.
type PCAPScreenModel struct {
	state *AppState

	// Selected file
	FilePath string
	FileSize string

	// Action selection
	ActionIndex int // Which action is selected
	SubView     int // 0 = main, 1 = action config, 2 = file browser, 3 = completed

	// Replay options (when action is replay)
	ReplayTargetIP string
	ReplayRewrite  bool
	ReplayTiming   bool
	ReplayAppOnly  bool

	// Dump options (when action is dump)
	DumpService string // Service code to filter (e.g., "0x51")

	// Diff options (when action is diff)
	DiffBaseline    string  // Baseline PCAP file
	DiffCompare     string  // Compare PCAP file
	DiffExpectedRPI float64 // Expected RPI in ms
	DiffSkipTiming  bool    // Skip timing analysis
	DiffSkipRPI     bool    // Skip RPI analysis
	DiffFocusField  int     // 0=baseline, 1=compare, 2=rpi

	// File browser state
	BrowserPath       string      // Current directory
	BrowserEntries    []FileEntry // Files/dirs in current directory
	BrowserCursor     int         // Selected entry
	BrowserSelectMode string      // "single", "baseline", "compare" - which file we're selecting

	// UI state
	focusIndex    int
	Status        string
	Running       bool
	Completed     bool   // True after action finishes
	Output        string // Captured stdout from the action
	RunDir        string // Directory where artifacts were saved
	ReportPath    string // Path to generated report file (for actions 2, 3)
	ReportContent string // Content of generated report

	// Viewer state (subview 5)
	ViewerLines  []string // Lines of content being viewed
	ViewerScroll int      // Current scroll position
	ViewerTitle  string   // Title for the viewer
}

// FileEntry represents a file or directory in the browser.
type FileEntry struct {
	Name    string
	Path    string
	IsDir   bool
	Size    int64
	ModTime time.Time
}

var pcapActions = []struct {
	Key  string
	Name string
	Desc string
}{
	{"1", "Summary", "Packet counts, endpoints, timing (single file)"},
	{"2", "Report", "Multi-file summary report (uses directory)"},
	{"3", "Coverage", "CIP service coverage report (uses directory)"},
	{"4", "Replay", "Send packets to a target device"},
	{"5", "Rewrite", "Modify IPs/MACs and save new capture"},
	{"6", "Dump", "Hex dump of CIP packets by service code"},
	{"7", "Diff", "Compare two PCAPs for service/timing differences"},
}

const (
	pcapFieldFile = iota
	pcapFieldAction
	pcapFieldReplayIP
	pcapFieldReplayOpts
	pcapFieldCount
)

// NewPCAPScreenModel creates a new PCAP screen model.
func NewPCAPScreenModel(state *AppState) *PCAPScreenModel {
	return &PCAPScreenModel{
		state: state,
	}
}

// Update handles input for the PCAP screen.
func (m *PCAPScreenModel) Update(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch m.SubView {
	case 1:
		return m.updateActionConfig(msg)
	case 2:
		return m.updateFileBrowser(msg)
	case 3:
		return m.updateCompleted(msg)
	case 4:
		return m.updateDumpConfig(msg)
	case 5:
		return m.updateViewer(msg)
	case 6:
		return m.updateDiffConfig(msg)
	default:
		return m.updateMain(msg)
	}
}

func (m *PCAPScreenModel) updateViewer(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	maxVisible := 20 // Lines visible at once
	maxScroll := len(m.ViewerLines) - maxVisible
	if maxScroll < 0 {
		maxScroll = 0
	}

	switch msg.String() {
	case "q", "esc":
		m.SubView = 3 // Return to completed view
		m.ViewerLines = nil
		m.ViewerScroll = 0
	case "up", "k":
		if m.ViewerScroll > 0 {
			m.ViewerScroll--
		}
	case "down", "j":
		if m.ViewerScroll < maxScroll {
			m.ViewerScroll++
		}
	case "pgup", "b", "ctrl+u":
		m.ViewerScroll -= maxVisible
		if m.ViewerScroll < 0 {
			m.ViewerScroll = 0
		}
	case "pgdown", " ", "ctrl+d":
		m.ViewerScroll += maxVisible
		if m.ViewerScroll > maxScroll {
			m.ViewerScroll = maxScroll
		}
	case "g", "home":
		m.ViewerScroll = 0
	case "G", "end":
		m.ViewerScroll = maxScroll
	}
	return m, nil
}

func (m *PCAPScreenModel) updateDumpConfig(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.SubView = 0
	case "enter":
		if m.DumpService != "" {
			return m.runAction()
		} else {
			m.Status = "Service code is required (e.g., 0x51)"
		}
	case "y":
		cmd := m.buildCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "backspace":
		if len(m.DumpService) > 0 {
			m.DumpService = m.DumpService[:len(m.DumpService)-1]
		}
	default:
		if len(msg.String()) == 1 {
			ch := msg.String()
			// Allow hex characters for service code
			if strings.ContainsAny(ch, "0123456789abcdefABCDEFxX") {
				m.DumpService += ch
			}
		}
	}
	return m, nil
}

func (m *PCAPScreenModel) updateDiffConfig(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.SubView = 0
	case "enter":
		if m.DiffBaseline != "" && m.DiffCompare != "" {
			return m.runAction()
		} else {
			m.Status = "Both baseline and compare files are required"
		}
	case "tab", "down", "j":
		m.DiffFocusField = (m.DiffFocusField + 1) % 5 // 0=baseline, 1=compare, 2=rpi, 3=skip-timing, 4=skip-rpi
	case "shift+tab", "up", "k":
		m.DiffFocusField--
		if m.DiffFocusField < 0 {
			m.DiffFocusField = 4
		}
	case "b":
		// Open file browser for current field
		if m.DiffFocusField == 0 {
			m.BrowserSelectMode = "baseline"
			m.openFileBrowser()
		} else if m.DiffFocusField == 1 {
			m.BrowserSelectMode = "compare"
			m.openFileBrowser()
		}
	case " ":
		// Toggle checkboxes
		if m.DiffFocusField == 3 {
			m.DiffSkipTiming = !m.DiffSkipTiming
		} else if m.DiffFocusField == 4 {
			m.DiffSkipRPI = !m.DiffSkipRPI
		}
	case "y":
		cmd := m.buildCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "+", "=":
		if m.DiffFocusField == 2 {
			m.DiffExpectedRPI += 1.0
		}
	case "-", "_":
		if m.DiffFocusField == 2 && m.DiffExpectedRPI > 1.0 {
			m.DiffExpectedRPI -= 1.0
		}
	}
	return m, nil
}

func (m *PCAPScreenModel) updateCompleted(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Return to main view
		m.Completed = false
		m.SubView = 0
		m.Output = ""
		m.ReportContent = ""
		m.Status = ""
	case "enter", "v", "o":
		// Open full content in scrollable viewer
		content := m.Output
		title := "Output"
		if m.ReportContent != "" {
			content = m.ReportContent
			title = "Report"
		}
		if content != "" {
			m.ViewerLines = strings.Split(content, "\n")
			m.ViewerScroll = 0
			m.ViewerTitle = title
			m.SubView = 5
		}
	case "r":
		// Re-run same action
		m.Completed = false
		m.SubView = 0
		m.ReportContent = ""
		return m.runAction()
	}
	return m, nil
}

func (m *PCAPScreenModel) updateMain(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "b":
		// Open file browser
		m.openFileBrowser()
		return m, nil
	case "1", "2", "3", "4", "5", "6", "7":
		idx := int(msg.String()[0] - '1')
		if idx >= 0 && idx < len(pcapActions) {
			m.ActionIndex = idx
			if idx == 6 { // Diff - doesn't need FilePath, has its own file selection
				m.SubView = 6
				m.DiffFocusField = 0
				if m.DiffExpectedRPI == 0 {
					m.DiffExpectedRPI = 20.0
				}
				return m, nil
			}
			if m.FilePath != "" {
				// Go to action config for replay and dump, otherwise run directly
				if idx == 3 { // Replay
					m.SubView = 1
					m.focusIndex = pcapFieldReplayIP
				} else if idx == 5 { // Dump - needs service code
					m.SubView = 4 // Dump config view
					m.focusIndex = 0
				} else {
					return m.runAction()
				}
			} else {
				m.Status = "Select a file first"
			}
		}
	case "enter":
		if m.FilePath != "" && m.ActionIndex >= 0 {
			if m.ActionIndex == 3 { // Replay needs config
				m.SubView = 1
				m.focusIndex = pcapFieldReplayIP
			} else if m.ActionIndex == 5 { // Dump needs service code
				m.SubView = 4
				m.focusIndex = 0
			} else {
				return m.runAction()
			}
		}
	case "y":
		if m.FilePath != "" {
			cmd := m.buildCommand()
			if err := copyToClipboard(cmd); err != nil {
				m.Status = fmt.Sprintf("Copy failed: %v", err)
			} else {
				m.Status = "Command copied to clipboard"
			}
		}
	case "up", "k":
		if m.ActionIndex > 0 {
			m.ActionIndex--
		}
	case "down", "j":
		if m.ActionIndex < len(pcapActions)-1 {
			m.ActionIndex++
		}
	case "backspace":
		if len(m.FilePath) > 0 {
			m.FilePath = m.FilePath[:len(m.FilePath)-1]
			m.updateFileInfo()
		}
	default:
		// Allow typing file path
		if len(msg.String()) == 1 {
			m.FilePath += msg.String()
			m.updateFileInfo()
		}
	}
	return m, nil
}

func (m *PCAPScreenModel) updateActionConfig(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.SubView = 0
	case "tab", "down", "j":
		m.focusIndex = (m.focusIndex + 1) % 4
		if m.focusIndex < pcapFieldReplayIP {
			m.focusIndex = pcapFieldReplayIP
		}
	case "shift+tab", "up", "k":
		m.focusIndex--
		if m.focusIndex < pcapFieldReplayIP {
			m.focusIndex = pcapFieldReplayOpts
		}
	case "enter":
		if m.ReplayTargetIP != "" {
			return m.runAction()
		}
	case " ":
		// Toggle checkboxes
		if m.focusIndex == pcapFieldReplayOpts {
			// Cycle through options - simplified
			m.ReplayRewrite = !m.ReplayRewrite
		}
	case "1":
		m.ReplayRewrite = !m.ReplayRewrite
	case "2":
		m.ReplayTiming = !m.ReplayTiming
	case "3":
		m.ReplayAppOnly = !m.ReplayAppOnly
	case "y":
		cmd := m.buildCommand()
		if err := copyToClipboard(cmd); err != nil {
			m.Status = fmt.Sprintf("Copy failed: %v", err)
		} else {
			m.Status = "Command copied to clipboard"
		}
	case "backspace":
		if m.focusIndex == pcapFieldReplayIP && len(m.ReplayTargetIP) > 0 {
			m.ReplayTargetIP = m.ReplayTargetIP[:len(m.ReplayTargetIP)-1]
		}
	default:
		if m.focusIndex == pcapFieldReplayIP && len(msg.String()) == 1 {
			if strings.ContainsAny(msg.String(), "0123456789.") {
				m.ReplayTargetIP += msg.String()
			}
		}
	}
	return m, nil
}

func (m *PCAPScreenModel) updateFileInfo() {
	if info, err := os.Stat(m.FilePath); err == nil {
		m.FileSize = formatFileSize(info.Size())
	} else {
		m.FileSize = ""
	}
}

// File browser methods

func (m *PCAPScreenModel) openFileBrowser() {
	// Start in workspace pcaps dir, or current dir
	startDir := filepath.Join(m.state.WorkspaceRoot, "pcaps")
	if _, err := os.Stat(startDir); err != nil {
		startDir, _ = os.Getwd()
	}
	m.BrowserPath = startDir
	m.BrowserCursor = 0
	m.loadDirectory()
	m.SubView = 2
}

func (m *PCAPScreenModel) loadDirectory() {
	entries, err := os.ReadDir(m.BrowserPath)
	if err != nil {
		m.Status = fmt.Sprintf("Error reading directory: %v", err)
		return
	}

	m.BrowserEntries = make([]FileEntry, 0)

	// Add parent directory entry if not at root
	if m.BrowserPath != "/" {
		m.BrowserEntries = append(m.BrowserEntries, FileEntry{
			Name:  "..",
			Path:  filepath.Dir(m.BrowserPath),
			IsDir: true,
		})
	}

	// Add directories first, then pcap files
	var dirs, files []FileEntry
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fe := FileEntry{
			Name:    entry.Name(),
			Path:    filepath.Join(m.BrowserPath, entry.Name()),
			IsDir:   entry.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}

		if entry.IsDir() {
			dirs = append(dirs, fe)
		} else {
			// Only show pcap files
			lower := strings.ToLower(entry.Name())
			if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
				files = append(files, fe)
			}
		}
	}

	// Sort directories and files by name
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name < dirs[j].Name })
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	m.BrowserEntries = append(m.BrowserEntries, dirs...)
	m.BrowserEntries = append(m.BrowserEntries, files...)

	if m.BrowserCursor >= len(m.BrowserEntries) {
		m.BrowserCursor = len(m.BrowserEntries) - 1
	}
	if m.BrowserCursor < 0 {
		m.BrowserCursor = 0
	}
}

func (m *PCAPScreenModel) updateFileBrowser(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.SubView = 0
	case "up", "k":
		if m.BrowserCursor > 0 {
			m.BrowserCursor--
		}
	case "down", "j":
		if m.BrowserCursor < len(m.BrowserEntries)-1 {
			m.BrowserCursor++
		}
	case "enter":
		if len(m.BrowserEntries) > 0 {
			entry := m.BrowserEntries[m.BrowserCursor]
			if entry.IsDir {
				// Navigate into directory
				m.BrowserPath = entry.Path
				m.BrowserCursor = 0
				m.loadDirectory()
			} else {
				// Select file based on mode
				switch m.BrowserSelectMode {
				case "baseline":
					m.DiffBaseline = entry.Path
					m.SubView = 6 // Return to diff config
					m.Status = fmt.Sprintf("Baseline: %s", entry.Name)
				case "compare":
					m.DiffCompare = entry.Path
					m.SubView = 6 // Return to diff config
					m.Status = fmt.Sprintf("Compare: %s", entry.Name)
				default:
					m.FilePath = entry.Path
					m.updateFileInfo()
					m.SubView = 0
					m.Status = fmt.Sprintf("Selected: %s", entry.Name)
				}
				m.BrowserSelectMode = "" // Reset mode
			}
		}
	case "h", "left":
		// Go to parent directory
		if m.BrowserPath != "/" {
			m.BrowserPath = filepath.Dir(m.BrowserPath)
			m.BrowserCursor = 0
			m.loadDirectory()
		}
	case "l", "right":
		// Enter directory if selected
		if len(m.BrowserEntries) > 0 {
			entry := m.BrowserEntries[m.BrowserCursor]
			if entry.IsDir {
				m.BrowserPath = entry.Path
				m.BrowserCursor = 0
				m.loadDirectory()
			}
		}
	case "g":
		// Go to top
		m.BrowserCursor = 0
	case "G":
		// Go to bottom
		m.BrowserCursor = len(m.BrowserEntries) - 1
	}
	return m, nil
}

func (m *PCAPScreenModel) runAction() (*PCAPScreenModel, tea.Cmd) {
	// Diff action has different requirements
	if m.ActionIndex == 6 {
		if m.DiffBaseline == "" || m.DiffCompare == "" {
			m.Status = "Both baseline and compare files are required"
			return m, nil
		}
	} else if m.FilePath == "" {
		m.Status = "File path is required"
		return m, nil
	}

	// For replay, require target IP
	if m.ActionIndex == 3 && m.ReplayTargetIP == "" {
		m.Status = "Target IP is required for replay"
		return m, nil
	}

	// For dump, require service code
	if m.ActionIndex == 5 && m.DumpService == "" {
		m.Status = "Service code is required for dump"
		return m, nil
	}

	m.Running = true
	m.Status = "Running..."

	// Track report path for actions that generate reports
	m.ReportPath = ""
	if m.ActionIndex == 1 { // Report
		m.ReportPath = filepath.Join(m.state.WorkspaceRoot, "reports", "pcap_report.md")
	} else if m.ActionIndex == 2 { // Coverage
		m.ReportPath = filepath.Join(m.state.WorkspaceRoot, "reports", "pcap_coverage.md")
	}

	// Build the command
	args := m.buildCommandArgs()
	command := CommandSpec{Args: args}

	// Create run directory
	actionName := pcapActions[m.ActionIndex].Name
	runName := fmt.Sprintf("pcap_%s", strings.ToLower(actionName))
	runDir, err := CreateRunDir(m.state.WorkspaceRoot, runName)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to create run directory: %v", err)
		m.Running = false
		return m, nil
	}

	// Return a command that executes the pcap action
	startTime := time.Now()
	ctx := context.Background()
	return m, func() tea.Msg {
		stdout, exitCode, runErr := ExecuteCommand(ctx, command)

		// Write artifacts
		resolved := map[string]interface{}{
			"action": actionName,
			"file":   m.FilePath,
		}
		if m.ActionIndex == 3 {
			resolved["target_ip"] = m.ReplayTargetIP
		}
		status := "success"
		if runErr != nil {
			status = "failed"
		}
		summary := RunSummary{
			Status:     status,
			Command:    args,
			StartedAt:  startTime.UTC().Format(time.RFC3339),
			FinishedAt: time.Now().UTC().Format(time.RFC3339),
			ExitCode:   exitCode,
		}
		_ = WriteRunArtifacts(runDir, resolved, args, stdout, summary)

		return pcapResultMsg{
			RunDir:   runDir,
			ExitCode: exitCode,
			Stdout:   stdout,
			Err:      runErr,
		}
	}
}

// pcapResultMsg is sent when a PCAP action completes.
type pcapResultMsg struct {
	RunDir   string
	ExitCode int
	Stdout   string
	Err      error
}

func (m *PCAPScreenModel) buildCommandArgs() []string {
	// Diff action uses DiffBaseline/DiffCompare, not FilePath
	if m.ActionIndex != 6 && m.FilePath == "" {
		return nil
	}

	var args []string
	switch m.ActionIndex {
	case 0: // Summary - uses --input for single file
		args = []string{"cipdip", "pcap-summary", "--input", m.FilePath}
	case 1: // Report - uses --pcap-dir for directory
		pcapDir := filepath.Dir(m.FilePath)
		outputPath := filepath.Join(m.state.WorkspaceRoot, "reports", "pcap_report.md")
		args = []string{"cipdip", "pcap-report", "--pcap-dir", pcapDir, "--output", outputPath}
	case 2: // Coverage - uses --pcap-dir for directory
		pcapDir := filepath.Dir(m.FilePath)
		outputPath := filepath.Join(m.state.WorkspaceRoot, "reports", "pcap_coverage.md")
		args = []string{"cipdip", "pcap-coverage", "--pcap-dir", pcapDir, "--output", outputPath}
	case 3: // Replay - uses --input for single file
		args = []string{"cipdip", "pcap-replay", "--input", m.FilePath}
		if m.ReplayTargetIP != "" {
			args = append(args, "--server-ip", m.ReplayTargetIP)
		}
		if m.ReplayRewrite {
			args = append(args, "--rewrite")
		}
		if m.ReplayTiming {
			args = append(args, "--realtime")
		}
		if m.ReplayAppOnly {
			args = append(args, "--mode", "app")
		}
	case 4: // Rewrite - uses --input and --output
		outputPath := strings.TrimSuffix(m.FilePath, filepath.Ext(m.FilePath)) + "_rewritten.pcap"
		args = []string{"cipdip", "pcap-rewrite", "--input", m.FilePath, "--output", outputPath}
	case 5: // Dump - uses --input and --service
		args = []string{"cipdip", "pcap-dump", "--input", m.FilePath}
		if m.DumpService != "" {
			args = append(args, "--service", m.DumpService)
		}
	case 6: // Diff - uses --baseline and --compare
		args = []string{"cipdip", "pcap-diff"}
		if m.DiffBaseline != "" {
			args = append(args, "--baseline", m.DiffBaseline)
		}
		if m.DiffCompare != "" {
			args = append(args, "--compare", m.DiffCompare)
		}
		if m.DiffExpectedRPI > 0 && m.DiffExpectedRPI != 20.0 {
			args = append(args, "--expected-rpi", fmt.Sprintf("%.1f", m.DiffExpectedRPI))
		}
		if m.DiffSkipTiming {
			args = append(args, "--skip-timing")
		}
		if m.DiffSkipRPI {
			args = append(args, "--skip-rpi")
		}
	}
	return args
}

func (m *PCAPScreenModel) buildCommand() string {
	args := m.buildCommandArgs()
	if len(args) == 0 {
		return ""
	}
	return strings.Join(args, " ")
}

// View renders the PCAP screen.
func (m *PCAPScreenModel) View() string {
	switch m.SubView {
	case 1:
		return m.viewReplayConfig()
	case 2:
		return m.viewFileBrowser()
	case 3:
		return m.viewCompleted()
	case 4:
		return m.viewDumpConfig()
	case 5:
		return m.viewViewer()
	case 6:
		return m.viewDiffConfig()
	default:
		return m.viewMain()
	}
}

func (m *PCAPScreenModel) viewViewer() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render(fmt.Sprintf("PCAP > %s", m.ViewerTitle)))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 70))
	b.WriteString("\n")

	// Content with scroll
	maxVisible := 20
	totalLines := len(m.ViewerLines)
	endIdx := m.ViewerScroll + maxVisible
	if endIdx > totalLines {
		endIdx = totalLines
	}

	// Show scroll indicator
	if m.ViewerScroll > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑ %d lines above\n", m.ViewerScroll)))
	} else {
		b.WriteString("\n")
	}

	// Show visible lines
	for i := m.ViewerScroll; i < endIdx; i++ {
		line := m.ViewerLines[i]
		// Don't truncate in viewer - show full width
		if len(line) > 68 {
			line = line[:68]
		}
		b.WriteString(fmt.Sprintf("%s\n", line))
	}

	// Pad to consistent height
	displayed := endIdx - m.ViewerScroll
	for i := displayed; i < maxVisible; i++ {
		b.WriteString("\n")
	}

	// Show scroll indicator at bottom
	remaining := totalLines - endIdx
	if remaining > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↓ %d lines below", remaining)))
	}
	b.WriteString("\n")

	// Progress indicator
	b.WriteString(strings.Repeat("─", 70))
	b.WriteString("\n")
	pct := 0
	if totalLines > 0 {
		pct = (m.ViewerScroll + maxVisible) * 100 / totalLines
		if pct > 100 {
			pct = 100
		}
	}
	b.WriteString(dimStyle.Render(fmt.Sprintf("Line %d-%d of %d (%d%%)", m.ViewerScroll+1, endIdx, totalLines, pct)))

	return b.String()
}

func (m *PCAPScreenModel) viewDumpConfig() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("PCAP > Dump"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// File info
	b.WriteString(fmt.Sprintf("File: %s\n\n", filepath.Base(m.FilePath)))

	// Service code input
	serviceValue := m.DumpService
	if serviceValue == "" {
		serviceValue = "0x__"
	}
	b.WriteString(selectedStyle.Render("Service code: " + serviceValue + "█"))
	b.WriteString("\n\n")

	// Help text
	b.WriteString(dimStyle.Render("Enter a CIP service code in hex format (e.g., 0x51, 0x0E)"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Common services: 0x0E (Get Attribute Single), 0x10 (Set Attribute Single)"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("                0x52 (Unconnected Send), 0x54 (Forward Open)"))
	b.WriteString("\n")

	// Command preview
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")
	b.WriteString("Command preview:\n")
	cmd := m.buildCommand()
	if m.DumpService == "" {
		cmd = strings.Replace(cmd, "--service ", "--service ???", 1)
	}
	b.WriteString(dimStyle.Render(cmd))
	b.WriteString("\n")

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *PCAPScreenModel) viewDiffConfig() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("PCAP > Diff"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Baseline file
	baselineLabel := "Baseline: "
	baselineValue := m.DiffBaseline
	if baselineValue == "" {
		baselineValue = "[press 'b' to browse]"
	} else {
		baselineValue = filepath.Base(baselineValue)
	}
	if m.DiffFocusField == 0 {
		b.WriteString(selectedStyle.Render(baselineLabel + baselineValue))
	} else {
		b.WriteString(baselineLabel + baselineValue)
	}
	b.WriteString("\n\n")

	// Compare file
	compareLabel := "Compare:  "
	compareValue := m.DiffCompare
	if compareValue == "" {
		compareValue = "[press 'b' to browse]"
	} else {
		compareValue = filepath.Base(compareValue)
	}
	if m.DiffFocusField == 1 {
		b.WriteString(selectedStyle.Render(compareLabel + compareValue))
	} else {
		b.WriteString(compareLabel + compareValue)
	}
	b.WriteString("\n\n")

	// Expected RPI
	rpiLabel := fmt.Sprintf("Expected RPI: %.1f ms", m.DiffExpectedRPI)
	if m.DiffFocusField == 2 {
		b.WriteString(selectedStyle.Render(rpiLabel + " (+/- to adjust)"))
	} else {
		b.WriteString(rpiLabel)
	}
	b.WriteString("\n\n")

	// Skip options
	skipTimingCheck := "[ ]"
	if m.DiffSkipTiming {
		skipTimingCheck = "[x]"
	}
	skipTimingLine := fmt.Sprintf("%s Skip timing analysis", skipTimingCheck)
	if m.DiffFocusField == 3 {
		b.WriteString(selectedStyle.Render(skipTimingLine))
	} else {
		b.WriteString(skipTimingLine)
	}
	b.WriteString("\n")

	skipRPICheck := "[ ]"
	if m.DiffSkipRPI {
		skipRPICheck = "[x]"
	}
	skipRPILine := fmt.Sprintf("%s Skip RPI/jitter analysis", skipRPICheck)
	if m.DiffFocusField == 4 {
		b.WriteString(selectedStyle.Render(skipRPILine))
	} else {
		b.WriteString(skipRPILine)
	}
	b.WriteString("\n")

	// Command preview
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")
	b.WriteString("Command preview:\n")
	cmd := m.buildCommand()
	b.WriteString(dimStyle.Render(cmd))
	b.WriteString("\n")

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *PCAPScreenModel) viewCompleted() string {
	var b strings.Builder

	// Header with status
	actionName := "PCAP"
	if m.ActionIndex >= 0 && m.ActionIndex < len(pcapActions) {
		actionName = pcapActions[m.ActionIndex].Name
	}
	b.WriteString(headerStyle.Render(fmt.Sprintf("PCAP > %s", actionName)))
	b.WriteString("                                    ")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render("[FAILED]"))
	} else {
		b.WriteString(successStyle.Render("[DONE]"))
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// File info
	b.WriteString(fmt.Sprintf("File: %s\n", filepath.Base(m.FilePath)))

	// Status message
	b.WriteString("\n")
	if strings.HasPrefix(m.Status, "FAILED") {
		b.WriteString(errorStyle.Render(m.Status))
	} else {
		b.WriteString(successStyle.Render(m.Status))
	}
	b.WriteString("\n")

	// Content section - show report if available, otherwise stdout
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")

	content := m.Output
	contentLabel := "Output"
	if m.ReportContent != "" {
		content = m.ReportContent
		contentLabel = "Report"
	}

	b.WriteString(fmt.Sprintf("%s:\n", contentLabel))
	if content == "" {
		b.WriteString(dimStyle.Render("  (no output captured)"))
		b.WriteString("\n")
	} else {
		// Show content lines (scroll if needed)
		lines := strings.Split(strings.TrimSpace(content), "\n")
		maxLines := 18
		startIdx := 0
		if len(lines) > maxLines {
			startIdx = len(lines) - maxLines
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ... (%d lines omitted, press 'o' to view full)\n", startIdx)))
		}
		for _, line := range lines[startIdx:] {
			if len(line) > 70 {
				line = line[:67] + "..."
			}
			b.WriteString(fmt.Sprintf("  %s\n", line))
		}
	}

	return borderStyle.Render(b.String())
}

func (m *PCAPScreenModel) viewFileBrowser() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("PCAP > Browse Files"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Current path
	b.WriteString(dimStyle.Render("Path: "))
	b.WriteString(m.BrowserPath)
	b.WriteString("\n\n")

	// File list
	if len(m.BrowserEntries) == 0 {
		b.WriteString(dimStyle.Render("  (no pcap files in this directory)"))
		b.WriteString("\n")
	} else {
		// Show max 15 entries with scrolling
		startIdx := 0
		maxVisible := 15
		if m.BrowserCursor >= maxVisible {
			startIdx = m.BrowserCursor - maxVisible + 1
		}
		endIdx := startIdx + maxVisible
		if endIdx > len(m.BrowserEntries) {
			endIdx = len(m.BrowserEntries)
		}

		for i := startIdx; i < endIdx; i++ {
			entry := m.BrowserEntries[i]
			prefix := "  "
			if i == m.BrowserCursor {
				prefix = "> "
			}

			// Format entry
			icon := " "
			if entry.IsDir {
				icon = "/"
			}
			name := entry.Name + icon

			var line string
			if entry.IsDir {
				line = fmt.Sprintf("%s%-40s", prefix, name)
			} else {
				size := formatFileSize(entry.Size)
				date := entry.ModTime.Format("2006-01-02 15:04")
				line = fmt.Sprintf("%s%-30s %8s  %s", prefix, name, size, date)
			}

			if i == m.BrowserCursor {
				b.WriteString(selectedStyle.Render(line))
			} else if entry.IsDir {
				b.WriteString(dimStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}

		// Show scroll indicator if needed
		if len(m.BrowserEntries) > maxVisible {
			b.WriteString(fmt.Sprintf("\n%s", dimStyle.Render(fmt.Sprintf("  ... %d of %d items", m.BrowserCursor+1, len(m.BrowserEntries)))))
		}
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *PCAPScreenModel) viewMain() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("PCAP TOOLS"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// File selection
	b.WriteString("File: ")
	if m.FilePath == "" {
		b.WriteString(dimStyle.Render("[select or type path]"))
	} else {
		b.WriteString(m.FilePath)
		if m.FileSize != "" {
			b.WriteString(fmt.Sprintf("  (%s)", m.FileSize))
		}
	}
	b.WriteString("                       [b]rowse\n")

	// Separator
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Actions
	if m.FilePath == "" {
		b.WriteString(dimStyle.Render("Actions (select file first):"))
	} else {
		b.WriteString("Actions:")
	}
	b.WriteString("\n\n")

	for i, action := range pcapActions {
		prefix := "  "
		if i == m.ActionIndex {
			prefix = "> "
		}
		line := fmt.Sprintf("%s[%s] %-12s %s", prefix, action.Key, action.Name, action.Desc)
		if i == m.ActionIndex {
			b.WriteString(selectedStyle.Render(line))
		} else if m.FilePath == "" {
			b.WriteString(dimStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	// Command preview
	if m.FilePath != "" {
		b.WriteString("\n")
		b.WriteString(strings.Repeat("─", 60))
		b.WriteString("\n\n")
		b.WriteString("Command preview:\n")
		b.WriteString(dimStyle.Render(m.buildCommand()))
		b.WriteString("\n")
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *PCAPScreenModel) viewReplayConfig() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("PCAP > Replay"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// File info
	b.WriteString(fmt.Sprintf("File: %s\n", m.FilePath))
	b.WriteString("\n")

	// Target IP
	ipValue := m.ReplayTargetIP
	if ipValue == "" {
		ipValue = "_____________"
	}
	if m.focusIndex == pcapFieldReplayIP {
		b.WriteString(selectedStyle.Render("Target IP: " + ipValue + "█"))
	} else {
		b.WriteString("Target IP: " + ipValue)
	}
	b.WriteString("\n\n")

	// Options
	b.WriteString("Options:\n")
	rewriteCheck := "[ ]"
	if m.ReplayRewrite {
		rewriteCheck = "[x]"
	}
	b.WriteString(fmt.Sprintf("  %s Rewrite IP/MAC addresses\n", rewriteCheck))

	timingCheck := "[ ]"
	if m.ReplayTiming {
		timingCheck = "[x]"
	}
	b.WriteString(fmt.Sprintf("  %s Preserve original timing\n", timingCheck))

	appCheck := "[ ]"
	if m.ReplayAppOnly {
		appCheck = "[x]"
	}
	b.WriteString(fmt.Sprintf("  %s Application-layer only (skip raw replay)\n", appCheck))

	// Command preview
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")
	b.WriteString("Command preview:\n")
	cmd := m.buildCommand()
	if m.ReplayTargetIP == "" {
		cmd = strings.Replace(cmd, "--server-ip ", "--server-ip ???", 1)
	}
	b.WriteString(dimStyle.Render(cmd))
	b.WriteString("\n")

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

// Footer returns the footer text for the PCAP screen.
func (m *PCAPScreenModel) Footer() string {
	switch m.SubView {
	case 1:
		return "Tab: next    1/2/3: toggle    Enter: run    y: copy command    Esc: back    m: menu"
	case 2:
		return "↑↓: navigate    Enter: select    ←/h: parent    Esc: cancel    m: menu"
	case 3:
		return "Enter/v: view full    r: re-run    Esc: back    m: menu"
	case 4:
		return "Enter: run    y: copy command    Esc: back    m: menu"
	case 5:
		return "↑↓/j/k: scroll    Space/b: page    g/G: top/bottom    q/Esc: back"
	case 6:
		return "Tab: next    b: browse    Space: toggle    +/-: RPI    Enter: run    y: copy    Esc: back"
	default:
		return "b: browse files    1-7: select action    y: copy command    m: menu"
	}
}

func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
