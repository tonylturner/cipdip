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
	SubView     int // 0 = main, 1 = action config, 2 = file browser

	// Replay options (when action is replay)
	ReplayTargetIP string
	ReplayRewrite  bool
	ReplayTiming   bool
	ReplayAppOnly  bool

	// File browser state
	BrowserPath    string       // Current directory
	BrowserEntries []FileEntry  // Files/dirs in current directory
	BrowserCursor  int          // Selected entry

	// UI state
	focusIndex int
	Status     string
	Running    bool
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
	{"1", "Summary", "Packet counts, endpoints, timing"},
	{"2", "Report", "Detailed CIP request/response analysis"},
	{"3", "Coverage", "Which CIP classes/services are present"},
	{"4", "Replay", "Send packets to a target device"},
	{"5", "Rewrite", "Modify IPs/MACs and save new capture"},
	{"6", "Dump", "Hex dump of specific packets"},
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
	default:
		return m.updateMain(msg)
	}
}

func (m *PCAPScreenModel) updateMain(msg tea.KeyMsg) (*PCAPScreenModel, tea.Cmd) {
	switch msg.String() {
	case "b":
		// Open file browser
		m.openFileBrowser()
		return m, nil
	case "1", "2", "3", "4", "5", "6":
		idx := int(msg.String()[0] - '1')
		if idx >= 0 && idx < len(pcapActions) {
			m.ActionIndex = idx
			if m.FilePath != "" {
				// Go to action config for replay, otherwise run directly
				if idx == 3 { // Replay
					m.SubView = 1
					m.focusIndex = pcapFieldReplayIP
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
				// Select file
				m.FilePath = entry.Path
				m.updateFileInfo()
				m.SubView = 0
				m.Status = fmt.Sprintf("Selected: %s", entry.Name)
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
	if m.FilePath == "" {
		m.Status = "File path is required"
		return m, nil
	}

	// For replay, require target IP
	if m.ActionIndex == 3 && m.ReplayTargetIP == "" {
		m.Status = "Target IP is required for replay"
		return m, nil
	}

	m.Running = true
	m.Status = "Running..."

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
	if m.FilePath == "" {
		return nil
	}

	var args []string
	switch m.ActionIndex {
	case 0: // Summary
		args = []string{"cipdip", "pcap-summary", "--input", m.FilePath}
	case 1: // Report
		args = []string{"cipdip", "pcap-report", "--input", m.FilePath}
	case 2: // Coverage
		args = []string{"cipdip", "pcap-coverage", "--input", m.FilePath}
	case 3: // Replay
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
	case 4: // Rewrite
		args = []string{"cipdip", "pcap-rewrite", "--input", m.FilePath}
	case 5: // Dump
		args = []string{"cipdip", "pcap-dump", "--input", m.FilePath}
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
	default:
		return m.viewMain()
	}
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
	default:
		return "b: browse files    1-6: select action    y: copy command    m: menu"
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
