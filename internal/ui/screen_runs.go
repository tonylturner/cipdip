package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// RunsScreenModel handles the run history screen.
type RunsScreenModel struct {
	state *AppState

	// Filter
	FilterType string // "all", "client", "server", "pcap"

	// Navigation
	cursor         int
	showDetail     bool
	detailIdx      int
	detailRun      *RunArtifacts
	confirmDelete  bool
	artifactCursor int // For selecting which artifact to open

	// UI state
	Status string
}

var runFilterTypes = []string{"all", "client", "server", "pcap"}

// NewRunsScreenModel creates a new runs screen model.
func NewRunsScreenModel(state *AppState) *RunsScreenModel {
	return &RunsScreenModel{
		state:      state,
		FilterType: "all",
	}
}

// Update handles input for the runs screen.
func (m *RunsScreenModel) Update(msg tea.KeyMsg) (*RunsScreenModel, tea.Cmd) {
	if m.showDetail {
		return m.updateDetail(msg)
	}
	return m.updateList(msg)
}

func (m *RunsScreenModel) updateList(msg tea.KeyMsg) (*RunsScreenModel, tea.Cmd) {
	filtered := m.filteredRuns()

	// Handle delete confirmation
	if m.confirmDelete {
		switch msg.String() {
		case "y", "Y":
			// Confirm delete
			if m.cursor < len(filtered) {
				return m.deleteRun(filtered[m.cursor])
			}
			m.confirmDelete = false
		case "n", "N", "esc":
			m.confirmDelete = false
			m.Status = ""
		}
		return m, nil
	}

	switch msg.String() {
	case "tab":
		// Cycle filter type
		for i, t := range runFilterTypes {
			if t == m.FilterType {
				m.FilterType = runFilterTypes[(i+1)%len(runFilterTypes)]
				m.cursor = 0
				break
			}
		}
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(filtered)-1 {
			m.cursor++
		}
	case "enter":
		if len(filtered) > 0 && m.cursor < len(filtered) {
			m.showDetail = true
			m.detailIdx = m.cursor
			m.artifactCursor = 0
			m.loadRunDetail(filtered[m.cursor])
		}
	case "d":
		// Delete run - show confirmation
		if len(filtered) > 0 && m.cursor < len(filtered) {
			m.confirmDelete = true
			m.Status = fmt.Sprintf("Delete %s? (y/n)", filtered[m.cursor])
		}
	}
	return m, nil
}

func (m *RunsScreenModel) updateDetail(msg tea.KeyMsg) (*RunsScreenModel, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		m.showDetail = false
		m.detailRun = nil
	case "o":
		// Open artifact in $EDITOR
		return m.openArtifact()
	case "r":
		// Re-run command
		return m.rerunCommand()
	case "y":
		// Copy command
		if m.detailRun != nil && m.detailRun.Command != "" {
			if err := copyToClipboard(m.detailRun.Command); err != nil {
				m.Status = fmt.Sprintf("Copy failed: %v", err)
			} else {
				m.Status = "Command copied to clipboard"
			}
		}
	case "1":
		m.artifactCursor = 0
	case "2":
		m.artifactCursor = 1
	case "3":
		m.artifactCursor = 2
	case "4":
		m.artifactCursor = 3
	}
	return m, nil
}

func (m *RunsScreenModel) openArtifact() (*RunsScreenModel, tea.Cmd) {
	if m.detailRun == nil {
		m.Status = "No run loaded"
		return m, nil
	}

	// Determine which artifact to open
	artifacts := m.getArtifactPaths()
	if len(artifacts) == 0 {
		m.Status = "No artifacts available"
		return m, nil
	}

	idx := m.artifactCursor
	if idx >= len(artifacts) {
		idx = 0
	}
	artifactPath := artifacts[idx]

	// Get editor from environment
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "less" // Default to less for viewing
	}

	// Open in editor
	cmd := exec.Command(editor, artifactPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		m.Status = fmt.Sprintf("Failed to open: %v", err)
		return m, nil
	}

	m.Status = fmt.Sprintf("Opened %s in %s", filepath.Base(artifactPath), editor)
	return m, nil
}

func (m *RunsScreenModel) getArtifactPaths() []string {
	if m.detailRun == nil {
		return nil
	}

	var paths []string
	if m.detailRun.Command != "" {
		paths = append(paths, filepath.Join(m.detailRun.RunDir, "command.txt"))
	}
	if m.detailRun.Stdout != "" {
		paths = append(paths, filepath.Join(m.detailRun.RunDir, "stdout.log"))
	}
	if m.detailRun.Resolved != "" {
		paths = append(paths, filepath.Join(m.detailRun.RunDir, "resolved.yaml"))
	}
	if m.detailRun.Summary != nil {
		paths = append(paths, filepath.Join(m.detailRun.RunDir, "summary.json"))
	}
	return paths
}

func (m *RunsScreenModel) rerunCommand() (*RunsScreenModel, tea.Cmd) {
	if m.detailRun == nil || m.detailRun.Summary == nil || len(m.detailRun.Summary.Command) == 0 {
		m.Status = "No command available to re-run"
		return m, nil
	}

	// Build command from saved args
	args := m.detailRun.Summary.Command
	command := CommandSpec{Args: args}

	// Create new run directory
	runName := "rerun"
	if len(args) >= 2 {
		runName = fmt.Sprintf("rerun_%s", args[1])
	}
	runDir, err := CreateRunDir(m.state.WorkspaceRoot, runName)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to create run directory: %v", err)
		return m, nil
	}

	m.Status = "Re-running command..."

	// Execute the command
	startTime := time.Now()
	ctx := context.Background()
	return m, func() tea.Msg {
		stdout, exitCode, runErr := ExecuteCommand(ctx, command)

		// Write artifacts
		resolved := map[string]interface{}{
			"rerun_of": m.detailRun.RunDir,
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

		return rerunResultMsg{
			RunDir:   runDir,
			ExitCode: exitCode,
			Err:      runErr,
		}
	}
}

// rerunResultMsg is sent when a re-run completes.
type rerunResultMsg struct {
	RunDir   string
	ExitCode int
	Err      error
}

func (m *RunsScreenModel) deleteRun(runName string) (*RunsScreenModel, tea.Cmd) {
	runDir := filepath.Join(m.state.WorkspaceRoot, "runs", runName)

	if err := os.RemoveAll(runDir); err != nil {
		m.Status = fmt.Sprintf("Failed to delete: %v", err)
	} else {
		m.Status = fmt.Sprintf("Deleted %s", runName)
		// Refresh runs list
		runs, _ := ListRuns(m.state.WorkspaceRoot, 20)
		m.state.Runs = runs
		// Adjust cursor if needed
		filtered := m.filteredRuns()
		if m.cursor >= len(filtered) {
			m.cursor = len(filtered) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
	}
	m.confirmDelete = false
	return m, nil
}

func (m *RunsScreenModel) filteredRuns() []string {
	if m.FilterType == "all" {
		return m.state.Runs
	}

	var filtered []string
	for _, run := range m.state.Runs {
		// Parse run name to determine type
		parts := strings.Split(run, "_")
		if len(parts) >= 3 {
			runType := parts[2]
			if strings.Contains(runType, m.FilterType) {
				filtered = append(filtered, run)
			}
		}
	}
	return filtered
}

func (m *RunsScreenModel) loadRunDetail(runName string) {
	runDir := filepath.Join(m.state.WorkspaceRoot, "runs", runName)
	artifacts, err := LoadRunArtifacts(runDir)
	if err != nil {
		m.Status = fmt.Sprintf("Failed to load run: %v", err)
		m.detailRun = nil
		return
	}
	m.detailRun = artifacts
}

// View renders the runs screen.
func (m *RunsScreenModel) View() string {
	if m.showDetail {
		return m.viewDetail()
	}
	return m.viewList()
}

func (m *RunsScreenModel) viewList() string {
	var b strings.Builder
	filtered := m.filteredRuns()

	// Header
	b.WriteString(headerStyle.Render("RUN HISTORY"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	// Filter tabs
	b.WriteString("Filter: ")
	for i, t := range runFilterTypes {
		if i > 0 {
			b.WriteString(" | ")
		}
		if t == m.FilterType {
			b.WriteString(selectedStyle.Render("[" + t + "]"))
		} else {
			b.WriteString(t)
		}
	}
	b.WriteString("\n\n")

	// Runs list
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n")

	if len(filtered) == 0 {
		b.WriteString(dimStyle.Render("  (no runs found)"))
		b.WriteString("\n")
	} else {
		displayRuns := filtered
		if len(displayRuns) > 15 {
			displayRuns = displayRuns[:15]
		}

		for i, run := range displayRuns {
			prefix := "  "
			if i == m.cursor {
				prefix = "> "
			}

			// Parse run name for display
			status := successStyle.Render("✓")
			runType := "run"
			target := ""
			parts := strings.Split(run, "_")
			if len(parts) >= 3 {
				runType = parts[2]
			}
			if len(parts) >= 4 {
				target = parts[3]
			}

			line := fmt.Sprintf("%s%s  %-12s %-20s %s",
				prefix, run[:min(16, len(run))], runType, target, status)
			if i == m.cursor {
				b.WriteString(selectedStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}

		if len(filtered) > 15 {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  ... and %d more", len(filtered)-15)))
			b.WriteString("\n")
		}
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

func (m *RunsScreenModel) viewDetail() string {
	var b strings.Builder
	filtered := m.filteredRuns()

	runName := "Unknown"
	if m.detailIdx < len(filtered) {
		runName = filtered[m.detailIdx]
	}

	// Header
	b.WriteString(headerStyle.Render(fmt.Sprintf("RUN: %s", runName)))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 60))
	b.WriteString("\n\n")

	if m.detailRun == nil {
		b.WriteString(dimStyle.Render("Failed to load run details"))
		b.WriteString("\n")
	} else {
		// Status
		status := "unknown"
		if m.detailRun.Summary != nil {
			status = m.detailRun.Summary.Status
		}
		b.WriteString(fmt.Sprintf("Status: %s\n", status))

		// Timing
		if m.detailRun.Summary != nil {
			b.WriteString(fmt.Sprintf("Started: %s\n", m.detailRun.Summary.StartedAt))
			b.WriteString(fmt.Sprintf("Finished: %s\n", m.detailRun.Summary.FinishedAt))
			b.WriteString(fmt.Sprintf("Exit code: %d\n", m.detailRun.Summary.ExitCode))
		}

		// Command
		b.WriteString("\n")
		b.WriteString("Command:\n")
		if m.detailRun.Command != "" {
			b.WriteString(dimStyle.Render(m.detailRun.Command))
		} else {
			b.WriteString(dimStyle.Render("(not available)"))
		}
		b.WriteString("\n")

		// Stdout preview
		if m.detailRun.Stdout != "" {
			b.WriteString("\n")
			b.WriteString("Output preview:\n")
			b.WriteString(strings.Repeat("─", 60))
			b.WriteString("\n")
			lines := strings.Split(m.detailRun.Stdout, "\n")
			maxLines := 8
			if len(lines) > maxLines {
				for i := 0; i < maxLines; i++ {
					line := lines[i]
					if len(line) > 58 {
						line = line[:55] + "..."
					}
					b.WriteString(dimStyle.Render("  " + line))
					b.WriteString("\n")
				}
				b.WriteString(dimStyle.Render(fmt.Sprintf("  ... (%d more lines)", len(lines)-maxLines)))
				b.WriteString("\n")
			} else {
				for _, line := range lines {
					if line == "" {
						continue
					}
					if len(line) > 58 {
						line = line[:55] + "..."
					}
					b.WriteString(dimStyle.Render("  " + line))
					b.WriteString("\n")
				}
			}
		}

		// Artifacts
		b.WriteString("\n")
		b.WriteString("Artifacts:\n")
		artifacts := []string{}
		if m.detailRun.Command != "" {
			artifacts = append(artifacts, "command.txt")
		}
		if m.detailRun.Stdout != "" {
			artifacts = append(artifacts, "stdout.log")
		}
		if m.detailRun.Resolved != "" {
			artifacts = append(artifacts, "resolved.yaml")
		}
		if m.detailRun.Summary != nil {
			artifacts = append(artifacts, "summary.json")
		}
		if len(artifacts) > 0 {
			b.WriteString("  " + strings.Join(artifacts, "    "))
		} else {
			b.WriteString(dimStyle.Render("  (no artifacts)"))
		}
		b.WriteString("\n")
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

// Footer returns the footer text for the runs screen.
func (m *RunsScreenModel) Footer() string {
	if m.showDetail {
		return "o: open artifact    r: re-run    y: copy command    Esc: back    m: menu"
	}
	return "Enter: view details    d: delete    Tab: filter    m: menu    ?/h: help"
}
