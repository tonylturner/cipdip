package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/tturner/cipdip/internal/cipclient"
)

type viewMode int

const (
	viewHome viewMode = iota
	viewPalette
	viewCatalog
	viewReview
	viewWizard
)

type tuiModel struct {
	workspaceRoot string
	workspaceName string
	profiles      []ProfileInfo
	runs          []string
	palette       []PaletteItem
	catalog       []CatalogEntry
	mode          viewMode
	search        string
	searchFocus   bool
	cursor        int
	selected      string
	reviewText    string
	reviewProfile *Profile
	reviewCommand CommandSpec
	reviewStatus  string
	running       bool
	showStatus    bool
	cancelRun     func()
	wizardForm    *huh.Form
	err           error
}

func newTUIModel(workspaceRoot, workspaceName string, profiles []ProfileInfo, runs []string, palette []PaletteItem, catalog []CatalogEntry) tuiModel {
	return tuiModel{
		workspaceRoot: workspaceRoot,
		workspaceName: workspaceName,
		profiles:      profiles,
		runs:          runs,
		palette:       palette,
		catalog:       catalog,
		mode:          viewHome,
		showStatus:    true,
	}
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.mode == viewWizard && m.wizardForm != nil {
		formModel, cmd := m.wizardForm.Update(msg)
		m.wizardForm = formModel.(*huh.Form)
		switch m.wizardForm.State {
		case huh.StateCompleted:
			profile, err := buildWizardProfileFromForm(m.wizardForm, m.workspaceRoot)
			if err != nil {
				m.err = err
				return m, nil
			}
			command, err := BuildCommand(profile)
			if err != nil {
				m.err = err
				return m, nil
			}
			m.reviewText = RenderReviewScreen(profile, command)
			m.reviewProfile = &profile
			m.reviewCommand = command
			m.reviewStatus = ""
			m.wizardForm = nil
			m.mode = viewReview
		case huh.StateAborted:
			m.wizardForm = nil
			m.mode = viewHome
		}
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "/":
			m.searchFocus = true
			return m, nil
		case "esc":
			m.searchFocus = false
			m.search = ""
			return m, nil
		case "h":
			m.mode = viewHome
			m.cursor = 0
		case "p":
			m.mode = viewPalette
			m.cursor = 0
		case "c":
			m.mode = viewCatalog
			m.cursor = 0
		case "b":
			m.mode = viewHome
			m.reviewText = ""
			m.reviewProfile = nil
			m.reviewCommand = CommandSpec{}
			m.reviewStatus = ""
			m.cancelRun = nil
			m.wizardForm = nil
		default:
			if m.searchFocus {
				switch msg.Type {
				case tea.KeyBackspace:
					if len(m.search) > 0 {
						m.search = m.search[:len(m.search)-1]
					}
				case tea.KeyEnter:
					m.searchFocus = false
				default:
					if msg.Type == tea.KeyRunes {
						m.search += msg.String()
					}
				}
			} else {
				switch msg.String() {
				case "up", "k":
					m.cursor--
				case "down", "j":
					m.cursor++
				case "enter":
					m.selected = m.currentSelection()
					if m.mode == viewHome {
						m = m.handleHomeSelection()
					}
					if m.mode == viewPalette {
						m = m.handlePaletteSelection()
					}
					if m.mode == viewCatalog {
						if entry := m.currentCatalogEntry(); entry != nil {
							profile := profileFromCatalogEntry(*entry)
							cmd, err := BuildCommand(profile)
							if err != nil {
								m.err = err
								return m, nil
							}
							m.reviewText = RenderReviewScreen(profile, cmd)
							m.reviewProfile = &profile
							m.reviewCommand = cmd
							m.reviewStatus = ""
							m.mode = viewReview
						}
					}
				case "r":
					if m.mode == viewReview {
						var cmd tea.Cmd
						m, cmd = m.runCurrentProfile()
						return m, cmd
					}
				case "s":
					if m.mode == viewReview {
						m = m.saveCurrentProfile()
					}
				case "c":
					if m.mode == viewReview {
						m = m.copyCurrentCommand()
					}
				case "x":
					if m.mode == viewReview && m.running && m.cancelRun != nil {
						m.cancelRun()
						m.reviewStatus = "Cancel requested..."
					}
				case " ":
					if m.mode == viewReview {
						m.showStatus = !m.showStatus
					}
				}
			}
		}
	case runResult:
		if msg.canceled {
			m.reviewStatus = fmt.Sprintf("Run canceled. Artifacts: %s", msg.runDir)
		} else if msg.err != nil {
			m.reviewStatus = fmt.Sprintf("Run failed (exit %d). Artifacts: %s", msg.exitCode, msg.runDir)
		} else {
			m.reviewStatus = fmt.Sprintf("Run complete. Artifacts: %s", msg.runDir)
		}
		if msg.err != nil {
			if msg.canceled {
				msg.status = "canceled"
			}
		}
		summary := RunSummary{
			Status:     msg.status,
			Command:    msg.command.Args,
			StartedAt:  msg.startedAt.Format(time.RFC3339),
			FinishedAt: msg.finishedAt.Format(time.RFC3339),
			ExitCode:   msg.exitCode,
		}
		if err := WriteRunArtifacts(msg.runDir, msg.profile, msg.command.Args, msg.stdout, summary); err != nil {
			m.err = err
			return m, nil
		}
		if runs, err := ListRuns(m.workspaceRoot, 5); err == nil {
			m.runs = runs
		}
		m.running = false
		m.cancelRun = nil
	}
	m.cursor = clampCursor(m.cursor, m.currentListLen())
	return m, nil
}

func (m tuiModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("Error: %v\n", m.err)
	}

	searchLabel := "Search"
	if m.searchFocus {
		searchLabel = "Search (editing)"
	}
	header := fmt.Sprintf("%s: %s\n", searchLabel, m.search)
	footerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	footer := "\nKeys: h=home p=palette c=catalog /=search esc=clear q=quit enter=select"
	if m.selected != "" {
		footer += fmt.Sprintf(" selected=%s", m.selected)
	}
	footer = footerStyle.Render(footer)
	switch m.mode {
	case viewPalette:
		return header + renderPaletteWithCursor(FilterPalette(m.palette, m.search), m.cursor) + footer
	case viewCatalog:
		filtered := FilterCatalogEntries(m.catalog, m.search)
		return header + renderCatalogWithCursor(filtered, m.cursor) + footer
	case viewReview:
		status := ""
		if m.showStatus {
			if m.reviewStatus != "" {
				status = "\n\n" + m.reviewStatus
			}
			if m.running {
				status += "\n\nRunning..."
			}
		}
		frameStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(1, 2)
		reviewFooter := footerStyle.Render("\n\nKeys: r=run s=save c=copy x=cancel space=status b=back q=quit")
		return header + frameStyle.Render(m.reviewText+status) + reviewFooter
	case viewWizard:
		if m.wizardForm == nil {
			return header + "Wizard not initialized.\n"
		}
		frameStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(1, 2)
		return header + frameStyle.Render(m.wizardForm.View())
	default:
		return header + RenderHomeScreenWithCursor(m.workspaceName, m.profiles, m.runs, m.palette, m.cursor) + footer
	}
}

func (m tuiModel) currentListLen() int {
	switch m.mode {
	case viewHome:
		return len(HomeActions())
	case viewPalette:
		return len(FilterPalette(m.palette, m.search))
	case viewCatalog:
		return len(FilterCatalogEntries(m.catalog, m.search))
	default:
		return 0
	}
}

func (m tuiModel) currentSelection() string {
	switch m.mode {
	case viewHome:
		actions := HomeActions()
		if m.cursor >= 0 && m.cursor < len(actions) {
			return actions[m.cursor]
		}
	case viewPalette:
		items := FilterPalette(m.palette, m.search)
		if m.cursor >= 0 && m.cursor < len(items) {
			return items[m.cursor].Title
		}
	case viewCatalog:
		items := FilterCatalogEntries(m.catalog, m.search)
		if m.cursor >= 0 && m.cursor < len(items) {
			return items[m.cursor].Key
		}
	}
	return ""
}

func (m tuiModel) currentCatalogEntry() *CatalogEntry {
	if m.mode != viewCatalog {
		return nil
	}
	items := FilterCatalogEntries(m.catalog, m.search)
	if m.cursor >= 0 && m.cursor < len(items) {
		return &items[m.cursor]
	}
	return nil
}

func (m tuiModel) handleHomeSelection() tuiModel {
	actions := HomeActions()
	if m.cursor < 0 || m.cursor >= len(actions) {
		return m
	}
	return m.applyTaskAction(actions[m.cursor])
}

func (m tuiModel) handlePaletteSelection() tuiModel {
	items := FilterPalette(m.palette, m.search)
	if m.cursor < 0 || m.cursor >= len(items) {
		return m
	}
	item := items[m.cursor]
	switch item.Kind {
	case "Catalog":
		m.mode = viewCatalog
		m.search = item.Title
		m.searchFocus = false
	case "Config":
		if profile := findProfileByName(m.profiles, item.Title); profile != nil {
			loaded, err := LoadProfile(profile.Path)
			if err != nil {
				m.err = err
				return m
			}
			cmd, err := BuildCommand(*loaded)
			if err != nil {
				m.err = err
				return m
			}
			m.reviewText = RenderReviewScreen(*loaded, cmd)
			m.reviewProfile = loaded
			m.reviewCommand = cmd
			m.reviewStatus = ""
			m.mode = viewReview
		}
	case "Task":
		return m.applyTaskAction(item.Title)
	default:
		m.selected = item.Title
	}
	return m
}

func (m tuiModel) applyTaskAction(title string) tuiModel {
	switch title {
	case "Explore CIP Catalog":
		m.mode = viewCatalog
		m.search = ""
	case "Baseline (Guided)":
		profile := Profile{
			Version: 1,
			Kind:    "baseline",
			Name:    "baseline",
			Spec:    map[string]interface{}{},
		}
		cmd, err := BuildCommand(profile)
		if err != nil {
			m.err = err
			return m
		}
		m.reviewText = RenderReviewScreen(profile, cmd)
		m.reviewProfile = &profile
		m.reviewCommand = cmd
		m.reviewStatus = ""
		m.mode = viewReview
	case "Start Server Emulator":
		profile := Profile{
			Version: 1,
			Kind:    "server",
			Name:    "server",
			Spec:    map[string]interface{}{},
		}
		cmd, err := BuildCommand(profile)
		if err != nil {
			m.err = err
			return m
		}
		m.reviewText = RenderReviewScreen(profile, cmd)
		m.reviewProfile = &profile
		m.reviewCommand = cmd
		m.reviewStatus = ""
		m.mode = viewReview
	case "Run Existing Config":
		m.mode = viewPalette
		m.search = "config"
		m.searchFocus = false
		m.cursor = 0
	case "New Run (Wizard)":
		m.wizardForm = buildWizardForm(m.workspaceRoot)
		m.mode = viewWizard
	case "Single Request":
		m.wizardForm = buildWizardFormWithDefault("single", m.workspaceRoot)
		m.mode = viewWizard
	}
	return m
}

func findProfileByName(profiles []ProfileInfo, name string) *ProfileInfo {
	for _, profile := range profiles {
		if profile.Name == name {
			return &profile
		}
	}
	return nil
}

func findFirstPcap(workspaceRoot string) string {
	pcapsDir := filepath.Join(workspaceRoot, "pcaps")
	var found string
	stop := errors.New("stop")
	if err := filepath.WalkDir(pcapsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
			found = path
			return stop
		}
		return nil
	}); err != nil && !errors.Is(err, stop) {
		return ""
	}
	return found
}

type runResult struct {
	runDir     string
	profile    Profile
	command    CommandSpec
	stdout     string
	exitCode   int
	status     string
	startedAt  time.Time
	finishedAt time.Time
	err        error
	canceled   bool
}

func (m tuiModel) runCurrentProfile() (tuiModel, tea.Cmd) {
	if m.reviewProfile == nil {
		m.reviewStatus = "Run: no profile selected"
		return m, nil
	}
	if m.running {
		m.reviewStatus = "Run already in progress"
		return m, nil
	}
	if m.reviewCommand.Args == nil || len(m.reviewCommand.Args) == 0 {
		cmd, err := BuildCommand(*m.reviewProfile)
		if err != nil {
			m.err = err
			return m, nil
		}
		m.reviewCommand = cmd
	}
	runDir, err := CreateRunDir(m.workspaceRoot, m.reviewProfile.Name)
	if err != nil {
		m.err = err
		return m, nil
	}
	profile := *m.reviewProfile
	command := m.reviewCommand
	m.running = true
	m.reviewStatus = fmt.Sprintf("Run started. Artifacts: %s", runDir)
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelRun = cancel
	return m, func() tea.Msg {
		started := time.Now().UTC()
		stdout, exitCode, runErr := executeCommand(ctx, command)
		finished := time.Now().UTC()
		status := "success"
		canceled := false
		if runErr != nil {
			status = "failed"
			if errors.Is(runErr, context.Canceled) {
				status = "canceled"
				canceled = true
			}
		}
		return runResult{
			runDir:     runDir,
			profile:    profile,
			command:    command,
			stdout:     stdout,
			exitCode:   exitCode,
			status:     status,
			startedAt:  started,
			finishedAt: finished,
			err:        runErr,
			canceled:   canceled,
		}
	}
}

func (m tuiModel) saveCurrentProfile() tuiModel {
	if m.reviewProfile == nil {
		m.reviewStatus = "Save: no profile selected"
		return m
	}
	profilesDir := filepath.Join(m.workspaceRoot, "profiles")
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		m.err = fmt.Errorf("create profiles dir: %w", err)
		return m
	}
	base := sanitizeRunName(m.reviewProfile.Name)
	if base == "" {
		base = "profile"
	}
	path := filepath.Join(profilesDir, base+".yaml")
	path = nextAvailablePath(path)
	if err := SaveProfile(path, *m.reviewProfile); err != nil {
		m.err = err
		return m
	}
	m.reviewStatus = fmt.Sprintf("Saved profile: %s", path)
	return m
}

func (m tuiModel) copyCurrentCommand() tuiModel {
	if m.reviewCommand.Args == nil || len(m.reviewCommand.Args) == 0 {
		if m.reviewProfile == nil {
			m.reviewStatus = "Copy: no command available"
			return m
		}
		cmd, err := BuildCommand(*m.reviewProfile)
		if err != nil {
			m.err = err
			return m
		}
		m.reviewCommand = cmd
	}
	command := FormatCommand(m.reviewCommand.Args)
	if err := clipboard.WriteAll(command); err != nil {
		m.reviewStatus = fmt.Sprintf("Copy failed: %v", err)
		return m
	}
	m.reviewStatus = "Command copied to clipboard"
	return m
}

func executeCommand(ctx context.Context, command CommandSpec) (string, int, error) {
	if len(command.Args) == 0 {
		return "", 0, fmt.Errorf("command is empty")
	}
	executable, err := os.Executable()
	if err != nil {
		executable = command.Args[0]
	}
	args := command.Args[1:]
	if command.Args[0] != "cipdip" {
		executable = command.Args[0]
		args = command.Args[1:]
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return output.String(), exitCode, err
}

func nextAvailablePath(path string) string {
	if _, err := os.Stat(path); err != nil {
		return path
	}
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s-%d%s", base, i, ext)
		if _, err := os.Stat(candidate); err != nil {
			return candidate
		}
	}
	return path
}

func profileFromCatalogEntry(entry CatalogEntry) Profile {
	spec := map[string]interface{}{}
	if entry.Service != "" {
		spec["service"] = entry.Service
	}
	if entry.Class != "" {
		spec["class"] = entry.Class
	}
	if entry.Instance != "" {
		spec["instance"] = entry.Instance
	}
	if entry.Attribute != "" {
		spec["attribute"] = entry.Attribute
	}
	return Profile{
		Version: 1,
		Kind:    "single",
		Name:    entry.Key,
		Spec:    spec,
	}
}

func clampCursor(cursor, length int) int {
	if length <= 0 {
		return 0
	}
	if cursor < 0 {
		return 0
	}
	if cursor >= length {
		return length - 1
	}
	return cursor
}

func renderPaletteWithCursor(items []PaletteItem, cursor int) string {
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	kindStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	lines := []string{titleStyle.Render("Palette")}
	if len(items) == 0 {
		lines = append(lines, "(no items)")
		return frameStyle.Render(strings.Join(lines, "\n"))
	}
	currentKind := ""
	for i, item := range items {
		if item.Kind != currentKind {
			currentKind = item.Kind
			lines = append(lines, "", kindStyle.Render(fmt.Sprintf("[%s]", currentKind)))
		}
		prefix := "  "
		if i == cursor {
			prefix = "> "
		}
		lines = append(lines, fmt.Sprintf("%s%s", prefix, item.String()))
	}
	return frameStyle.Render(strings.Join(lines, "\n"))
}

func renderCatalogWithCursor(entries []CatalogEntry, cursor int) string {
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	lines := []string{titleStyle.Render("CIP Catalog"), ""}
	if len(entries) == 0 {
		lines = append(lines, "(no catalog entries)")
		return frameStyle.Render(strings.Join(lines, "\n"))
	}
	for i, entry := range entries {
		prefix := "  "
		if i == cursor {
			prefix = "> "
		}
		serviceLabel := entry.Service
		if code, ok := parseServiceForDisplay(entry.Service); ok {
			if alias, ok := cipclient.ServiceAliasName(code); ok {
				serviceLabel = fmt.Sprintf("%s (%s)", entry.Service, alias)
			}
		}
		classLabel := entry.Class
		if code, ok := parseClassForDisplay(entry.Class); ok {
			if alias, ok := cipclient.ClassAliasName(code); ok {
				classLabel = fmt.Sprintf("%s (%s)", entry.Class, alias)
			}
		}
		lines = append(lines, fmt.Sprintf("%s%s (%s)", prefix, entry.Name, entry.Key))
		lines = append(lines, fmt.Sprintf("  Service: %s  Class: %s  Instance: %s  Attribute: %s", serviceLabel, classLabel, entry.Instance, entry.Attribute))
	}
	return frameStyle.Render(strings.Join(lines, "\n"))
}

func parseServiceForDisplay(input string) (uint8, bool) {
	if value, err := strconv.ParseUint(strings.TrimSpace(input), 0, 8); err == nil {
		return uint8(value), true
	}
	if code, ok := cipclient.ParseServiceAlias(input); ok {
		return code, true
	}
	return 0, false
}

func parseClassForDisplay(input string) (uint16, bool) {
	if value, err := strconv.ParseUint(strings.TrimSpace(input), 0, 16); err == nil {
		return uint16(value), true
	}
	if code, ok := cipclient.ParseClassAlias(input); ok {
		return code, true
	}
	return 0, false
}

// RunTUI starts the Bubble Tea UI.
func RunTUI(workspaceRoot string) error {
	ws, err := LoadWorkspace(workspaceRoot)
	if err != nil {
		return err
	}
	profiles, _ := ListProfiles(ws.Root)
	runs, _ := ListRuns(ws.Root, 5)
	palette, _ := BuildPaletteIndex(ws.Root)
	catalog, _ := ListCatalogEntries(ws.Root)

	model := newTUIModel(ws.Root, ws.Config.Name, profiles, runs, palette, catalog)
	program := tea.NewProgram(model)
	_, err = program.Run()
	return err
}
