package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	viewHelp
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
	reviewPlan    *Plan
	running       bool
	showStatus    bool
	cancelRun     func()
	wizardForm    *huh.Form
	wizardContext string
	compareRuns   []string
	homeStatus    string
	prevMode      viewMode
	err           error
}

type homeStatusClearMsg struct{}

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
			if m.wizardContext == "workspace" {
				var cmd tea.Cmd
				m, cmd = m.applyWorkspaceForm()
				return m, cmd
			}
			if kind := wizardKindFromForm(m.wizardForm); kind == "plan" {
				name := strings.TrimSpace(m.wizardForm.GetString("plan_name"))
				steps := m.wizardForm.GetString("plan_steps")
				plan, err := BuildPlanFromText(name, steps)
				if err != nil {
					m.reviewText = "Test Plan"
					m.reviewPlan = nil
					m.reviewProfile = nil
					m.reviewCommand = CommandSpec{}
					m.reviewStatus = err.Error()
					m.wizardForm = nil
					m.wizardContext = ""
					m.mode = viewReview
					return m, nil
				}
				m.reviewText = renderPlanDetails(plan)
				m.reviewPlan = &plan
				m.reviewProfile = nil
				m.reviewCommand = CommandSpec{}
				m.reviewStatus = "Plan ready. Save to workspace/plans."
				m.wizardForm = nil
				m.wizardContext = ""
				m.mode = viewReview
				return m, nil
			}
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
			m.wizardContext = ""
			m.mode = viewReview
		case huh.StateAborted:
			m.wizardForm = nil
			m.wizardContext = ""
			m.mode = viewHome
		}
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			if m.mode != viewHelp {
				m.prevMode = m.mode
				m.mode = viewHelp
			}
			return m, nil
		case "/":
			m.searchFocus = true
			return m, nil
		case "esc":
			if m.mode == viewHelp {
				m.mode = m.prevMode
				return m, nil
			}
			m.searchFocus = false
			m.search = ""
			return m, nil
		case "h":
			m.mode = viewHome
			m.cursor = 0
		case "p":
			m.mode = viewPalette
			m.cursor = 0
		case "u":
			m.mode = viewPalette
			m.search = "run"
			m.searchFocus = false
			m.cursor = 0
		case "g":
			m.mode = viewPalette
			m.search = "config"
			m.searchFocus = false
			m.cursor = 0
		case "n":
			m.mode = viewPalette
			m.search = "plan"
			m.searchFocus = false
			m.cursor = 0
		case "c":
			m.mode = viewCatalog
			m.cursor = 0
		case "b":
			if m.mode == viewHelp {
				m.mode = m.prevMode
				return m, nil
			}
			m.mode = viewHome
			m.reviewText = ""
			m.reviewProfile = nil
			m.reviewCommand = CommandSpec{}
			m.reviewStatus = ""
			m.reviewPlan = nil
			m.cancelRun = nil
			m.wizardForm = nil
			m.wizardContext = ""
			m.compareRuns = nil
			m.homeStatus = ""
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
							m.wizardForm = buildWizardFormWithDefaults(m.workspaceRoot, *entry)
							m.mode = viewWizard
						}
					}
					if m.mode == viewReview && strings.HasPrefix(m.reviewStatus, "Compare:") {
						m.mode = viewPalette
						m.search = "run"
						m.searchFocus = false
						m.cursor = 0
					}
				case "r":
					if m.mode == viewReview {
						var cmd tea.Cmd
						m, cmd = m.runCurrentArtifact()
						return m, cmd
					}
				case "s":
					if m.mode == viewReview {
						m = m.saveCurrentArtifact()
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
				case "d":
					if m.mode == viewReview && m.reviewStatus != "" {
						if runName := strings.TrimPrefix(m.reviewStatus, "Run: "); runName != "" {
							m.compareRuns = append(m.compareRuns, runName)
							if len(m.compareRuns) > 2 {
								m.compareRuns = m.compareRuns[len(m.compareRuns)-2:]
							}
							if len(m.compareRuns) == 2 {
								left := filepath.Join(m.workspaceRoot, "runs", m.compareRuns[0])
								right := filepath.Join(m.workspaceRoot, "runs", m.compareRuns[1])
								m.reviewText = renderRunComparison(left, right)
								m.reviewStatus = fmt.Sprintf("Compare: %s vs %s", m.compareRuns[0], m.compareRuns[1])
								m.mode = viewReview
							} else {
								m.reviewStatus = fmt.Sprintf("Compare: selected %s (pick another run)", runName)
							}
						}
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
	case homeStatusClearMsg:
		m.homeStatus = ""
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
	footer := "\nKeys: h=home p=palette u=runs g=profiles n=plans c=catalog /=search esc=clear q=quit enter=select"
	if m.selected != "" {
		footer += fmt.Sprintf(" selected=%s", m.selected)
	}
	footer += fmt.Sprintf(" view=%s", m.viewLabel())
	if m.searchFocus {
		footer += " [search]"
	}
	footer = footerStyle.Render(footer)
	switch m.mode {
	case viewPalette:
		filtered := FilterPalette(m.palette, m.search)
		return header + renderPaletteWithCursor(filtered, m.cursor, m.search) + footer
	case viewCatalog:
		filtered := FilterCatalogEntries(m.catalog, m.search)
		return header + renderCatalogWithCursor(filtered, m.cursor, m.search) + footer
	case viewReview:
		status := ""
		if m.showStatus {
			if m.reviewStatus != "" {
				status = "\n\n" + m.reviewStatus
			}
			if m.running {
				status += "\n\nRunning..."
			}
			if len(m.compareRuns) == 1 {
				status += fmt.Sprintf("\n\nCompare: %s (pick another run)", m.compareRuns[0])
			}
		}
		frameStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(1, 2)
		reviewFooter := footerStyle.Render("\n\nKeys: r=run s=save c=copy x=cancel d=compare space=status b=back q=quit")
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
	case viewHelp:
		return header + renderHelpScreen() + footer
	default:
		return header + RenderHomeScreenWithCursor(m.workspaceName, m.profiles, m.runs, m.palette, m.cursor, m.homeStatus) + footer
	}
}

func (m tuiModel) viewLabel() string {
	switch m.mode {
	case viewHome:
		return "home"
	case viewPalette:
		return "palette"
	case viewCatalog:
		return "catalog"
	case viewReview:
		return "review"
	case viewWizard:
		return "wizard"
	case viewHelp:
		return "help"
	default:
		return "unknown"
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
	case "Run":
		runDir := filepath.Join(m.workspaceRoot, "runs", item.Title)
		artifacts, err := LoadRunArtifacts(runDir)
		if err != nil {
			m.reviewText = "Run details"
			m.reviewProfile = nil
			m.reviewCommand = CommandSpec{}
			m.reviewStatus = fmt.Sprintf("Run: %s (failed to load artifacts)", item.Title)
			m.mode = viewReview
			return m
		}
		m.reviewText = renderRunDetails(*artifacts)
		m.reviewProfile = nil
		m.reviewCommand = CommandSpec{}
		m.reviewStatus = fmt.Sprintf("Run: %s", item.Title)
		m.mode = viewReview
	case "Plan":
		planPath := filepath.Join(m.workspaceRoot, "plans", item.Title+".yaml")
		plan, err := LoadPlan(planPath)
		if err != nil {
			m.reviewText = "Test Plan"
			m.reviewProfile = nil
			m.reviewCommand = CommandSpec{}
			m.reviewPlan = nil
			m.reviewStatus = fmt.Sprintf("Failed to load plan: %s", item.Title)
			m.mode = viewReview
			return m
		}
		m.reviewText = renderPlanDetails(*plan)
		m.reviewPlan = plan
		m.reviewProfile = nil
		m.reviewCommand = CommandSpec{}
		m.reviewStatus = fmt.Sprintf("Plan: %s", plan.Name)
		m.mode = viewReview
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
		m.wizardContext = "wizard"
		m.mode = viewWizard
	case "Single Request":
		m.wizardForm = buildWizardFormWithDefault("single", m.workspaceRoot)
		m.wizardContext = "wizard"
		m.mode = viewWizard
	case "Test Plan Builder":
		m.wizardForm = buildWizardFormWithDefault("plan", m.workspaceRoot)
		m.wizardContext = "wizard"
		m.mode = viewWizard
	case "Workspace":
		m.wizardForm = buildWorkspaceForm(m.workspaceRoot)
		m.wizardContext = "workspace"
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
		stdout, exitCode, runErr := ExecuteCommand(ctx, command)
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

func (m tuiModel) runCurrentArtifact() (tuiModel, tea.Cmd) {
	if m.reviewPlan != nil {
		if m.running {
			m.reviewStatus = "Run already in progress"
			return m, nil
		}
		runDir, err := CreateRunDir(m.workspaceRoot, m.reviewPlan.Name)
		if err != nil {
			m.err = err
			return m, nil
		}
		plan := *m.reviewPlan
		m.running = true
		m.reviewStatus = fmt.Sprintf("Plan started. Artifacts: %s", runDir)
		ctx, cancel := context.WithCancel(context.Background())
		m.cancelRun = cancel
		return m, func() tea.Msg {
			started := time.Now().UTC()
			stdout, runErr := ExecutePlan(ctx, m.workspaceRoot, plan)
			finished := time.Now().UTC()
			status := "success"
			exitCode := 0
			canceled := false
			if runErr != nil {
				status = "failed"
				exitCode = 1
				if errors.Is(runErr, context.Canceled) {
					status = "canceled"
					canceled = true
				}
			}
			return runResult{
				runDir:     runDir,
				profile:    Profile{Name: plan.Name},
				command:    CommandSpec{Args: []string{"plan", plan.Name}},
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
	return m.runCurrentProfile()
}

func (m tuiModel) saveCurrentArtifact() tuiModel {
	if m.reviewPlan != nil {
		plansDir := filepath.Join(m.workspaceRoot, "plans")
		if err := os.MkdirAll(plansDir, 0755); err != nil {
			m.err = fmt.Errorf("create plans dir: %w", err)
			return m
		}
		path := PlanPath(m.workspaceRoot, m.reviewPlan.Name)
		path = nextAvailablePath(path)
		if err := SavePlan(path, *m.reviewPlan); err != nil {
			m.err = err
			return m
		}
		m.reviewStatus = fmt.Sprintf("Saved plan: %s", path)
		return m
	}
	return m.saveCurrentProfile()
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

func renderPaletteWithCursor(items []PaletteItem, cursor int, query string) string {
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	kindStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	header := "Palette"
	if strings.TrimSpace(query) != "" {
		header = fmt.Sprintf("Palette (%d match)", len(items))
		if len(items) != 1 {
			header = fmt.Sprintf("Palette (%d matches)", len(items))
		}
	}
	lines := []string{titleStyle.Render(header)}
	if len(items) == 0 {
		lines = append(lines, "(no items)")
		if strings.TrimSpace(query) != "" {
			lines = append(lines, "Tip: press Esc to clear search")
		}
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
		if hint := paletteHint(item); hint != "" {
			lines = append(lines, fmt.Sprintf("  %s", metaStyle.Render(hint)))
		}
	}
	return frameStyle.Render(strings.Join(lines, "\n"))
}

func renderCatalogWithCursor(entries []CatalogEntry, cursor int, query string) string {
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	header := "CIP Catalog"
	if strings.TrimSpace(query) != "" {
		header = fmt.Sprintf("CIP Catalog (%d match)", len(entries))
		if len(entries) != 1 {
			header = fmt.Sprintf("CIP Catalog (%d matches)", len(entries))
		}
	}
	lines := []string{titleStyle.Render(header), ""}
	if len(entries) == 0 {
		lines = append(lines, "(no catalog entries)")
		if strings.TrimSpace(query) != "" {
			lines = append(lines, "Tip: press Esc to clear search")
		}
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
		scopeLabel := entry.Scope
		if scopeLabel == "" {
			scopeLabel = "core"
		}
		scopeSuffix := scopeLabel
		if entry.Vendor != "" {
			scopeSuffix = fmt.Sprintf("%s/%s", scopeLabel, entry.Vendor)
		}
		lines = append(lines, fmt.Sprintf("%s%s (%s)", prefix, entry.Name, entry.Key))
		lines = append(lines, fmt.Sprintf("  Scope: %s", scopeSuffix))
		lines = append(lines, fmt.Sprintf("  Service: %s  Class: %s  Instance: %s  Attribute: %s", serviceLabel, classLabel, entry.Instance, entry.Attribute))
		if entry.Notes != "" {
			lines = append(lines, fmt.Sprintf("  Notes: %s", entry.Notes))
		}
	}
	return frameStyle.Render(strings.Join(lines, "\n"))
}

func renderRunDetails(artifacts RunArtifacts) string {
	lines := []string{
		"Run Details",
		fmt.Sprintf("Run: %s", artifacts.RunDir),
	}
	if artifacts.Summary != nil {
		lines = append(lines, fmt.Sprintf("Status: %s", artifacts.Summary.Status))
		lines = append(lines, fmt.Sprintf("Started: %s", artifacts.Summary.StartedAt))
		lines = append(lines, fmt.Sprintf("Finished: %s", artifacts.Summary.FinishedAt))
		lines = append(lines, fmt.Sprintf("Exit: %d", artifacts.Summary.ExitCode))
	}
	if artifacts.Command != "" {
		lines = append(lines, "", "Command:", artifacts.Command)
	}
	if artifacts.Stdout != "" {
		lines = append(lines, "", "Stdout:", truncateText(artifacts.Stdout, 12))
	}
	if artifacts.Resolved != "" {
		lines = append(lines, "", "Resolved:", truncateText(artifacts.Resolved, 12))
	}
	return strings.Join(lines, "\n")
}

func paletteHint(item PaletteItem) string {
	switch item.Kind {
	case "Task":
		switch item.Title {
		case "New Run (Wizard)":
			return "Create a new run profile from guided inputs."
		case "Run Existing Config":
			return "Select a saved profile and run it."
		case "Baseline (Guided)":
			return "Run the baseline test suite."
		case "Start Server Emulator":
			return "Start the CIP server emulator."
		case "Single Request":
			return "Send a one-off CIP request."
		case "Test Plan Builder":
			return "Create and run multi-step plans."
		case "Workspace":
			return "Open or create a workspace."
		case "Explore CIP Catalog":
			return "Browse catalog operations."
		}
	case "Config":
		return fmt.Sprintf("Profile kind: %s", item.Meta)
	case "Plan":
		if item.Meta != "" {
			return "Plan " + item.Meta
		}
		return "Saved plan"
	case "Run":
		return "View run artifacts"
	case "Catalog":
		if item.Meta != "" {
			return "Catalog: " + item.Meta
		}
		return "Catalog entry"
	}
	return ""
}
func renderRunComparison(leftDir, rightDir string) string {
	left, leftErr := LoadRunArtifacts(leftDir)
	right, rightErr := LoadRunArtifacts(rightDir)
	lines := []string{
		"Run Comparison",
		fmt.Sprintf("Left: %s", leftDir),
		fmt.Sprintf("Right: %s", rightDir),
	}
	if leftErr != nil || rightErr != nil {
		lines = append(lines, "", "Unable to load artifacts for one or both runs.")
		if leftErr != nil {
			lines = append(lines, fmt.Sprintf("Left error: %v", leftErr))
		}
		if rightErr != nil {
			lines = append(lines, fmt.Sprintf("Right error: %v", rightErr))
		}
		return strings.Join(lines, "\n")
	}
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("Left status: %s", summaryStatus(left.Summary)))
	lines = append(lines, fmt.Sprintf("Right status: %s", summaryStatus(right.Summary)))
	lines = append(lines, fmt.Sprintf("Left exit: %d", summaryExit(left.Summary)))
	lines = append(lines, fmt.Sprintf("Right exit: %d", summaryExit(right.Summary)))
	if left.Command != right.Command {
		lines = append(lines, "", "Command differs.")
		lines = append(lines, "Left:", left.Command)
		lines = append(lines, "Right:", right.Command)
	} else {
		lines = append(lines, "", "Command: identical")
	}
	if left.Resolved != right.Resolved {
		lines = append(lines, "", "Resolved config differs.")
	} else {
		lines = append(lines, "Resolved config: identical")
	}
	lines = append(lines, "", "Tip: press Enter to pick new runs")
	return strings.Join(lines, "\n")
}

func renderPlanDetails(plan Plan) string {
	lines := []string{
		"Test Plan",
		fmt.Sprintf("Name: %s", plan.Name),
		"",
		"Steps:",
	}
	for _, step := range plan.Steps {
		for k, v := range step {
			lines = append(lines, fmt.Sprintf("- %s: %s", k, v))
		}
	}
	lines = append(lines,
		"",
		"Formats:",
		"- single:<catalog_key>@<ip[:port]>",
		"- sleep:<duration>",
		"- replay:<profile_name>",
	)
	return strings.Join(lines, "\n")
}

func renderHelpScreen() string {
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	lines := []string{
		"Help",
		"",
		"Global:",
		"  ?        Help",
		"  /        Search",
		"  Esc      Clear search / close help",
		"  q        Quit",
		"",
		"Navigation:",
		"  h        Home",
		"  p        Palette",
		"  c        Catalog",
		"  Up/Down  Move selection",
		"  Enter    Select",
		"",
		"Review:",
		"  r        Run",
		"  s        Save",
		"  c        Copy command",
		"  x        Cancel run",
		"  d        Compare runs",
		"  Space    Toggle status",
		"  b        Back",
	}
	return frameStyle.Render(strings.Join(lines, "\n"))
}

func (m tuiModel) applyWorkspaceForm() (tuiModel, tea.Cmd) {
	action := strings.ToLower(strings.TrimSpace(m.wizardForm.GetString("workspace_action")))
	path := strings.TrimSpace(m.wizardForm.GetString("workspace_path"))
	name := strings.TrimSpace(m.wizardForm.GetString("workspace_name"))
	if path == "" {
		m.reviewText = "Workspace"
		m.reviewStatus = "Workspace path is required."
		m.wizardForm = nil
		m.wizardContext = ""
		m.mode = viewReview
		return m, nil
	}
	var ws *Workspace
	var err error
	switch action {
	case "create":
		ws, err = CreateWorkspace(path, name)
	default:
		ws, err = EnsureWorkspace(path)
	}
	if err != nil {
		m.reviewText = "Workspace"
		m.reviewStatus = err.Error()
		m.wizardForm = nil
		m.wizardContext = ""
		m.mode = viewReview
		return m, nil
	}
	m.workspaceRoot = ws.Root
	m.workspaceName = ws.Config.Name
	m.reloadWorkspace()
	m.homeStatus = fmt.Sprintf("Workspace loaded: %s", ws.Root)
	m.wizardForm = nil
	m.wizardContext = ""
	m.mode = viewHome
	return m, tea.Tick(3*time.Second, func(time.Time) tea.Msg {
		return homeStatusClearMsg{}
	})
}

func (m *tuiModel) reloadWorkspace() {
	m.profiles, _ = ListProfiles(m.workspaceRoot)
	m.runs, _ = ListRuns(m.workspaceRoot, 5)
	m.palette, _ = BuildPaletteIndex(m.workspaceRoot)
	m.catalog, _ = ListCatalogEntries(m.workspaceRoot)
}

func summaryStatus(summary *RunSummary) string {
	if summary == nil {
		return "unknown"
	}
	return summary.Status
}

func summaryExit(summary *RunSummary) int {
	if summary == nil {
		return -1
	}
	return summary.ExitCode
}

func truncateText(input string, maxLines int) string {
	if maxLines <= 0 {
		return ""
	}
	lines := strings.Split(input, "\n")
	if len(lines) <= maxLines {
		return input
	}
	return strings.Join(lines[:maxLines], "\n") + "\n..."
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
