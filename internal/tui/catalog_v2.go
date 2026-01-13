package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/catalog"
	"github.com/tturner/cipdip/internal/cip/protocol"
)

// CatalogScreen represents the current catalog screen.
type CatalogScreen int

const (
	CatalogScreen1Groups  CatalogScreen = iota // Service group list
	CatalogScreen2Targets                      // Target selection + EPATH preview
	CatalogScreen3Config                       // Configure request
	CatalogScreen4Result                       // Result display
)

// CatalogV2Model is the enhanced catalog model with 3-screen workflow.
type CatalogV2Model struct {
	styles  Styles
	catalog *catalog.Catalog

	// Current screen
	screen CatalogScreen

	// Screen 1: Groups
	groups       []*catalog.ServiceGroup
	groupCursor  int
	groupScroll  int
	domainFilter catalog.Domain // "" = all
	searchQuery  string
	searchMode   bool

	// Screen 2: Targets
	selectedGroup *catalog.ServiceGroup
	targetCursor  int
	targetScroll  int

	// Screen 3: Config
	selectedEntry *catalog.Entry
	configIP      string
	configPort    string
	configTag     string  // For symbol_path entries
	configField   int     // 0=IP, 1=Port, 2=Tag

	// Screen 4: Result / Running
	running     bool
	startTime   time.Time
	result      string
	resultError string

	// Layout
	width  int
	height int
}

// NewCatalogV2Model creates a new enhanced catalog model.
func NewCatalogV2Model(styles Styles) *CatalogV2Model {
	m := &CatalogV2Model{
		styles:     styles,
		screen:     CatalogScreen1Groups,
		configPort: "44818",
		width:      100,
		height:     30,
	}
	m.loadCatalog()
	return m
}

func (m *CatalogV2Model) loadCatalog() {
	// Find catalog
	cwd, _ := os.Getwd()
	path, err := catalog.FindCoreCatalog(cwd)
	if err != nil {
		// Try relative to executable
		exe, _ := os.Executable()
		if exe != "" {
			path, err = catalog.FindCoreCatalog(filepath.Dir(exe))
		}
	}

	if err != nil {
		m.groups = nil
		return
	}

	file, err := catalog.Load(path)
	if err != nil {
		return
	}

	m.catalog = catalog.NewCatalog(file)
	m.updateGroups()
}

func (m *CatalogV2Model) updateGroups() {
	if m.catalog == nil {
		m.groups = nil
		return
	}

	if m.domainFilter != "" {
		m.groups = m.catalog.GroupsByDomain(m.domainFilter)
	} else {
		m.groups = m.catalog.Groups()
	}
}

// Update handles key events.
func (m *CatalogV2Model) Update(msg tea.KeyMsg) (*CatalogV2Model, tea.Cmd) {
	// Handle search mode
	if m.searchMode {
		return m.handleSearchInput(msg)
	}

	switch m.screen {
	case CatalogScreen1Groups:
		return m.updateScreen1(msg)
	case CatalogScreen2Targets:
		return m.updateScreen2(msg)
	case CatalogScreen3Config:
		return m.updateScreen3(msg)
	case CatalogScreen4Result:
		return m.updateScreen4(msg)
	}

	return m, nil
}

func (m *CatalogV2Model) handleSearchInput(msg tea.KeyMsg) (*CatalogV2Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.searchMode = false
		m.searchQuery = ""
		m.updateGroups() // Reset to full list
		m.groupCursor = 0
		m.groupScroll = 0
	case "enter":
		m.searchMode = false
		m.applySearchFilter()
	case "backspace":
		if len(m.searchQuery) > 0 {
			m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
		}
		// Live filter as user types
		m.applySearchFilter()
	default:
		if len(msg.String()) == 1 {
			m.searchQuery += msg.String()
		}
		// Live filter as user types
		m.applySearchFilter()
	}
	return m, nil
}

// applySearchFilter filters groups based on search query.
func (m *CatalogV2Model) applySearchFilter() {
	if m.catalog == nil {
		return
	}

	if m.searchQuery == "" {
		m.updateGroups()
		m.groupCursor = 0
		m.groupScroll = 0
		return
	}

	query := strings.ToLower(m.searchQuery)

	// Get all groups (respecting domain filter)
	var allGroups []*catalog.ServiceGroup
	if m.domainFilter != "" {
		allGroups = m.catalog.GroupsByDomain(m.domainFilter)
	} else {
		allGroups = m.catalog.Groups()
	}

	// Filter groups by search query
	var filtered []*catalog.ServiceGroup
	for _, g := range allGroups {
		// Match against service name, object name, or entry names/keys
		if strings.Contains(strings.ToLower(g.ServiceName), query) ||
			strings.Contains(strings.ToLower(g.ObjectName), query) {
			filtered = append(filtered, g)
			continue
		}

		// Check entries within the group
		for _, e := range g.Entries {
			if strings.Contains(strings.ToLower(e.Key), query) ||
				strings.Contains(strings.ToLower(e.Name), query) ||
				strings.Contains(strings.ToLower(e.Description), query) {
				filtered = append(filtered, g)
				break
			}
		}
	}

	m.groups = filtered
	m.groupCursor = 0
	m.groupScroll = 0
}

func (m *CatalogV2Model) updateScreen1(msg tea.KeyMsg) (*CatalogV2Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.groupCursor > 0 {
			m.groupCursor--
			m.adjustGroupScroll()
		}
	case "down", "j":
		if m.groupCursor < len(m.groups)-1 {
			m.groupCursor++
			m.adjustGroupScroll()
		}
	case "enter":
		// Go to Screen 2 (targets)
		if m.groupCursor < len(m.groups) {
			m.selectedGroup = m.groups[m.groupCursor]
			// If group has only one entry with no targets, skip to Screen 3
			if len(m.selectedGroup.Entries) == 1 && !m.selectedGroup.Entries[0].HasTargets() {
				m.selectedEntry = m.selectedGroup.Entries[0]
				m.screen = CatalogScreen3Config
			} else {
				m.targetCursor = 0
				m.targetScroll = 0
				m.screen = CatalogScreen2Targets
			}
		}
	case "t":
		// Quick test - use first entry in group
		if m.groupCursor < len(m.groups) && len(m.groups[m.groupCursor].Entries) > 0 {
			m.selectedGroup = m.groups[m.groupCursor]
			m.selectedEntry = m.selectedGroup.Entries[0]
			m.screen = CatalogScreen3Config
		}
	case "/":
		m.searchMode = true
		m.searchQuery = ""
	case "f":
		// Cycle domain filter
		switch m.domainFilter {
		case "":
			m.domainFilter = catalog.DomainCore
		case catalog.DomainCore:
			m.domainFilter = catalog.DomainLogix
		case catalog.DomainLogix:
			m.domainFilter = catalog.DomainLegacy
		case catalog.DomainLegacy:
			m.domainFilter = ""
		}
		m.updateGroups()
		m.groupCursor = 0
		m.groupScroll = 0
	case "esc":
		// Clear filter
		if m.domainFilter != "" {
			m.domainFilter = ""
			m.updateGroups()
			m.groupCursor = 0
		}
	}
	return m, nil
}

func (m *CatalogV2Model) updateScreen2(msg tea.KeyMsg) (*CatalogV2Model, tea.Cmd) {
	if m.selectedGroup == nil {
		return m, nil
	}

	switch msg.String() {
	case "up", "k":
		if m.targetCursor > 0 {
			m.targetCursor--
			m.adjustTargetScroll()
		}
	case "down", "j":
		if m.targetCursor < len(m.selectedGroup.Entries)-1 {
			m.targetCursor++
			m.adjustTargetScroll()
		}
	case "enter", "t":
		// Go to Screen 3 (config)
		if m.targetCursor < len(m.selectedGroup.Entries) {
			m.selectedEntry = m.selectedGroup.Entries[m.targetCursor]
			m.screen = CatalogScreen3Config
		}
	case "esc":
		// Back to Screen 1
		m.screen = CatalogScreen1Groups
		m.selectedGroup = nil
	}
	return m, nil
}

func (m *CatalogV2Model) updateScreen3(msg tea.KeyMsg) (*CatalogV2Model, tea.Cmd) {
	switch msg.String() {
	case "tab":
		m.configField = (m.configField + 1) % m.numConfigFields()
	case "shift+tab":
		m.configField = (m.configField + m.numConfigFields() - 1) % m.numConfigFields()
	case "enter":
		if m.configIP != "" && !m.running {
			return m, m.executeTest()
		}
	case "esc":
		// Back to previous screen
		if m.selectedGroup != nil && len(m.selectedGroup.Entries) > 1 {
			m.screen = CatalogScreen2Targets
		} else {
			m.screen = CatalogScreen1Groups
		}
	case "backspace":
		m.handleConfigBackspace()
	default:
		m.handleConfigInput(msg.String())
	}
	return m, nil
}

func (m *CatalogV2Model) updateScreen4(msg tea.KeyMsg) (*CatalogV2Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter":
		m.screen = CatalogScreen1Groups
		m.result = ""
		m.resultError = ""
	case "r":
		// Re-run
		if !m.running {
			return m, m.executeTest()
		}
	}
	return m, nil
}

func (m *CatalogV2Model) numConfigFields() int {
	if m.selectedEntry != nil && len(m.selectedEntry.RequiresInput) > 0 {
		return 3 // IP, Port, Tag
	}
	return 2 // IP, Port
}

func (m *CatalogV2Model) handleConfigBackspace() {
	switch m.configField {
	case 0:
		if len(m.configIP) > 0 {
			m.configIP = m.configIP[:len(m.configIP)-1]
		}
	case 1:
		if len(m.configPort) > 0 {
			m.configPort = m.configPort[:len(m.configPort)-1]
		}
	case 2:
		if len(m.configTag) > 0 {
			m.configTag = m.configTag[:len(m.configTag)-1]
		}
	}
}

func (m *CatalogV2Model) handleConfigInput(ch string) {
	if len(ch) != 1 {
		return
	}

	switch m.configField {
	case 0: // IP
		if ch == "." || (ch >= "0" && ch <= "9") {
			m.configIP += ch
		}
	case 1: // Port
		if ch >= "0" && ch <= "9" {
			m.configPort += ch
		}
	case 2: // Tag
		m.configTag += ch
	}
}

func (m *CatalogV2Model) executeTest() tea.Cmd {
	if m.selectedEntry == nil {
		return nil
	}

	entry := m.selectedEntry
	ip := m.configIP
	port := m.configPort
	tag := m.configTag

	m.running = true
	m.startTime = time.Now()
	m.result = ""
	m.resultError = ""
	m.screen = CatalogScreen4Result

	return func() tea.Msg {
		portNum := 44818
		if port != "" {
			fmt.Sscanf(port, "%d", &portNum)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client := cipclient.NewClient()
		if err := client.Connect(ctx, ip, portNum); err != nil {
			return TestResultMsg{Error: fmt.Sprintf("Connect: %v", err)}
		}
		defer client.Disconnect(ctx)

		// Build request from entry
		req := entry.ToCIPRequest()

		// Handle symbolic paths
		if entry.EPATH.Kind == catalog.EPATHSymbolic && tag != "" {
			req.RawPath = protocol.BuildSymbolicEPATH(tag)
		}

		start := time.Now()
		resp, err := client.InvokeService(ctx, req)
		rtt := time.Since(start).Seconds() * 1000

		if err != nil {
			return TestResultMsg{Error: fmt.Sprintf("Invoke: %v", err)}
		}

		return TestResultMsg{
			Result: fmt.Sprintf("Status=0x%02X Payload=%d bytes RTT=%.2fms", resp.Status, len(resp.Payload), rtt),
		}
	}
}

// HandleTestResult processes test result messages.
func (m *CatalogV2Model) HandleTestResult(msg TestResultMsg) {
	m.running = false
	m.result = msg.Result
	m.resultError = msg.Error
}

func (m *CatalogV2Model) adjustGroupScroll() {
	maxVisible := m.maxVisibleGroups()
	if m.groupCursor < m.groupScroll {
		m.groupScroll = m.groupCursor
	} else if m.groupCursor >= m.groupScroll+maxVisible {
		m.groupScroll = m.groupCursor - maxVisible + 1
	}
}

func (m *CatalogV2Model) adjustTargetScroll() {
	maxVisible := m.maxVisibleTargets()
	if m.targetCursor < m.targetScroll {
		m.targetScroll = m.targetCursor
	} else if m.targetCursor >= m.targetScroll+maxVisible {
		m.targetScroll = m.targetCursor - maxVisible + 1
	}
}

func (m *CatalogV2Model) maxVisibleGroups() int {
	return 18
}

func (m *CatalogV2Model) maxVisibleTargets() int {
	return 12
}

// View renders the catalog.
func (m *CatalogV2Model) View() string {
	if m.catalog == nil {
		return m.renderNoCatalog()
	}

	switch m.screen {
	case CatalogScreen1Groups:
		return m.renderScreen1()
	case CatalogScreen2Targets:
		return m.renderScreen2()
	case CatalogScreen3Config:
		return m.renderScreen3()
	case CatalogScreen4Result:
		return m.renderScreen4()
	}

	return ""
}

func (m *CatalogV2Model) renderNoCatalog() string {
	s := m.styles
	return s.Error.Render("Catalog not found. Ensure catalogs/core.yaml exists.")
}

func (m *CatalogV2Model) renderScreen1() string {
	s := m.styles
	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader("CIP Service Catalog"))
	b.WriteString("\n")

	// Filter bar
	b.WriteString(m.renderFilterBar())
	b.WriteString("\n\n")

	// Search mode
	if m.searchMode {
		b.WriteString(s.Header.Render("Search: ") + m.searchQuery + s.Cursor.Render("█"))
		b.WriteString("\n")
		b.WriteString(s.Dim.Render("Type to search, Enter to apply, Esc to cancel"))
		return b.String()
	}

	// Column headers
	header := fmt.Sprintf("  %-8s %-26s %-26s %s", "DOMAIN", "SERVICE", "OBJECT", "TARGETS")
	b.WriteString(s.Dim.Render(header))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render(strings.Repeat("─", 100)))
	b.WriteString("\n")

	// Groups
	maxVisible := m.maxVisibleGroups()
	for i := m.groupScroll; i < len(m.groups) && i < m.groupScroll+maxVisible; i++ {
		g := m.groups[i]

		cursor := "  "
		style := lipgloss.NewStyle()
		if i == m.groupCursor {
			cursor = s.Selected.Render("> ")
			style = s.Selected
		}

		service := fmt.Sprintf("%s 0x%02X", g.ServiceName, g.ServiceCode)
		object := fmt.Sprintf("%s 0x%02X", g.ObjectName, g.ObjectClass)
		targets := g.TargetPreview(3)

		line := fmt.Sprintf("%-8s %-26s %-26s %s",
			g.Domain, truncateString(service, 24), truncateString(object, 24), targets)

		b.WriteString(cursor + style.Render(line))
		b.WriteString("\n")
	}

	// Scroll indicator
	if len(m.groups) > maxVisible {
		b.WriteString("\n")
		b.WriteString(s.Dim.Render(fmt.Sprintf("  %d/%d groups", m.groupCursor+1, len(m.groups))))
	}

	return b.String()
}

func (m *CatalogV2Model) renderScreen2() string {
	s := m.styles
	var b strings.Builder

	if m.selectedGroup == nil {
		return ""
	}

	g := m.selectedGroup

	// Header with service info
	header := fmt.Sprintf("Select Target - %s 0x%02X on %s 0x%02X",
		g.ServiceName, g.ServiceCode, g.ObjectName, g.ObjectClass)
	b.WriteString(m.renderHeader(header))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render(fmt.Sprintf("Domain: %s", g.Domain)))
	b.WriteString("\n\n")

	// Two-column layout: targets | EPATH preview
	leftWidth := 50
	rightWidth := 45

	// Build left column (targets)
	var leftLines []string
	leftLines = append(leftLines, s.Dim.Render(fmt.Sprintf("  %-6s %-24s %s", "ATTR", "NAME", "TYPE")))
	leftLines = append(leftLines, s.Dim.Render(strings.Repeat("─", leftWidth)))

	maxVisible := m.maxVisibleTargets()
	for i := m.targetScroll; i < len(g.Entries) && i < m.targetScroll+maxVisible; i++ {
		e := g.Entries[i]

		cursor := "  "
		style := lipgloss.NewStyle()
		if i == m.targetCursor {
			cursor = s.Selected.Render("> ")
			style = s.Selected
		}

		attr := "-"
		if e.EPATH.Attribute != 0 {
			attr = fmt.Sprintf("0x%02X", e.EPATH.Attribute)
		}

		dataType := ""
		if desc := e.Description; desc != "" {
			// Extract type hint from description if present
			if idx := strings.LastIndex(desc, "("); idx > 0 {
				dataType = strings.Trim(desc[idx:], "()")
			}
		}

		line := fmt.Sprintf("%-6s %-24s %s", attr, truncateString(e.Name, 22), dataType)
		leftLines = append(leftLines, cursor+style.Render(line))
	}

	// Build right column (EPATH preview)
	var rightLines []string
	rightLines = append(rightLines, s.Header.Render("EPATH Preview"))
	rightLines = append(rightLines, s.Dim.Render(strings.Repeat("─", rightWidth)))

	if m.targetCursor < len(g.Entries) {
		e := g.Entries[m.targetCursor]
		rightLines = append(rightLines, "")
		rightLines = append(rightLines, s.Dim.Render("Parsed:"))
		rightLines = append(rightLines, fmt.Sprintf("  Class 0x%02X (%s)", e.ObjectClass, e.ObjectName))
		if e.EPATH.Instance != 0 {
			rightLines = append(rightLines, fmt.Sprintf("  Instance 0x%02X", e.EPATH.Instance))
		}
		if e.EPATH.Attribute != 0 {
			rightLines = append(rightLines, fmt.Sprintf("  Attribute 0x%02X (%s)", e.EPATH.Attribute, e.Name))
		}
		rightLines = append(rightLines, "")
		rightLines = append(rightLines, s.Dim.Render("Hex:"))
		rightLines = append(rightLines, fmt.Sprintf("  %s", m.formatEPATHHex(e)))
		rightLines = append(rightLines, "")
		rightLines = append(rightLines, s.Dim.Render(fmt.Sprintf("Kind: %s", e.EPATH.Kind)))
	}

	// Combine columns
	maxLines := max(len(leftLines), len(rightLines))
	for i := 0; i < maxLines; i++ {
		left := ""
		right := ""
		if i < len(leftLines) {
			left = leftLines[i]
		}
		if i < len(rightLines) {
			right = rightLines[i]
		}

		// Pad left column
		leftPadded := left + strings.Repeat(" ", leftWidth-lipgloss.Width(left))
		b.WriteString(leftPadded + " │ " + right)
		b.WriteString("\n")
	}

	return b.String()
}

func (m *CatalogV2Model) renderScreen3() string {
	s := m.styles
	var b strings.Builder

	if m.selectedEntry == nil {
		return ""
	}

	e := m.selectedEntry

	// Header
	header := fmt.Sprintf("Configure Request - %s", e.Name)
	b.WriteString(m.renderHeader(header))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render(fmt.Sprintf("Service: %s (0x%02X)  Object: %s (0x%02X)",
		e.ServiceName, e.ServiceCode, e.ObjectName, e.ObjectClass)))
	if e.EPATH.Attribute != 0 {
		b.WriteString(s.Dim.Render(fmt.Sprintf("  Attr: 0x%02X", e.EPATH.Attribute)))
	}
	b.WriteString("\n")
	b.WriteString(s.Dim.Render(fmt.Sprintf("Domain: %s", e.Domain)))
	b.WriteString("\n\n")

	cursor := s.Cursor.Render("█")

	// Target IP
	ipLabel := s.Dim.Render("Target IP")
	if m.configField == 0 {
		ipLabel = s.Selected.Render("Target IP")
		b.WriteString(ipLabel + ":   " + m.configIP + cursor)
	} else {
		b.WriteString(ipLabel + ":   " + m.configIP)
	}
	b.WriteString("\n")

	// Port
	portLabel := s.Dim.Render("Port")
	if m.configField == 1 {
		portLabel = s.Selected.Render("Port")
		b.WriteString(portLabel + ":        " + m.configPort + cursor)
	} else {
		b.WriteString(portLabel + ":        " + m.configPort)
	}
	b.WriteString("\n")

	// Tag (if required)
	if len(e.RequiresInput) > 0 {
		tagLabel := s.Dim.Render("Tag/Symbol")
		if m.configField == 2 {
			tagLabel = s.Selected.Render("Tag/Symbol")
			b.WriteString(tagLabel + ": " + m.configTag + cursor)
		} else {
			b.WriteString(tagLabel + ": " + m.configTag)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")

	// EPATH Preview
	b.WriteString(s.Header.Render("EPATH Preview"))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render(strings.Repeat("─", 60)))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render("Parsed: "))
	b.WriteString(m.formatEPATHParsed(e))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render("Hex:    "))
	b.WriteString(m.formatEPATHHex(e))
	b.WriteString("\n\n")

	// Instructions
	b.WriteString(s.Dim.Render("Tab to navigate, Enter to execute, Esc to go back"))

	return b.String()
}

func (m *CatalogV2Model) renderScreen4() string {
	s := m.styles
	var b strings.Builder

	if m.selectedEntry == nil {
		return ""
	}

	e := m.selectedEntry

	// Header
	header := fmt.Sprintf("Result - %s", e.Name)
	b.WriteString(m.renderHeader(header))
	b.WriteString("\n")
	b.WriteString(s.Dim.Render(fmt.Sprintf("Target: %s:%s", m.configIP, m.configPort)))
	b.WriteString("\n\n")

	if m.running {
		elapsed := time.Since(m.startTime).Seconds()
		b.WriteString(s.Info.Render(fmt.Sprintf("Running... %.1fs", elapsed)))
	} else if m.resultError != "" {
		b.WriteString(s.Error.Render("Error: ") + m.resultError)
	} else if m.result != "" {
		b.WriteString(s.Success.Render("Success: ") + m.result)
	}

	b.WriteString("\n\n")
	b.WriteString(s.Dim.Render("Press Enter/Esc to return, r to re-run"))

	return b.String()
}

func (m *CatalogV2Model) renderHeader(title string) string {
	s := m.styles
	titleStyle := lipgloss.NewStyle().
		Foreground(DefaultTheme.Purple).
		Bold(true)

	return titleStyle.Render(title) + "\n" + s.Dim.Render(strings.Repeat("─", 100))
}

func (m *CatalogV2Model) renderFilterBar() string {
	s := m.styles

	var parts []string
	domains := []struct{ name string; domain catalog.Domain }{
		{"All", ""},
		{"Core", catalog.DomainCore},
		{"Logix", catalog.DomainLogix},
		{"Legacy", catalog.DomainLegacy},
	}

	for _, d := range domains {
		if d.domain == m.domainFilter {
			parts = append(parts, s.Selected.Render("["+d.name+"]"))
		} else {
			parts = append(parts, s.Dim.Render(d.name))
		}
	}

	return "Domain: " + strings.Join(parts, " | ") + "  " + s.Dim.Render(fmt.Sprintf("(%d groups)", len(m.groups)))
}

func (m *CatalogV2Model) formatEPATHParsed(e *catalog.Entry) string {
	var parts []string

	if e.EPATH.Class != 0 {
		parts = append(parts, fmt.Sprintf("Class 0x%02X (%s)", e.EPATH.Class, e.ObjectName))
	}
	if e.EPATH.Instance != 0 {
		parts = append(parts, fmt.Sprintf("Instance 0x%02X", e.EPATH.Instance))
	}
	if e.EPATH.Attribute != 0 {
		parts = append(parts, fmt.Sprintf("Attribute 0x%02X (%s)", e.EPATH.Attribute, e.Name))
	}

	return strings.Join(parts, " -> ")
}

func (m *CatalogV2Model) formatEPATHHex(e *catalog.Entry) string {
	// Build EPATH hex manually
	var bytes []byte

	if e.EPATH.Kind == catalog.EPATHSymbolic {
		return "<symbolic - built at runtime>"
	}

	// Class segment
	if e.EPATH.Class != 0 {
		if e.EPATH.Class <= 0xFF {
			bytes = append(bytes, 0x20, byte(e.EPATH.Class))
		} else {
			bytes = append(bytes, 0x21, 0x00, byte(e.EPATH.Class), byte(e.EPATH.Class>>8))
		}
	}

	// Instance segment
	if e.EPATH.Instance != 0 {
		if e.EPATH.Instance <= 0xFF {
			bytes = append(bytes, 0x24, byte(e.EPATH.Instance))
		} else {
			bytes = append(bytes, 0x25, 0x00, byte(e.EPATH.Instance), byte(e.EPATH.Instance>>8))
		}
	}

	// Attribute segment
	if e.EPATH.Attribute != 0 {
		if e.EPATH.Attribute <= 0xFF {
			bytes = append(bytes, 0x30, byte(e.EPATH.Attribute))
		} else {
			bytes = append(bytes, 0x31, 0x00, byte(e.EPATH.Attribute), byte(e.EPATH.Attribute>>8))
		}
	}

	// Format as hex string
	var hexParts []string
	for _, b := range bytes {
		hexParts = append(hexParts, fmt.Sprintf("%02X", b))
	}

	return strings.Join(hexParts, " ")
}

// Footer returns footer hints.
func (m *CatalogV2Model) Footer() string {
	switch m.screen {
	case CatalogScreen1Groups:
		if m.searchMode {
			return KeyHints([]KeyHint{
				{"Enter", "Apply"},
				{"Esc", "Cancel"},
			}, m.styles)
		}
		return KeyHints([]KeyHint{
			{"/", "Search"},
			{"f", "Filter"},
			{"Enter", "Select"},
			{"t", "Quick Test"},
			{"j/k", "Navigate"},
		}, m.styles)
	case CatalogScreen2Targets:
		return KeyHints([]KeyHint{
			{"Enter/t", "Test"},
			{"j/k", "Navigate"},
			{"Esc", "Back"},
		}, m.styles)
	case CatalogScreen3Config:
		return KeyHints([]KeyHint{
			{"Tab", "Next field"},
			{"Enter", "Execute"},
			{"Esc", "Back"},
		}, m.styles)
	case CatalogScreen4Result:
		return KeyHints([]KeyHint{
			{"r", "Re-run"},
			{"Enter/Esc", "Back"},
		}, m.styles)
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
