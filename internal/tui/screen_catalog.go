package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tturner/cipdip/internal/app"
	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

// CatalogScreenModel handles the full-screen catalog view.
type CatalogScreenModel struct {
	state  *AppState
	styles Styles
	cursor int
	search string
	mode   string // "browse", "search", "test", "result"

	// Filtering
	filter     int // 0=all, 1=vendor, 2=core
	filterText string

	// Test mode
	testIP       string
	testPort     string
	testPayload  string
	testField    int // 0=IP, 1=port, 2=payload
	testRunning  bool
	testResult   string
	testError    string

	// Filtered entries (for cursor mapping)
	filteredEntries []app.CatalogEntry
}

// NewCatalogScreenModel creates a new catalog screen.
func NewCatalogScreenModel(state *AppState, styles Styles) *CatalogScreenModel {
	m := &CatalogScreenModel{
		state:    state,
		styles:   styles,
		mode:     "browse",
		testPort: "44818",
	}
	m.updateFilteredEntries()
	return m
}

// updateFilteredEntries rebuilds the filtered entry list based on current filter/search.
func (m *CatalogScreenModel) updateFilteredEntries() {
	m.filteredEntries = nil
	for _, entry := range m.state.Catalog {
		// Apply scope filter
		if m.filter == 1 && entry.Scope != "vendor" {
			continue
		}
		if m.filter == 2 && entry.Scope == "vendor" {
			continue
		}
		// Apply text search
		if m.filterText != "" {
			q := strings.ToLower(m.filterText)
			if !strings.Contains(strings.ToLower(entry.Name), q) &&
				!strings.Contains(strings.ToLower(entry.Key), q) &&
				!strings.Contains(strings.ToLower(entry.Service), q) &&
				!strings.Contains(strings.ToLower(entry.Class), q) &&
				!strings.Contains(strings.ToLower(entry.Notes), q) {
				continue
			}
		}
		m.filteredEntries = append(m.filteredEntries, entry)
	}
}

// Update handles input for the catalog screen.
func (m *CatalogScreenModel) Update(msg tea.KeyMsg) (*CatalogScreenModel, tea.Cmd) {
	// Handle search mode input
	if m.mode == "search" {
		switch msg.String() {
		case "esc":
			m.mode = "browse"
			m.search = ""
		case "enter":
			m.mode = "browse"
			m.filterText = m.search
			m.updateFilteredEntries()
			m.cursor = 0
		case "backspace":
			if len(m.search) > 0 {
				m.search = m.search[:len(m.search)-1]
			}
		default:
			if len(msg.String()) == 1 {
				m.search += msg.String()
			}
		}
		return m, nil
	}

	// Handle test mode input
	if m.mode == "test" {
		switch msg.String() {
		case "esc":
			m.mode = "browse"
			m.testResult = ""
			m.testError = ""
		case "tab":
			m.testField = (m.testField + 1) % 3
		case "shift+tab":
			m.testField = (m.testField + 2) % 3
		case "enter":
			if !m.testRunning && m.testIP != "" {
				return m, m.executeTest()
			}
		case "backspace":
			switch m.testField {
			case 0:
				if len(m.testIP) > 0 {
					m.testIP = m.testIP[:len(m.testIP)-1]
				}
			case 1:
				if len(m.testPort) > 0 {
					m.testPort = m.testPort[:len(m.testPort)-1]
				}
			case 2:
				if len(m.testPayload) > 0 {
					m.testPayload = m.testPayload[:len(m.testPayload)-1]
				}
			}
		default:
			ch := msg.String()
			if len(ch) == 1 {
				switch m.testField {
				case 0: // IP - allow digits and dots
					if ch == "." || (ch >= "0" && ch <= "9") {
						m.testIP += ch
					}
				case 1: // Port - digits only
					if ch >= "0" && ch <= "9" {
						m.testPort += ch
					}
				case 2: // Payload hex - hex chars only
					ch = strings.ToUpper(ch)
					if (ch >= "0" && ch <= "9") || (ch >= "A" && ch <= "F") || ch == " " {
						m.testPayload += ch
					}
				}
			}
		}
		return m, nil
	}

	// Handle result mode
	if m.mode == "result" {
		switch msg.String() {
		case "esc", "enter":
			m.mode = "browse"
			m.testResult = ""
			m.testError = ""
		case "r":
			// Re-run
			return m, m.executeTest()
		}
		return m, nil
	}

	// Browse mode
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.filteredEntries)-1 {
			m.cursor++
		}
	case "/":
		m.mode = "search"
		m.search = ""
	case "esc":
		if m.filterText != "" {
			m.filterText = ""
			m.filter = 0
			m.updateFilteredEntries()
			m.cursor = 0
		}
	case "enter", "t":
		// Enter test mode for selected entry
		if len(m.filteredEntries) > 0 && m.cursor < len(m.filteredEntries) {
			entry := m.filteredEntries[m.cursor]
			m.mode = "test"
			m.testField = 0
			m.testPayload = entry.PayloadHex
			m.testResult = ""
			m.testError = ""
		}
	case "y":
		// Copy EPATH to clipboard (TODO: implement)
	case "0":
		m.filter = 0
		m.filterText = ""
		m.updateFilteredEntries()
		m.cursor = 0
	case "1":
		m.filter = 1
		m.updateFilteredEntries()
		m.cursor = 0
	case "2":
		m.filter = 2
		m.updateFilteredEntries()
		m.cursor = 0
	}
	return m, nil
}

// TestResultMsg carries the result of a test execution.
type TestResultMsg struct {
	Result string
	Error  string
}

// executeTest runs a single CIP request for the selected catalog entry.
func (m *CatalogScreenModel) executeTest() tea.Cmd {
	if m.cursor >= len(m.filteredEntries) {
		return nil
	}
	entry := m.filteredEntries[m.cursor]
	ip := m.testIP
	port := m.testPort
	payload := m.testPayload

	m.testRunning = true
	m.testResult = ""
	m.testError = ""

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

		// Build request
		req, err := buildTestRequest(entry, payload)
		if err != nil {
			return TestResultMsg{Error: fmt.Sprintf("Build: %v", err)}
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
func (m *CatalogScreenModel) HandleTestResult(msg TestResultMsg) {
	m.testRunning = false
	m.testResult = msg.Result
	m.testError = msg.Error
	if m.testResult != "" || m.testError != "" {
		m.mode = "result"
	}
}

// buildTestRequest constructs a CIP request from a catalog entry.
func buildTestRequest(entry app.CatalogEntry, payloadHex string) (protocol.CIPRequest, error) {
	service, err := parseHexValue(entry.Service)
	if err != nil {
		return protocol.CIPRequest{}, fmt.Errorf("parse service: %w", err)
	}
	class, err := parseHexValue(entry.Class)
	if err != nil {
		return protocol.CIPRequest{}, fmt.Errorf("parse class: %w", err)
	}
	instance, err := parseHexValue(entry.Instance)
	if err != nil {
		return protocol.CIPRequest{}, fmt.Errorf("parse instance: %w", err)
	}
	attribute := uint64(0)
	if entry.Attribute != "" {
		attribute, err = parseHexValue(entry.Attribute)
		if err != nil {
			return protocol.CIPRequest{}, fmt.Errorf("parse attribute: %w", err)
		}
	}

	req := protocol.CIPRequest{
		Service: protocol.CIPServiceCode(service),
		Path: protocol.CIPPath{
			Class:     uint16(class),
			Instance:  uint16(instance),
			Attribute: uint16(attribute),
			Name:      entry.Key,
		},
	}

	// Add payload if specified
	if payloadHex != "" {
		payload, err := parseHexPayload(payloadHex)
		if err != nil {
			return req, fmt.Errorf("parse payload: %w", err)
		}
		req.Payload = payload
	}

	return req, nil
}

// parseHexValue parses a hex string like "0x0E" or "0E" to uint64.
func parseHexValue(s string) (uint64, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	s = strings.TrimPrefix(s, "0X")
	var val uint64
	_, err := fmt.Sscanf(s, "%x", &val)
	return val, err
}

// parseHexPayload parses a hex string to bytes.
func parseHexPayload(s string) ([]byte, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%x", &b)
		if err != nil {
			return nil, err
		}
		result[i/2] = b
	}
	return result, nil
}

// View renders the catalog screen.
func (m *CatalogScreenModel) View() string {
	fullWidth := 118
	s := m.styles

	header := m.renderHeader(fullWidth)

	var lines []string

	// Filter/search bar
	filterBar := m.renderFilterBar(s)
	lines = append(lines, filterBar)
	lines = append(lines, "")

	// Handle different modes
	switch m.mode {
	case "test":
		lines = append(lines, m.renderTestMode(s)...)
	case "result":
		lines = append(lines, m.renderResultMode(s)...)
	case "search":
		lines = append(lines, s.Header.Render("Search: ")+m.search+s.Cursor.Render("█"))
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render("Type to search, Enter to filter, Esc to cancel"))
	default:
		// Browse mode - catalog content
		lines = append(lines, m.renderCatalogContent(s)...)
	}

	content := strings.Join(lines, "\n")

	// Build box
	innerWidth := fullWidth - 4
	var result strings.Builder
	result.WriteString(header + "\n\n")

	for _, line := range strings.Split(content, "\n") {
		lineWidth := lipgloss.Width(line)
		if lineWidth < innerWidth {
			line += strings.Repeat(" ", innerWidth-lineWidth)
		}
		result.WriteString(line + "\n")
	}

	outerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(DefaultTheme.Border).
		Padding(0, 1)

	return outerStyle.Render(result.String())
}

// renderTestMode renders the test configuration screen.
func (m *CatalogScreenModel) renderTestMode(s Styles) []string {
	var lines []string

	if m.cursor >= len(m.filteredEntries) {
		return lines
	}
	entry := m.filteredEntries[m.cursor]

	// Entry info header
	lines = append(lines, s.Header.Render("Test: "+entry.Name))
	lines = append(lines, "")

	// EPATH tuple
	epath := fmt.Sprintf("%s/%s/%s", entry.Service, entry.Class, entry.Instance)
	if entry.Attribute != "" {
		epath += "/" + entry.Attribute
	}
	serviceName := "Unknown"
	if svc, err := parseHexValue(entry.Service); err == nil {
		serviceName = spec.ServiceName(protocol.CIPServiceCode(svc))
	}
	lines = append(lines, s.Dim.Render("Path: ")+s.Info.Render(epath)+"  "+s.Dim.Render(serviceName))
	lines = append(lines, "")

	// Input fields
	cursor := s.Cursor.Render("█")

	ipLabel := s.Dim.Render("Target IP")
	portLabel := s.Dim.Render("Port")
	payloadLabel := s.Dim.Render("Payload (hex)")

	if m.testField == 0 {
		ipLabel = s.Selected.Render("Target IP")
		lines = append(lines, ipLabel+":    "+m.testIP+cursor)
	} else {
		lines = append(lines, ipLabel+":    "+m.testIP)
	}

	if m.testField == 1 {
		portLabel = s.Selected.Render("Port")
		lines = append(lines, portLabel+":        "+m.testPort+cursor)
	} else {
		lines = append(lines, portLabel+":        "+m.testPort)
	}

	lines = append(lines, "")

	if m.testField == 2 {
		payloadLabel = s.Selected.Render("Payload (hex)")
		lines = append(lines, payloadLabel+": "+m.testPayload+cursor)
	} else {
		payloadLine := payloadLabel + ": "
		if m.testPayload != "" {
			payloadLine += m.testPayload
		} else {
			payloadLine += s.Dim.Render("(none)")
		}
		lines = append(lines, payloadLine)
	}

	lines = append(lines, "")
	if m.testRunning {
		lines = append(lines, s.Info.Render("Sending request..."))
	} else {
		lines = append(lines, s.Dim.Render("Tab to navigate, Enter to send, Esc to cancel"))
	}

	return lines
}

// renderResultMode renders the test result.
func (m *CatalogScreenModel) renderResultMode(s Styles) []string {
	var lines []string

	if m.cursor >= len(m.filteredEntries) {
		return lines
	}
	entry := m.filteredEntries[m.cursor]

	lines = append(lines, s.Header.Render("Result: "+entry.Name))
	lines = append(lines, "")

	// EPATH tuple
	epath := fmt.Sprintf("%s/%s/%s", entry.Service, entry.Class, entry.Instance)
	if entry.Attribute != "" {
		epath += "/" + entry.Attribute
	}
	lines = append(lines, s.Dim.Render("Path: ")+s.Info.Render(epath))
	lines = append(lines, s.Dim.Render("Target: ")+m.testIP+":"+m.testPort)
	lines = append(lines, "")

	if m.testError != "" {
		lines = append(lines, s.Error.Render("Error: ")+m.testError)
	} else if m.testResult != "" {
		lines = append(lines, s.Success.Render("Success: ")+m.testResult)
	}

	lines = append(lines, "")
	lines = append(lines, s.Dim.Render("Press Enter/Esc to return, r to re-run"))

	return lines
}

func (m *CatalogScreenModel) renderFilterBar(s Styles) string {
	filters := []string{"All", "Vendor", "Core"}
	var parts []string
	for i, f := range filters {
		if i == m.filter {
			parts = append(parts, s.Selected.Render("["+f+"]"))
		} else {
			parts = append(parts, s.Dim.Render(f))
		}
	}
	filterLine := "Filter: " + strings.Join(parts, " | ")

	if m.filterText != "" {
		filterLine += "  " + s.Info.Render("Search: "+m.filterText)
	}

	filterLine += "  " + s.Dim.Render(fmt.Sprintf("(%d entries)", len(m.filteredEntries)))

	return filterLine
}

func (m *CatalogScreenModel) renderCatalogContent(s Styles) []string {
	var lines []string

	if len(m.filteredEntries) == 0 {
		lines = append(lines, s.Dim.Render("No catalog entries found."))
		if len(m.state.Catalog) == 0 {
			lines = append(lines, "")
			lines = append(lines, s.Dim.Render("Catalog is empty. Add entries via workspace/catalogs/*.yaml"))
		}
		return lines
	}

	// Column header
	header := fmt.Sprintf("  %-24s %-22s %-30s", "EPATH", "Service", "Name")
	lines = append(lines, s.Dim.Render(header))
	lines = append(lines, s.Dim.Render(strings.Repeat("─", 80)))

	// Render entries
	maxVisible := 20 // Show max entries to avoid overflow
	startIdx := 0
	if m.cursor >= maxVisible {
		startIdx = m.cursor - maxVisible + 1
	}

	for i := startIdx; i < len(m.filteredEntries) && i < startIdx+maxVisible; i++ {
		entry := m.filteredEntries[i]

		// Build EPATH tuple
		epath := fmt.Sprintf("%s/%s/%s", entry.Service, entry.Class, entry.Instance)
		if entry.Attribute != "" && entry.Attribute != "0x00" {
			epath += "/" + entry.Attribute
		}

		// Get service name
		serviceName := ""
		if svc, err := parseHexValue(entry.Service); err == nil {
			serviceName = spec.ServiceName(protocol.CIPServiceCode(svc))
		}

		// Cursor and selection
		cursor := "  "
		nameStyle := lipgloss.NewStyle()
		if i == m.cursor {
			cursor = s.Selected.Render("> ")
			nameStyle = s.Selected
		}

		// Format entry line: EPATH | Service Name | Entry Name
		epathStr := fmt.Sprintf("%-22s", epath)
		serviceStr := fmt.Sprintf("%-22s", truncateString(serviceName, 20))
		nameStr := truncateString(entry.Name, 28)

		line := cursor + s.Info.Render(epathStr) + " " + s.Dim.Render(serviceStr) + " " + nameStyle.Render(nameStr)
		lines = append(lines, line)

		// Show scope/vendor as secondary info for selected item
		if i == m.cursor && (entry.Scope != "" || entry.Notes != "") {
			extra := "     "
			if entry.Scope != "" {
				extra += s.Dim.Render("["+entry.Scope+"]") + " "
			}
			if entry.Vendor != "" {
				extra += s.Dim.Render("vendor:"+entry.Vendor) + " "
			}
			if entry.Notes != "" {
				extra += s.Dim.Render(truncateString(entry.Notes, 50))
			}
			lines = append(lines, extra)
		}
	}

	// Scroll indicator
	if len(m.filteredEntries) > maxVisible {
		lines = append(lines, "")
		lines = append(lines, s.Dim.Render(fmt.Sprintf("  Showing %d-%d of %d (scroll with j/k)", startIdx+1, min(startIdx+maxVisible, len(m.filteredEntries)), len(m.filteredEntries))))
	}

	return lines
}

// truncateString truncates a string to max length with ellipsis.
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *CatalogScreenModel) renderHeader(width int) string {
	s := m.styles

	title := lipgloss.NewStyle().
		Foreground(DefaultTheme.Purple).
		Bold(true).
		Render("CATALOG")

	subtitle := s.Dim.Render("CIP Object Browser")

	count := s.Dim.Render(fmt.Sprintf("%d entries", len(m.state.Catalog)))

	left := title + "  " + subtitle
	right := count

	leftWidth := lipgloss.Width(left)
	rightWidth := lipgloss.Width(right)
	padding := width - leftWidth - rightWidth
	if padding < 1 {
		padding = 1
	}

	header := left + strings.Repeat(" ", padding) + right
	return header + "\n" + s.Muted.Render(strings.Repeat("─", width))
}

// Footer returns the footer text.
func (m *CatalogScreenModel) Footer() string {
	switch m.mode {
	case "search":
		return KeyHints([]KeyHint{
			{"Enter", "Apply"},
			{"Esc", "Cancel"},
		}, m.styles)
	case "test":
		return KeyHints([]KeyHint{
			{"Tab", "Next field"},
			{"Enter", "Send"},
			{"Esc", "Cancel"},
		}, m.styles)
	case "result":
		return KeyHints([]KeyHint{
			{"r", "Re-run"},
			{"Enter/Esc", "Back"},
		}, m.styles)
	default:
		return KeyHints([]KeyHint{
			{"/", "Search"},
			{"0/1/2", "Filter"},
			{"Enter/t", "Test"},
			{"j/k", "Navigate"},
			{"m", "Menu"},
		}, m.styles)
	}
}
