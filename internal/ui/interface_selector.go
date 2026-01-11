package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/netdetect"
)

// InterfaceEntry represents a network interface in the selector.
type InterfaceEntry struct {
	Name        string // System name (used for actual capture)
	DisplayName string // Human-readable name for UI
	Description string
	Addresses   []string
	IsLoopback  bool
	IsUp        bool
}

// InterfaceSelectorModel handles interface selection.
type InterfaceSelectorModel struct {
	Entries              []InterfaceEntry
	Cursor               int
	Selected             string // Selected interface name
	Status               string
	Loaded               bool
	CurrentAutoDetected  string // Currently auto-detected interface (for display)
}

// NewInterfaceSelectorModel creates a new interface selector.
func NewInterfaceSelectorModel() *InterfaceSelectorModel {
	return &InterfaceSelectorModel{}
}

// LoadInterfaces loads available network interfaces.
func (m *InterfaceSelectorModel) LoadInterfaces() error {
	interfaces, err := netdetect.ListInterfaces()
	if err != nil {
		m.Status = fmt.Sprintf("Error: %v", err)
		return err
	}

	m.Entries = make([]InterfaceEntry, 0)

	// Add "Auto-detect" as first option
	m.Entries = append(m.Entries, InterfaceEntry{
		Name:        "",
		Description: "Auto-detect based on target/listen IP",
	})

	for _, iface := range interfaces {
		entry := InterfaceEntry{
			Name:        iface.Name,
			DisplayName: iface.DisplayName,
			Description: iface.Description,
			Addresses:   iface.Addresses,
			IsLoopback:  iface.IsLoopback,
			IsUp:        iface.IsUp,
		}
		// Fallback to Name if DisplayName is empty
		if entry.DisplayName == "" {
			entry.DisplayName = entry.Name
		}
		m.Entries = append(m.Entries, entry)
	}

	m.Loaded = true
	m.Cursor = 0
	return nil
}

// Update handles input for the interface selector.
func (m *InterfaceSelectorModel) Update(msg tea.KeyMsg) (*InterfaceSelectorModel, tea.Cmd, bool) {
	switch msg.String() {
	case "esc":
		return m, nil, true // Signal to close without selection
	case "up", "k":
		if m.Cursor > 0 {
			m.Cursor--
		}
	case "down", "j":
		if m.Cursor < len(m.Entries)-1 {
			m.Cursor++
		}
	case "enter":
		if len(m.Entries) > 0 {
			m.Selected = m.Entries[m.Cursor].Name
			return m, nil, true // Signal selection complete
		}
	case "g", "home":
		m.Cursor = 0
	case "G", "end":
		m.Cursor = len(m.Entries) - 1
	}
	return m, nil, false
}

// View renders the interface selector.
func (m *InterfaceSelectorModel) View() string {
	var b strings.Builder

	// Header
	b.WriteString(headerStyle.Render("Select Network Interface"))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 70))
	b.WriteString("\n")

	// Show current auto-detected interface
	if m.CurrentAutoDetected != "" {
		b.WriteString(dimStyle.Render(fmt.Sprintf("Current auto-detected: %s", m.CurrentAutoDetected)))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if !m.Loaded {
		b.WriteString(dimStyle.Render("Loading interfaces..."))
		b.WriteString("\n")
		return borderStyle.Render(b.String())
	}

	if len(m.Entries) == 0 {
		b.WriteString(dimStyle.Render("No interfaces found"))
		b.WriteString("\n")
		return borderStyle.Render(b.String())
	}

	// Interface list with scrolling
	maxVisible := 12
	startIdx := 0
	if m.Cursor >= maxVisible {
		startIdx = m.Cursor - maxVisible + 1
	}
	endIdx := startIdx + maxVisible
	if endIdx > len(m.Entries) {
		endIdx = len(m.Entries)
	}

	for i := startIdx; i < endIdx; i++ {
		entry := m.Entries[i]
		prefix := "  "
		if i == m.Cursor {
			prefix = "> "
		}

		// Format interface info
		var line string
		if entry.Name == "" {
			// Auto-detect option
			line = fmt.Sprintf("%s[Auto] %s", prefix, entry.Description)
		} else {
			// Regular interface - use DisplayName for UI
			displayName := entry.DisplayName
			if displayName == "" {
				displayName = entry.Name
			}
			if len(displayName) > 25 {
				displayName = displayName[:22] + "..."
			}

			// Status indicator
			status := ""
			if entry.IsLoopback {
				status = "[lo]"
			} else if entry.IsUp {
				status = "[up]"
			} else {
				status = "[--]"
			}

			// Address info
			addrStr := ""
			if len(entry.Addresses) > 0 {
				addrStr = entry.Addresses[0]
				if len(entry.Addresses) > 1 {
					addrStr += fmt.Sprintf(" (+%d)", len(entry.Addresses)-1)
				}
			}

			line = fmt.Sprintf("%s%-25s %s %s", prefix, displayName, status, addrStr)
		}

		if i == m.Cursor {
			b.WriteString(selectedStyle.Render(line))
		} else if entry.Name == "" {
			b.WriteString(successStyle.Render(line))
		} else if !entry.IsUp && !entry.IsLoopback {
			b.WriteString(dimStyle.Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	// Scroll indicator
	if len(m.Entries) > maxVisible {
		b.WriteString(fmt.Sprintf("\n%s", dimStyle.Render(fmt.Sprintf("  ... %d of %d interfaces", m.Cursor+1, len(m.Entries)))))
	}

	// Status
	if m.Status != "" {
		b.WriteString("\n\n")
		b.WriteString(m.Status)
	}

	return borderStyle.Render(b.String())
}

// Footer returns the footer text for the interface selector.
func (m *InterfaceSelectorModel) Footer() string {
	return "↑↓/j/k: navigate    Enter: select    Esc: cancel"
}
