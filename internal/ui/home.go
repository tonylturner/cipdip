package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// HomeActions lists the selectable quick actions.
func HomeActions() []string {
	return []string{
		"New Run (Wizard)",
		"Run Existing Config",
		"Baseline (Guided)",
		"Start Server Emulator",
		"Single Request",
		"Test Plan Builder",
		"Workspace",
		"Explore CIP Catalog",
	}
}

// RenderHomeScreen builds a simple home screen view for non-interactive runs.
func RenderHomeScreen(workspaceName string, profiles []ProfileInfo, runs []string, palette []PaletteItem) string {
	return renderHomeScreen(workspaceName, profiles, runs, palette, -1, "")
}

// RenderHomeScreenWithCursor renders the home screen with a highlighted quick action.
func RenderHomeScreenWithCursor(workspaceName string, profiles []ProfileInfo, runs []string, palette []PaletteItem, cursor int, status string) string {
	return renderHomeScreen(workspaceName, profiles, runs, palette, cursor, status)
}

func renderHomeScreen(workspaceName string, profiles []ProfileInfo, runs []string, palette []PaletteItem, cursor int, status string) string {
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	sectionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	lines := []string{
		titleStyle.Render(fmt.Sprintf("cipdip UI | Workspace: %s", workspaceName)),
		"",
		sectionStyle.Render("Quick Actions:"),
	}
	for i, action := range HomeActions() {
		prefix := "  - "
		if cursor >= 0 && i == cursor {
			prefix = "> "
		}
		lines = append(lines, fmt.Sprintf("%s%s", prefix, action))
	}
	if strings.TrimSpace(status) != "" {
		lines = append(lines, "", status)
	}
	lines = append(lines, "", "Tip: press / to search, p for palette")
	return frameStyle.Render(strings.Join(lines, "\n"))
}

// RenderCatalogExplorer renders a catalog view with hex fields visible.
func RenderCatalogExplorer(entries []CatalogEntry, query string, sources []string) string {
	filtered := FilterCatalogEntries(entries, query)
	sourceLabel := "(none)"
	if len(sources) > 0 {
		sourceLabel = strings.Join(sources, ", ")
	}
	lines := []string{
		"CIP Catalog",
		fmt.Sprintf("Search: %s", query),
		fmt.Sprintf("Sources: %s", sourceLabel),
		"",
	}
	if len(filtered) == 0 {
		lines = append(lines, "(no catalog entries)")
		return strings.Join(lines, "\n")
	}
	for _, entry := range filtered {
		lines = append(lines, fmt.Sprintf("%s (%s)", entry.Name, entry.Key))
		lines = append(lines, fmt.Sprintf("  Service: %s  Class: %s  Instance: %s  Attribute: %s", entry.Service, entry.Class, entry.Instance, entry.Attribute))
	}
	return strings.Join(lines, "\n")
}

// RenderPaletteView formats palette entries for display.
func RenderPaletteView(items []PaletteItem) string {
	lines := []string{"Palette"}
	if len(items) == 0 {
		lines = append(lines, "(no items)")
		return strings.Join(lines, "\n")
	}
	for _, item := range items {
		lines = append(lines, item.String())
	}
	return strings.Join(lines, "\n")
}
