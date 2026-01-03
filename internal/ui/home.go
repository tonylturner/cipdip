package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// RenderHomeScreen builds a simple home screen view for non-interactive runs.
func RenderHomeScreen(workspaceName string, profiles []ProfileInfo, runs []string, palette []PaletteItem) string {
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
		"  - New Run (Wizard)",
		"  - Run Existing Config",
		"  - Baseline (Guided)",
		"  - Start Server Emulator",
		"  - Explore CIP Catalog",
		"",
		sectionStyle.Render("Configs:"),
	}
	if len(profiles) == 0 {
		lines = append(lines, "  (none)")
	} else {
		for _, profile := range profiles {
			lines = append(lines, fmt.Sprintf("  - %s", profile.Name))
		}
	}
	lines = append(lines, "", sectionStyle.Render("Recent Runs:"))
	if len(runs) == 0 {
		lines = append(lines, "  (none)")
	} else {
		for _, run := range runs {
			lines = append(lines, fmt.Sprintf("  - %s", run))
		}
	}
	lines = append(lines, "", sectionStyle.Render("Palette:"))
	for _, item := range palette {
		lines = append(lines, fmt.Sprintf("  %s", item.String()))
	}
	return frameStyle.Render(strings.Join(lines, "\n"))
}

// RenderCatalogExplorer renders a catalog view with hex fields visible.
func RenderCatalogExplorer(entries []CatalogEntry, query string) string {
	filtered := FilterCatalogEntries(entries, query)
	lines := []string{
		"CIP Catalog",
		fmt.Sprintf("Search: %s", query),
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
