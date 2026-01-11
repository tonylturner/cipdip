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
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	sectionStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true)
	metaStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	frameStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(1, 2)
	lines := []string{
		titleStyle.Render(fmt.Sprintf("cipdip UI | Workspace: %s", workspaceName)),
		"",
		sectionStyle.Render("Quick Actions:"),
	}
	for _, action := range HomeActions() {
		lines = append(lines, fmt.Sprintf("  - %s", action))
	}
	lines = append(lines, "")
	lines = append(lines, sectionStyle.Render("Configs:"))
	for _, profile := range truncateProfiles(profiles, 5) {
		lines = append(lines, fmt.Sprintf("  - %s (%s)", profile.Name, profile.Kind))
	}
	if len(profiles) == 0 {
		lines = append(lines, metaStyle.Render("  (no profiles yet)"))
	}
	lines = append(lines, "")
	lines = append(lines, sectionStyle.Render("Recent Runs:"))
	for _, run := range truncateStrings(runs, 5) {
		lines = append(lines, fmt.Sprintf("  - %s", run))
	}
	if len(runs) == 0 {
		lines = append(lines, metaStyle.Render("  (no runs yet)"))
	}
	lines = append(lines, "", "Tip: use --tui for interactive mode")
	return frameStyle.Render(strings.Join(lines, "\n"))
}

func truncateProfiles(profiles []ProfileInfo, limit int) []ProfileInfo {
	if len(profiles) <= limit {
		return profiles
	}
	return profiles[:limit]
}

func truncateStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
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

