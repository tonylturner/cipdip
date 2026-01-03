package ui

import (
	"fmt"
	"strings"
)

// RenderHomeScreen builds a simple home screen view for non-interactive runs.
func RenderHomeScreen(workspaceName string, profiles []ProfileInfo, runs []string, palette []PaletteItem) string {
	lines := []string{
		fmt.Sprintf("cipdip UI | Workspace: %s", workspaceName),
		"",
		"Quick Actions:",
		"  - New Run (Wizard)",
		"  - Run Existing Config",
		"  - Baseline (Guided)",
		"  - Start Server Emulator",
		"  - Explore CIP Catalog",
		"",
		"Configs:",
	}
	if len(profiles) == 0 {
		lines = append(lines, "  (none)")
	} else {
		for _, profile := range profiles {
			lines = append(lines, fmt.Sprintf("  - %s", profile.Name))
		}
	}
	lines = append(lines, "", "Recent Runs:")
	if len(runs) == 0 {
		lines = append(lines, "  (none)")
	} else {
		for _, run := range runs {
			lines = append(lines, fmt.Sprintf("  - %s", run))
		}
	}
	lines = append(lines, "", "Palette:")
	for _, item := range palette {
		lines = append(lines, fmt.Sprintf("  %s", item.String()))
	}
	return strings.Join(lines, "\n")
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
