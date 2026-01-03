package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PaletteItem represents a searchable entry in the command palette.
type PaletteItem struct {
	Kind  string
	Title string
	Meta  string
}

// BuildPaletteIndex builds a basic palette index from workspace data.
func BuildPaletteIndex(workspaceRoot string) ([]PaletteItem, error) {
	items := make([]PaletteItem, 0)

	for _, task := range []string{
		"New Run (Wizard)",
		"Run Existing Config",
		"Baseline (Guided)",
		"Start Server Emulator",
		"Explore CIP Catalog",
	} {
		items = append(items, PaletteItem{Kind: "Task", Title: task})
	}

	profiles, err := ListProfiles(workspaceRoot)
	if err == nil {
		for _, profile := range profiles {
			items = append(items, PaletteItem{
				Kind:  "Config",
				Title: profile.Name,
				Meta:  profile.Kind,
			})
		}
	}

	runsDir := filepath.Join(workspaceRoot, "runs")
	if entries, err := os.ReadDir(runsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				items = append(items, PaletteItem{
					Kind:  "Run",
					Title: entry.Name(),
				})
			}
		}
	}

	if catalogEntries, err := ListCatalogEntries(workspaceRoot); err == nil {
		for _, entry := range catalogEntries {
			items = append(items, PaletteItem{
				Kind:  "Catalog",
				Title: entry.Key,
				Meta:  entry.Name,
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind == items[j].Kind {
			return items[i].Title < items[j].Title
		}
		return items[i].Kind < items[j].Kind
	})

	return items, nil
}

// FilterPalette filters items by a search query.
func FilterPalette(items []PaletteItem, query string) []PaletteItem {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return items
	}
	matches := make([]PaletteItem, 0)
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Title), query) ||
			strings.Contains(strings.ToLower(item.Meta), query) ||
			strings.Contains(strings.ToLower(item.Kind), query) {
			matches = append(matches, item)
		}
	}
	return matches
}

func (item PaletteItem) String() string {
	if item.Meta == "" {
		return fmt.Sprintf("[%s] %s", item.Kind, item.Title)
	}
	return fmt.Sprintf("[%s] %s (%s)", item.Kind, item.Title, item.Meta)
}
