package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tonylturner/cipdip/internal/ui"
)

// Run starts the POC TUI.
func Run(workspaceRoot string) error {
	ws, err := ui.LoadWorkspace(workspaceRoot)
	if err != nil {
		return err
	}

	// Load initial data
	profiles, _ := ui.ListProfiles(ws.Root)
	runs, _ := ui.ListRuns(ws.Root, 20)

	state := &AppState{
		WorkspaceRoot: ws.Root,
		WorkspaceName: ws.Config.Name,
		Profiles:      profiles,
		Runs:          runs,
		// Catalog is loaded by CatalogPanel from /catalogs/core.yaml
	}

	model := NewModel(state)
	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseCellMotion())

	fmt.Printf("Workspace loaded: %s\n", ws.Root)

	_, err = program.Run()
	return err
}
