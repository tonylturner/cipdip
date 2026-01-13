package tui

import (
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/yaml.v3"
)

// WorkspaceConfig represents workspace.yaml
type WorkspaceConfig struct {
	Name string `yaml:"name"`
}

// Workspace represents a loaded workspace
type Workspace struct {
	Root   string
	Config WorkspaceConfig
}

// LoadWorkspace loads a workspace from the given root.
func LoadWorkspace(root string) (*Workspace, error) {
	configPath := filepath.Join(root, "workspace.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read workspace config: %w", err)
	}

	var config WorkspaceConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse workspace config: %w", err)
	}

	return &Workspace{
		Root:   root,
		Config: config,
	}, nil
}

// ListProfiles lists available profiles in the workspace.
func ListProfiles(workspaceRoot string) ([]ProfileInfo, error) {
	profilesDir := filepath.Join(workspaceRoot, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var profiles []ProfileInfo
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()
		name = name[:len(name)-5] // Remove .yaml
		profiles = append(profiles, ProfileInfo{
			Path: filepath.Join(profilesDir, entry.Name()),
			Name: name,
			Kind: "profile",
		})
	}

	return profiles, nil
}

// ListRuns lists recent runs in the workspace.
func ListRuns(workspaceRoot string, limit int) ([]string, error) {
	runsDir := filepath.Join(workspaceRoot, "runs")
	entries, err := os.ReadDir(runsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// Sort by name (which includes timestamp) descending
	var runs []string
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if !entry.IsDir() {
			continue
		}
		runs = append(runs, entry.Name())
		if len(runs) >= limit {
			break
		}
	}

	return runs, nil
}

// Run starts the POC TUI.
func Run(workspaceRoot string) error {
	ws, err := LoadWorkspace(workspaceRoot)
	if err != nil {
		return err
	}

	// Load initial data
	profiles, _ := ListProfiles(ws.Root)
	runs, _ := ListRuns(ws.Root, 20)

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
