package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// WorkspaceConfig is the on-disk workspace descriptor.
type WorkspaceConfig struct {
	Version   int    `yaml:"version"`
	Name      string `yaml:"name"`
	CreatedAt string `yaml:"created_at"`
}

// Workspace represents a discovered workspace.
type Workspace struct {
	Root   string
	Config WorkspaceConfig
}

var workspaceDirs = []string{
	"profiles",
	"catalogs",
	"pcaps",
	"runs",
	"reports",
	"tmp",
}

// CreateWorkspace initializes a new workspace layout and writes workspace.yaml.
func CreateWorkspace(root string, name string) (*Workspace, error) {
	if root == "" {
		return nil, fmt.Errorf("workspace path is required")
	}
	if name == "" {
		name = filepath.Base(root)
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	for _, dir := range workspaceDirs {
		path := filepath.Join(root, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("create workspace dir %s: %w", dir, err)
		}
	}

	catalogPath := filepath.Join(root, "catalogs", "core.yaml")
	if _, err := os.Stat(catalogPath); os.IsNotExist(err) {
		if err := SaveCatalogFile(catalogPath, DefaultCatalog()); err != nil {
			return nil, err
		}
	}

	profilesDir := filepath.Join(root, "profiles")
	if err := ensureDefaultProfile(profilesDir); err != nil {
		return nil, err
	}

	cfg := WorkspaceConfig{
		Version:   1,
		Name:      name,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeWorkspaceConfig(root, cfg); err != nil {
		return nil, err
	}

	return &Workspace{Root: root, Config: cfg}, nil
}

// LoadWorkspace reads workspace.yaml and returns the workspace.
func LoadWorkspace(root string) (*Workspace, error) {
	cfg, err := readWorkspaceConfig(root)
	if err != nil {
		return nil, err
	}
	return &Workspace{Root: root, Config: cfg}, nil
}

// EnsureWorkspace loads a workspace or returns a helpful error.
func EnsureWorkspace(root string) (*Workspace, error) {
	if root == "" {
		return nil, fmt.Errorf("workspace path is required")
	}
	cfg, err := readWorkspaceConfig(root)
	if err != nil {
		return nil, err
	}
	return &Workspace{Root: root, Config: cfg}, nil
}

func readWorkspaceConfig(root string) (WorkspaceConfig, error) {
	path := filepath.Join(root, "workspace.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return WorkspaceConfig{}, fmt.Errorf("read workspace.yaml: %w", err)
	}
	var cfg WorkspaceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return WorkspaceConfig{}, fmt.Errorf("parse workspace.yaml: %w", err)
	}
	return cfg, nil
}

func writeWorkspaceConfig(root string, cfg WorkspaceConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal workspace.yaml: %w", err)
	}
	path := filepath.Join(root, "workspace.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write workspace.yaml: %w", err)
	}
	return nil
}

func ensureDefaultProfile(profilesDir string) error {
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return fmt.Errorf("read profiles dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) == ".yaml" {
			return nil
		}
	}
	defaultProfile := Profile{
		Version: 1,
		Kind:    "baseline",
		Name:    "baseline-default",
		Spec: map[string]interface{}{
			"output_dir": "baseline_captures",
			"duration":   5,
		},
	}
	path := filepath.Join(profilesDir, "baseline-default.yaml")
	return SaveProfile(path, defaultProfile)
}
