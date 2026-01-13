package ui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateWorkspace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	ws, err := CreateWorkspace(root, "test-workspace")
	if err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	if ws.Root != root {
		t.Fatalf("workspace root mismatch: got %s want %s", ws.Root, root)
	}
	if ws.Config.Name != "test-workspace" {
		t.Fatalf("workspace name mismatch: got %s", ws.Config.Name)
	}

	for _, dir := range workspaceDirs {
		path := filepath.Join(root, dir)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing workspace dir %s: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected directory %s", path)
		}
	}

	// Note: Catalogs are no longer created in workspaces.
	// The single source of truth is /catalogs/core.yaml at repo root.

	profilePath := filepath.Join(root, "profiles", "baseline-default.yaml")
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("missing default profile: %v", err)
	}
}

func TestLoadWorkspace(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if _, err := CreateWorkspace(root, "load-workspace"); err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	ws, err := LoadWorkspace(root)
	if err != nil {
		t.Fatalf("LoadWorkspace failed: %v", err)
	}
	if ws.Config.Name != "load-workspace" {
		t.Fatalf("workspace name mismatch: got %s", ws.Config.Name)
	}
}

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.yaml")
	profile := Profile{
		Version: 1,
		Kind:    "baseline",
		Name:    "baseline-test",
		Spec: map[string]interface{}{
			"output_dir": "baseline_captures",
		},
	}
	if err := SaveProfile(profilePath, profile); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}
	loaded, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("LoadProfile failed: %v", err)
	}
	if loaded.Name != "baseline-test" {
		t.Fatalf("profile name mismatch: got %s", loaded.Name)
	}
}

func TestListProfiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if _, err := CreateWorkspace(root, "profiles"); err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	profile := Profile{
		Version: 1,
		Kind:    "baseline",
		Name:    "baseline-test",
		Spec:    map[string]interface{}{},
	}
	path := filepath.Join(root, "profiles", "baseline.yaml")
	if err := SaveProfile(path, profile); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}
	entries, err := ListProfiles(root)
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}
	if len(entries) < 1 {
		t.Fatalf("expected at least 1 profile entry, got %d", len(entries))
	}
	found := false
	for _, entry := range entries {
		if entry.Name == "baseline-test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected baseline-test profile in list")
	}
}
