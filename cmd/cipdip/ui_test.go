package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/tonylturner/cipdip/internal/ui"
)

func TestUICommandNoRun(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if _, err := ui.CreateWorkspace(root, "ui-test"); err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}
	profile := ui.Profile{
		Version: 1,
		Kind:    "baseline",
		Name:    "baseline-test",
		Spec: map[string]interface{}{
			"output_dir": "baseline_captures",
		},
	}
	profilePath := filepath.Join(root, "profiles", "baseline.yaml")
	if err := ui.SaveProfile(profilePath, profile); err != nil {
		t.Fatalf("SaveProfile failed: %v", err)
	}

	cmd := newUICmd()
	cmd.SetArgs([]string{"--workspace", root, "--no-run"})
	buf := &bytes.Buffer{}
	restore := captureStdout(buf)
	if err := cmd.Execute(); err != nil {
		restore()
		t.Fatalf("ui command failed: %v", err)
	}
	restore()
	if buf.Len() == 0 {
		t.Fatalf("expected output from ui command")
	}
}

func TestUICommandCatalogPreview(t *testing.T) {
	// Skip: The --catalog flag uses legacy workspace-based catalogs.
	// The new catalog system uses /catalogs/core.yaml at repo root.
	// Use 'cipdip catalog list' for catalog browsing.
	t.Skip("--catalog flag uses deprecated workspace catalogs")
}

func TestUICommandPalettePreview(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if _, err := ui.CreateWorkspace(root, "ui-test"); err != nil {
		t.Fatalf("CreateWorkspace failed: %v", err)
	}

	cmd := newUICmd()
	cmd.SetArgs([]string{"--workspace", root, "--palette", "--palette-query", "catalog"})
	buf := &bytes.Buffer{}
	restore := captureStdout(buf)
	if err := cmd.Execute(); err != nil {
		restore()
		t.Fatalf("ui command failed: %v", err)
	}
	restore()
	if buf.Len() == 0 {
		t.Fatalf("expected output from palette preview")
	}
}
