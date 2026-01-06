package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tturner/cipdip/internal/pcap"
)

func TestResolveTsharkPath(t *testing.T) {
	t.Run("explicit path", func(t *testing.T) {
		path := writeDummyTool(t, "tshark_explicit")
		t.Setenv("TSHARK", path)
		got, err := pcap.ResolveTsharkPath("")
		if err != nil {
			t.Fatalf("resolveTsharkPath failed: %v", err)
		}
		if got != path {
			t.Fatalf("path: got %q want %q", got, path)
		}
	})

	t.Run("env base name", func(t *testing.T) {
		name := "cipdip_test_tshark"
		path := writeDummyTool(t, name)
		t.Setenv("TSHARK", name)
		t.Setenv("PATH", filepath.Dir(path)+string(os.PathListSeparator)+os.Getenv("PATH"))
		got, err := pcap.ResolveTsharkPath("")
		if err != nil {
			t.Fatalf("resolveTsharkPath failed: %v", err)
		}
		if got != path {
			t.Fatalf("path: got %q want %q", got, path)
		}
	})
}

func TestResolveExternalPath(t *testing.T) {
	t.Run("explicit path", func(t *testing.T) {
		path := writeDummyTool(t, "tcpreplay_explicit")
		got, err := resolveExternalPath(path, "TCPREPLAY", "tcpreplay")
		if err != nil {
			t.Fatalf("resolveExternalPath failed: %v", err)
		}
		if got != path {
			t.Fatalf("path: got %q want %q", got, path)
		}
	})

	t.Run("env base name", func(t *testing.T) {
		name := "cipdip_test_tcpreplay"
		path := writeDummyTool(t, name)
		t.Setenv("TCPREPLAY", name)
		t.Setenv("PATH", filepath.Dir(path)+string(os.PathListSeparator)+os.Getenv("PATH"))
		got, err := resolveExternalPath("", "TCPREPLAY", "tcpreplay")
		if err != nil {
			t.Fatalf("resolveExternalPath failed: %v", err)
		}
		if got != path {
			t.Fatalf("path: got %q want %q", got, path)
		}
	})
}

func writeDummyTool(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	filename := name
	if runtime.GOOS == "windows" {
		filename += ".exe"
	}
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("write dummy tool: %v", err)
	}
	return path
}
