package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/server"
)

func TestServerHelpDoesNotStart(t *testing.T) {
	cmd := newServerCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if !strings.Contains(out.String(), "Run CIPDIP as an EtherNet/IP / CIP endpoint") {
		t.Fatalf("expected help output, got: %s", out.String())
	}
}

func TestServerTargetsCommand(t *testing.T) {
	cmd := newServerCmd()
	cmd.SetArgs([]string{"targets"})
	buf := &bytes.Buffer{}
	restore := captureStdout(buf)
	if err := cmd.Execute(); err != nil {
		restore()
		t.Fatalf("targets failed: %v", err)
	}
	restore()
	output := buf.String()
	if !strings.Contains(output, "Available targets:") {
		t.Fatalf("expected targets header, got: %s", output)
	}
	targets := server.AvailableServerTargets()
	if len(targets) == 0 {
		t.Fatalf("expected at least one target")
	}
	for _, target := range targets {
		if !strings.Contains(output, target.Name) {
			t.Fatalf("missing target %q in output: %s", target.Name, output)
		}
	}
}

func TestServerModesCommand(t *testing.T) {
	cmd := newServerCmd()
	cmd.SetArgs([]string{"modes"})
	buf := &bytes.Buffer{}
	restore := captureStdout(buf)
	if err := cmd.Execute(); err != nil {
		restore()
		t.Fatalf("modes failed: %v", err)
	}
	restore()
	output := buf.String()
	for _, mode := range []string{"baseline", "realistic", "dpi-torture", "perf"} {
		if !strings.Contains(output, mode) {
			t.Fatalf("missing mode %q in output: %s", mode, output)
		}
	}
}

func TestServerValidateConfigCommand(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "server.yaml")
	cfg := config.CreateDefaultServerConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := newServerCmd()
	cmd.SetArgs([]string{"validate-config", "--config", cfgPath})
	buf := &bytes.Buffer{}
	restore := captureStdout(buf)
	if err := cmd.Execute(); err != nil {
		restore()
		t.Fatalf("validate-config failed: %v", err)
	}
	restore()
	output := buf.String()
	if !strings.Contains(output, "Config OK:") {
		t.Fatalf("expected Config OK output, got: %s", output)
	}
}

func TestServerPrintDefaultConfigCommand(t *testing.T) {
	cmd := newServerCmd()
	cmd.SetArgs([]string{"print-default-config"})
	buf := &bytes.Buffer{}
	restore := captureStdout(buf)
	if err := cmd.Execute(); err != nil {
		restore()
		t.Fatalf("print-default-config failed: %v", err)
	}
	restore()
	output := buf.String()
	var cfg config.ServerConfig
	if err := yaml.Unmarshal([]byte(output), &cfg); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if err := config.ValidateServerConfig(&cfg); err != nil {
		t.Fatalf("validate output config: %v", err)
	}
}
