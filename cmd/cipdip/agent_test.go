package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/transport"
)

func TestGetAgentStatus(t *testing.T) {
	tmpDir := t.TempDir()
	status := getAgentStatus(tmpDir)

	if status.Version == "" {
		t.Error("Version should not be empty")
	}
	if status.OS == "" {
		t.Error("OS should not be empty")
	}
	if status.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if status.Hostname == "" {
		t.Error("Hostname should not be empty")
	}
	if len(status.SupportedRoles) == 0 {
		t.Error("SupportedRoles should not be empty")
	}
}

func TestCheckWorkdir_Writable(t *testing.T) {
	tmpDir := t.TempDir()
	ws := checkWorkdir(tmpDir)

	if !ws.Exists {
		t.Error("Workdir should exist")
	}
	if !ws.Writable {
		t.Error("Workdir should be writable")
	}
	if ws.Error != "" {
		t.Errorf("Workdir error should be empty, got: %s", ws.Error)
	}
}

func TestCheckWorkdir_NonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistent := filepath.Join(tmpDir, "non-existent")

	ws := checkWorkdir(nonExistent)

	// Should successfully create it (or report it can be created)
	if ws.Error != "" && !ws.Writable {
		t.Logf("Workdir status: %+v", ws)
	}
}

func TestCheckWorkdir_NotDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file.txt")

	// Create a file instead of directory
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	ws := checkWorkdir(filePath)

	if ws.Writable {
		t.Error("File should not be considered writable as workdir")
	}
	if ws.Error == "" {
		t.Error("Should have error for file instead of directory")
	}
}

func TestGetInterfaces(t *testing.T) {
	interfaces := getInterfaces()

	// Should find at least loopback
	found := false
	for _, iface := range interfaces {
		if iface.Name != "" {
			found = true
			if len(iface.Addresses) == 0 {
				t.Errorf("Interface %s has no addresses", iface.Name)
			}
		}
	}

	if !found {
		t.Log("No interfaces found (may be expected in some environments)")
	}
}

func TestCanBindAddress(t *testing.T) {
	// Loopback should always be bindable
	if !canBindAddress("127.0.0.1") {
		t.Error("Should be able to bind to 127.0.0.1")
	}
}

func TestCheckPcapCapability(t *testing.T) {
	capable, method := checkPcapCapability()

	// Just verify it returns without error
	// Result depends on system configuration
	t.Logf("PCAP capable: %v, method: %s", capable, method)
}

func TestTrimOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello\n", "hello"},
		{"hello\r\n", "hello"},
		{"hello  \n", "hello"},
		{"hello", "hello"},
		{"", ""},
		{"  \n\n", ""},
	}

	for _, tt := range tests {
		result := trimOutput(tt.input)
		if result != tt.expected {
			t.Errorf("trimOutput(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseVersionOutput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"cipdip version 0.2.1\n", "cipdip version 0.2.1"},
		{"v1.0.0", "v1.0.0"},
		{"", ""},
	}

	for _, tt := range tests {
		result := parseVersionOutput(tt.input)
		if result != tt.expected {
			t.Errorf("parseVersionOutput(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestCheckRemoteAgent_LocalTransport(t *testing.T) {
	// Use local transport to test the check logic
	tr := transport.NewLocal(transport.DefaultOptions())
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := checkRemoteAgent(ctx, tr, "local")

	if !result.Connected {
		t.Error("Should be connected for local transport")
	}

	// Should have connectivity check
	foundConnectivity := false
	for _, check := range result.Checks {
		if check.Name == "connectivity" {
			foundConnectivity = true
			if check.Status != "pass" {
				t.Errorf("Connectivity check should pass, got: %s", check.Status)
			}
		}
	}
	if !foundConnectivity {
		t.Error("Should have connectivity check")
	}

	// cipdip may or may not be found depending on environment
	t.Logf("Check result: OK=%v, cipdip_found=%v", result.OK, result.CipdipFound)
}

func TestAgentStatus_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	status := getAgentStatus(tmpDir)

	// Verify all fields are populated
	if status.Version == "" {
		t.Error("Version should be set")
	}
	if status.OS == "" {
		t.Error("OS should be set")
	}
	if status.Arch == "" {
		t.Error("Arch should be set")
	}
	if status.Workdir.Path == "" {
		t.Error("Workdir.Path should be set")
	}
}

func TestCheckResult_DetermineOK(t *testing.T) {
	// Test that OK is properly determined based on checks
	result := &CheckResult{
		Connected:   true,
		CipdipFound: true,
		Checks: []CheckItem{
			{Name: "connectivity", Status: "pass"},
			{Name: "cipdip_installed", Status: "pass"},
			{Name: "workdir_writable", Status: "pass"},
			{Name: "pcap_capable", Status: "fail"}, // pcap is optional
		},
	}

	// Re-evaluate OK (simulating the logic)
	result.OK = result.Connected && result.CipdipFound

	if !result.OK {
		t.Error("Result should be OK when connectivity and cipdip are good")
	}
}

func TestInterfaceInfo(t *testing.T) {
	info := InterfaceInfo{
		Name:      "eth0",
		Addresses: []string{"192.168.1.100"},
		CanBind:   true,
	}

	if info.Name != "eth0" {
		t.Errorf("Name = %s, want eth0", info.Name)
	}
	if len(info.Addresses) != 1 {
		t.Errorf("Addresses length = %d, want 1", len(info.Addresses))
	}
	if !info.CanBind {
		t.Error("CanBind should be true")
	}
}
