package ui

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentRegistry_LoadSave(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "agent-registry-test")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Load empty registry
	registry, err := LoadAgentRegistry(tmpDir)
	if err != nil {
		t.Fatalf("load empty registry: %v", err)
	}

	if len(registry.Agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(registry.Agents))
	}

	// Add agents
	registry.Add(&Agent{
		Name:        "test-agent",
		Transport:   "ssh://user@192.168.1.10",
		Description: "Test agent",
		Status:      AgentStatusOK,
	})

	registry.Add(&Agent{
		Name:        "another-agent",
		Transport:   "ssh://admin@10.0.0.50:2222",
		Description: "Another agent",
		Status:      AgentStatusUnknown,
	})

	// Save
	if err := registry.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	// Verify file exists
	agentsFile := filepath.Join(tmpDir, AgentsFileName)
	if _, err := os.Stat(agentsFile); os.IsNotExist(err) {
		t.Error("agents file not created")
	}

	// Reload and verify
	registry2, err := LoadAgentRegistry(tmpDir)
	if err != nil {
		t.Fatalf("reload registry: %v", err)
	}

	if len(registry2.Agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(registry2.Agents))
	}

	agent, exists := registry2.Get("test-agent")
	if !exists {
		t.Error("test-agent not found")
	} else {
		if agent.Transport != "ssh://user@192.168.1.10" {
			t.Errorf("wrong transport: %s", agent.Transport)
		}
		if agent.Status != AgentStatusOK {
			t.Errorf("wrong status: %s", agent.Status)
		}
	}
}

func TestAgentRegistry_AddRemove(t *testing.T) {
	registry := &AgentRegistry{
		Agents: make(map[string]*Agent),
	}

	// Add
	registry.Add(&Agent{Name: "agent1", Transport: "ssh://user@host1"})
	registry.Add(&Agent{Name: "agent2", Transport: "ssh://user@host2"})

	if len(registry.Agents) != 2 {
		t.Errorf("expected 2 agents, got %d", len(registry.Agents))
	}

	// Update existing
	registry.Add(&Agent{Name: "agent1", Transport: "ssh://newuser@host1"})
	if len(registry.Agents) != 2 {
		t.Errorf("expected 2 agents after update, got %d", len(registry.Agents))
	}

	agent, _ := registry.Get("agent1")
	if agent.Transport != "ssh://newuser@host1" {
		t.Error("agent not updated")
	}

	// Remove
	if !registry.Remove("agent1") {
		t.Error("remove should return true")
	}

	if len(registry.Agents) != 1 {
		t.Errorf("expected 1 agent after remove, got %d", len(registry.Agents))
	}

	// Remove non-existent
	if registry.Remove("nonexistent") {
		t.Error("remove non-existent should return false")
	}
}

func TestAgentRegistry_List(t *testing.T) {
	registry := &AgentRegistry{
		Agents: make(map[string]*Agent),
	}

	registry.Add(&Agent{Name: "charlie", Transport: "ssh://user@c"})
	registry.Add(&Agent{Name: "alpha", Transport: "ssh://user@a"})
	registry.Add(&Agent{Name: "bravo", Transport: "ssh://user@b"})

	list := registry.List()

	if len(list) != 3 {
		t.Fatalf("expected 3 agents, got %d", len(list))
	}

	// Should be sorted by name
	expected := []string{"alpha", "bravo", "charlie"}
	for i, agent := range list {
		if agent.Name != expected[i] {
			t.Errorf("position %d: expected %s, got %s", i, expected[i], agent.Name)
		}
	}
}

func TestParseSSHTransport(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		expected  SSHInfo
		wantErr   bool
	}{
		{
			name:      "simple ssh URL",
			transport: "ssh://user@192.168.1.10",
			expected:  SSHInfo{User: "user", Host: "192.168.1.10", Port: "22"},
		},
		{
			name:      "ssh URL with port",
			transport: "ssh://admin@host.local:2222",
			expected:  SSHInfo{User: "admin", Host: "host.local", Port: "2222"},
		},
		{
			name:      "ssh URL with key",
			transport: "ssh://user@host?key=/path/to/key",
			expected:  SSHInfo{User: "user", Host: "host", Port: "22", KeyFile: "/path/to/key"},
		},
		{
			name:      "ssh URL with insecure",
			transport: "ssh://user@host?insecure=true",
			expected:  SSHInfo{User: "user", Host: "host", Port: "22", Insecure: true},
		},
		{
			name:      "ssh URL with multiple params",
			transport: "ssh://user@host:2222?key=/path&insecure=true",
			expected:  SSHInfo{User: "user", Host: "host", Port: "2222", KeyFile: "/path", Insecure: true},
		},
		{
			name:      "bare user@host",
			transport: "user@host.example.com",
			expected:  SSHInfo{User: "user", Host: "host.example.com", Port: "22"},
		},
		{
			name:      "bare user@host:port",
			transport: "admin@10.0.0.1:22222",
			expected:  SSHInfo{User: "admin", Host: "10.0.0.1", Port: "22222"},
		},
		{
			name:      "host only",
			transport: "192.168.1.100",
			expected:  SSHInfo{Host: "192.168.1.100", Port: "22"},
		},
		{
			name:      "empty host",
			transport: "ssh://user@",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseSSHTransport(tt.transport)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if info.User != tt.expected.User {
				t.Errorf("user: expected %q, got %q", tt.expected.User, info.User)
			}
			if info.Host != tt.expected.Host {
				t.Errorf("host: expected %q, got %q", tt.expected.Host, info.Host)
			}
			if info.Port != tt.expected.Port {
				t.Errorf("port: expected %q, got %q", tt.expected.Port, info.Port)
			}
			if info.KeyFile != tt.expected.KeyFile {
				t.Errorf("keyfile: expected %q, got %q", tt.expected.KeyFile, info.KeyFile)
			}
			if info.Insecure != tt.expected.Insecure {
				t.Errorf("insecure: expected %v, got %v", tt.expected.Insecure, info.Insecure)
			}
		})
	}
}

func TestSSHInfo_ToTransport(t *testing.T) {
	tests := []struct {
		name     string
		info     SSHInfo
		expected string
	}{
		{
			name:     "simple",
			info:     SSHInfo{User: "user", Host: "host", Port: "22"},
			expected: "ssh://user@host",
		},
		{
			name:     "with custom port",
			info:     SSHInfo{User: "admin", Host: "192.168.1.10", Port: "2222"},
			expected: "ssh://admin@192.168.1.10:2222",
		},
		{
			name:     "with key file",
			info:     SSHInfo{User: "user", Host: "host", Port: "22", KeyFile: "/path/to/key"},
			expected: "ssh://user@host?key=/path/to/key",
		},
		{
			name:     "with insecure",
			info:     SSHInfo{User: "user", Host: "host", Port: "22", Insecure: true},
			expected: "ssh://user@host?insecure=true",
		},
		{
			name:     "with all options",
			info:     SSHInfo{User: "user", Host: "host", Port: "2222", KeyFile: "/key", Insecure: true},
			expected: "ssh://user@host:2222?key=/key&insecure=true",
		},
		{
			name:     "no user",
			info:     SSHInfo{Host: "host", Port: "22"},
			expected: "ssh://host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.info.ToTransport()
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAgent_Fields(t *testing.T) {
	agent := &Agent{
		Name:        "test",
		Transport:   "ssh://user@host",
		Description: "Test agent",
		LastCheck:   time.Now(),
		Status:      AgentStatusOK,
		StatusMsg:   "Connected",
		OSArch:      "linux/amd64",
		CipdipVer:   "v0.2.1",
		PCAPCapable: true,
	}

	if agent.Name != "test" {
		t.Error("name mismatch")
	}
	if agent.Status != AgentStatusOK {
		t.Error("status mismatch")
	}
	if !agent.PCAPCapable {
		t.Error("pcap capable should be true")
	}
}
