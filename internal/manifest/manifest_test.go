package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "minimal valid manifest",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: local
`,
			wantErr: false,
		},
		{
			name: "full manifest",
			yaml: `
api_version: v1
run_id: test-run
seed: 1337
profile:
  path: profiles/logix_like.yaml
  distribution: inline
  checksum: sha256:abc123
network:
  control_plane: management
  data_plane:
    client_bind_ip: 10.10.10.10
    server_listen_ip: 10.10.10.20
    target_ip: 10.10.10.20
    target_port: 44818
roles:
  server:
    agent: A1
    mode: baseline
    personality: adapter
    args:
      pcap: server.pcap
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
    interval_ms: 250
    args:
      pcap: client.pcap
readiness:
  method: structured_stdout
  timeout_seconds: 30
artifacts:
  bundle_format: dir
  include:
    - "*.pcap"
    - "*.log"
post_run:
  analyze: true
  diff_baseline: runs/baseline
`,
			wantErr: false,
		},
		{
			name:    "invalid yaml",
			yaml:    `{not: valid: yaml`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.yaml))
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && m == nil {
				t.Error("Parse() returned nil manifest without error")
			}
		})
	}
}

func TestManifest_Validate(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantErr    bool
		errContain string
	}{
		{
			name: "valid server-only",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: local
`,
			wantErr: false,
		},
		{
			name: "valid client-only",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr: false,
		},
		{
			name: "valid both roles",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: A1
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr: false,
		},
		{
			name: "missing api_version",
			yaml: `
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "api_version",
		},
		{
			name: "wrong api_version",
			yaml: `
api_version: v2
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "api_version",
		},
		{
			name: "missing profile path",
			yaml: `
api_version: v1
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "profile.path",
		},
		{
			name: "missing target_ip",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane: {}
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "target_ip",
		},
		{
			name: "invalid target_ip",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: not-an-ip
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "valid IP",
		},
		{
			name: "no roles defined",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
`,
			wantErr:    true,
			errContain: "roles",
		},
		{
			name: "server without listen IP",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  server:
    agent: local
`,
			wantErr:    true,
			errContain: "server_listen_ip",
		},
		{
			name: "client without scenario",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "scenario",
		},
		{
			name: "client without duration",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: baseline
`,
			wantErr:    true,
			errContain: "duration_seconds",
		},
		{
			name: "profile scenario without role",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: profile
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "profile_role",
		},
		{
			name: "invalid distribution",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
  distribution: invalid
network:
  data_plane:
    target_ip: 10.10.10.20
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "distribution",
		},
		{
			name: "invalid bundle format",
			yaml: `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
artifacts:
  bundle_format: tar
roles:
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`,
			wantErr:    true,
			errContain: "bundle_format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			err = m.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errContain != "" {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errContain)
				}
			}
		})
	}
}

func TestManifest_ValidateAgents(t *testing.T) {
	yaml := `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: A1
  client:
    agent: A2
    scenario: baseline
    duration_seconds: 60
`
	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Missing agents
	err = m.ValidateAgents(map[string]string{})
	if err == nil {
		t.Error("ValidateAgents() should fail with missing agents")
	}

	// Partial agents
	err = m.ValidateAgents(map[string]string{"A1": "ssh://user@host"})
	if err == nil {
		t.Error("ValidateAgents() should fail with partial agents")
	}

	// All agents present
	err = m.ValidateAgents(map[string]string{
		"A1": "ssh://user@host1",
		"A2": "ssh://user@host2",
	})
	if err != nil {
		t.Errorf("ValidateAgents() error = %v", err)
	}

	// Local agents don't need mapping
	yamlLocal := `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: local
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
`
	m2, _ := Parse([]byte(yamlLocal))
	err = m2.ValidateAgents(map[string]string{})
	if err != nil {
		t.Errorf("ValidateAgents() should pass for local agents, got error = %v", err)
	}
}

func TestLoadAndSave(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "test_manifest.yaml")

	original := &Manifest{
		APIVersion: "v1",
		RunID:      "test-run",
		Profile: ProfileConfig{
			Path:         "profiles/test.yaml",
			Distribution: "inline",
		},
		Network: NetworkConfig{
			DataPlane: DataPlaneConfig{
				TargetIP:       "10.10.10.20",
				ServerListenIP: "10.10.10.20",
			},
		},
		Roles: RolesConfig{
			Server: &ServerRoleConfig{
				Agent:       "local",
				Personality: "adapter",
			},
		},
	}

	// Save
	if err := original.SaveYAML(manifestPath); err != nil {
		t.Fatalf("SaveYAML() error = %v", err)
	}

	// Load
	loaded, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Compare
	if loaded.APIVersion != original.APIVersion {
		t.Errorf("APIVersion = %v, want %v", loaded.APIVersion, original.APIVersion)
	}
	if loaded.RunID != original.RunID {
		t.Errorf("RunID = %v, want %v", loaded.RunID, original.RunID)
	}
	if loaded.Profile.Path != original.Profile.Path {
		t.Errorf("Profile.Path = %v, want %v", loaded.Profile.Path, original.Profile.Path)
	}
}

func TestDefaults(t *testing.T) {
	yaml := `
api_version: v1
profile:
  path: profiles/test.yaml
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: local
`
	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Check defaults were applied
	if m.RunID == "" || m.RunID == "auto" {
		t.Error("RunID should be auto-generated")
	}
	if m.Readiness.Method != "structured_stdout" {
		t.Errorf("Readiness.Method = %v, want structured_stdout", m.Readiness.Method)
	}
	if m.Readiness.TimeoutSeconds != 30 {
		t.Errorf("Readiness.TimeoutSeconds = %v, want 30", m.Readiness.TimeoutSeconds)
	}
	if m.Artifacts.BundleFormat != "dir" {
		t.Errorf("Artifacts.BundleFormat = %v, want dir", m.Artifacts.BundleFormat)
	}
	if m.Network.DataPlane.TargetPort != 44818 {
		t.Errorf("Network.DataPlane.TargetPort = %v, want 44818", m.Network.DataPlane.TargetPort)
	}
	if m.Profile.Distribution != "inline" {
		t.Errorf("Profile.Distribution = %v, want inline", m.Profile.Distribution)
	}
}

func TestResolve(t *testing.T) {
	// Create a temporary profile file
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "test_profile.yaml")
	if err := os.WriteFile(profilePath, []byte("test: profile"), 0644); err != nil {
		t.Fatalf("Failed to create test profile: %v", err)
	}

	yaml := `
api_version: v1
profile:
  path: test_profile.yaml
  distribution: inline
network:
  data_plane:
    target_ip: 10.10.10.20
    server_listen_ip: 10.10.10.20
roles:
  server:
    agent: local
    personality: adapter
    args:
      pcap: server.pcap
  client:
    agent: local
    scenario: baseline
    duration_seconds: 60
    args:
      pcap: client.pcap
`
	m, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	resolved, err := m.ResolveWithOptions(ResolveOptions{
		WorkingDir:  tmpDir,
		ToolVersion: "0.2.1",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	// Check resolved fields
	if resolved.ProfileChecksum == "" {
		t.Error("ProfileChecksum should be set")
	}
	if !strings.HasPrefix(resolved.ProfileChecksum, "sha256:") {
		t.Errorf("ProfileChecksum should start with sha256:, got %v", resolved.ProfileChecksum)
	}
	if resolved.ProfileContent != "test: profile" {
		t.Errorf("ProfileContent = %v, want 'test: profile'", resolved.ProfileContent)
	}
	if resolved.ToolVersion != "0.2.1" {
		t.Errorf("ToolVersion = %v, want 0.2.1", resolved.ToolVersion)
	}
	if len(resolved.ServerArgs) == 0 {
		t.Error("ServerArgs should be populated")
	}
	if len(resolved.ClientArgs) == 0 {
		t.Error("ClientArgs should be populated")
	}

	// Check server args contain expected values
	serverArgsStr := strings.Join(resolved.ServerArgs, " ")
	if !strings.Contains(serverArgsStr, "--listen-ip") {
		t.Error("ServerArgs should contain --listen-ip")
	}
	if !strings.Contains(serverArgsStr, "--pcap") {
		t.Error("ServerArgs should contain --pcap")
	}

	// Check client args contain expected values
	clientArgsStr := strings.Join(resolved.ClientArgs, " ")
	if !strings.Contains(clientArgsStr, "--ip") {
		t.Error("ClientArgs should contain --ip")
	}
	if !strings.Contains(clientArgsStr, "--scenario") {
		t.Error("ClientArgs should contain --scenario")
	}
	if !strings.Contains(clientArgsStr, "--duration-seconds") {
		t.Error("ClientArgs should contain --duration-seconds")
	}
}
