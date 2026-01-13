// Package manifest provides Run Manifest loading, validation, and resolution
// for distributed orchestration runs.
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// APIVersion is the current manifest schema version.
const APIVersion = "v1"

// Manifest represents a Run Manifest for orchestrated execution.
type Manifest struct {
	APIVersion string          `yaml:"api_version" json:"api_version"`
	RunID      string          `yaml:"run_id" json:"run_id"`
	Seed       int64           `yaml:"seed,omitempty" json:"seed,omitempty"`
	Profile    ProfileConfig   `yaml:"profile" json:"profile"`
	Network    NetworkConfig   `yaml:"network" json:"network"`
	Roles      RolesConfig     `yaml:"roles" json:"roles"`
	Readiness  ReadinessConfig `yaml:"readiness,omitempty" json:"readiness,omitempty"`
	Artifacts  ArtifactsConfig `yaml:"artifacts,omitempty" json:"artifacts,omitempty"`
	PostRun    PostRunConfig   `yaml:"post_run,omitempty" json:"post_run,omitempty"`
}

// ProfileConfig specifies the process profile to use.
type ProfileConfig struct {
	Path         string `yaml:"path" json:"path"`
	Distribution string `yaml:"distribution" json:"distribution"` // inline, push, preinstalled
	Checksum     string `yaml:"checksum,omitempty" json:"checksum,omitempty"`
}

// NetworkConfig specifies network settings for the run.
type NetworkConfig struct {
	ControlPlane string          `yaml:"control_plane,omitempty" json:"control_plane,omitempty"`
	DataPlane    DataPlaneConfig `yaml:"data_plane" json:"data_plane"`
}

// DataPlaneConfig specifies data plane network settings.
type DataPlaneConfig struct {
	ClientBindIP   string `yaml:"client_bind_ip,omitempty" json:"client_bind_ip,omitempty"`
	ServerListenIP string `yaml:"server_listen_ip,omitempty" json:"server_listen_ip,omitempty"`
	TargetIP       string `yaml:"target_ip" json:"target_ip"`
	TargetPort     int    `yaml:"target_port,omitempty" json:"target_port,omitempty"`
}

// RolesConfig contains server and client role configurations.
type RolesConfig struct {
	Server *ServerRoleConfig `yaml:"server,omitempty" json:"server,omitempty"`
	Client *ClientRoleConfig `yaml:"client,omitempty" json:"client,omitempty"`
}

// ServerRoleConfig defines the server role.
type ServerRoleConfig struct {
	Agent       string            `yaml:"agent" json:"agent"`
	Mode        string            `yaml:"mode,omitempty" json:"mode,omitempty"`
	Personality string            `yaml:"personality,omitempty" json:"personality,omitempty"`
	Args        map[string]any    `yaml:"args,omitempty" json:"args,omitempty"`
}

// ClientRoleConfig defines the client role.
type ClientRoleConfig struct {
	Agent           string         `yaml:"agent" json:"agent"`
	Scenario        string         `yaml:"scenario" json:"scenario"`
	ProfileRole     string         `yaml:"profile_role,omitempty" json:"profile_role,omitempty"`
	DurationSeconds int            `yaml:"duration_seconds" json:"duration_seconds"`
	IntervalMs      int            `yaml:"interval_ms,omitempty" json:"interval_ms,omitempty"`
	Args            map[string]any `yaml:"args,omitempty" json:"args,omitempty"`
}

// Type aliases for convenience
type (
	ServerRole = ServerRoleConfig
	ClientRole = ClientRoleConfig
)

// ReadinessConfig specifies how to detect server readiness.
type ReadinessConfig struct {
	Method         string `yaml:"method,omitempty" json:"method,omitempty"` // structured_stdout, tcp_connect
	TimeoutSeconds int    `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

// ArtifactsConfig specifies artifact collection settings.
type ArtifactsConfig struct {
	BundleFormat string   `yaml:"bundle_format,omitempty" json:"bundle_format,omitempty"` // dir, zip
	Include      []string `yaml:"include,omitempty" json:"include,omitempty"`
}

// PostRunConfig specifies post-run actions.
type PostRunConfig struct {
	Analyze      bool   `yaml:"analyze,omitempty" json:"analyze,omitempty"`
	DiffBaseline string `yaml:"diff_baseline,omitempty" json:"diff_baseline,omitempty"`
}

// Load reads a manifest from a YAML file.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest file: %w", err)
	}

	return Parse(data)
}

// Parse parses manifest YAML data.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest YAML: %w", err)
	}

	// Apply defaults
	applyDefaults(&m)

	return &m, nil
}

// applyDefaults sets default values for optional fields.
func applyDefaults(m *Manifest) {
	if m.RunID == "" || m.RunID == "auto" {
		m.RunID = generateRunID()
	}

	if m.Readiness.Method == "" {
		m.Readiness.Method = "structured_stdout"
	}
	if m.Readiness.TimeoutSeconds == 0 {
		m.Readiness.TimeoutSeconds = 30
	}

	if m.Artifacts.BundleFormat == "" {
		m.Artifacts.BundleFormat = "dir"
	}

	if m.Network.DataPlane.TargetPort == 0 {
		m.Network.DataPlane.TargetPort = 44818
	}

	if m.Profile.Distribution == "" {
		m.Profile.Distribution = "inline"
	}
}

// generateRunID creates a timestamped run ID.
func generateRunID() string {
	return time.Now().UTC().Format("2006-01-02_15-04-05")
}

// ToYAML returns the manifest as YAML bytes.
func (m *Manifest) ToYAML() ([]byte, error) {
	return yaml.Marshal(m)
}

// SaveYAML writes the manifest to a YAML file.
func (m *Manifest) SaveYAML(path string) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write manifest file: %w", err)
	}

	return nil
}
