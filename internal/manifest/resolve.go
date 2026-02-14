package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// ResolvedManifest contains the fully expanded manifest with computed values.
type ResolvedManifest struct {
	// Original manifest fields
	Manifest

	// Resolved fields
	ResolvedAt       string            `yaml:"resolved_at" json:"resolved_at"`
	ProfilePath      string            `yaml:"profile_path" json:"profile_path"` // Absolute path to profile
	ProfileChecksum  string            `yaml:"profile_checksum" json:"profile_checksum"`
	ProfileContent   string            `yaml:"profile_content,omitempty" json:"profile_content,omitempty"` // For inline distribution
	ServerArgs       []string          `yaml:"server_args,omitempty" json:"server_args,omitempty"`
	ClientArgs       []string          `yaml:"client_args,omitempty" json:"client_args,omitempty"`
	ToolVersion      string            `yaml:"tool_version" json:"tool_version"`
	ControllerOS     string            `yaml:"controller_os" json:"controller_os"`
	ControllerArch   string            `yaml:"controller_arch" json:"controller_arch"`
}

// ResolveOptions configures manifest resolution.
type ResolveOptions struct {
	WorkingDir  string            // Base directory for relative paths
	ToolVersion string            // cipdip version string
	AgentMap    map[string]string // Agent ID -> transport spec mapping
}

// Resolve expands the manifest into a fully resolved form with default options.
func (m *Manifest) Resolve() (*ResolvedManifest, error) {
	cwd, _ := os.Getwd()
	return m.ResolveWithOptions(ResolveOptions{
		WorkingDir:  cwd,
		ToolVersion: "dev",
	})
}

// ResolveWithOptions expands the manifest into a fully resolved form.
func (m *Manifest) ResolveWithOptions(opts ResolveOptions) (*ResolvedManifest, error) {
	resolved := &ResolvedManifest{
		Manifest:       *m,
		ResolvedAt:     time.Now().UTC().Format(time.RFC3339),
		ToolVersion:    opts.ToolVersion,
		ControllerOS:   runtime.GOOS,
		ControllerArch: runtime.GOARCH,
	}

	// Resolve profile path and compute checksum
	profilePath := m.Profile.Path
	if profilePath != "" && !filepath.IsAbs(profilePath) && opts.WorkingDir != "" {
		profilePath = filepath.Join(opts.WorkingDir, profilePath)
	}
	resolved.ProfilePath = profilePath

	// Compute checksum if profile path is set
	if profilePath != "" {
		if _, err := os.Stat(profilePath); err == nil {
			checksum, err := computeFileChecksum(profilePath)
			if err != nil {
				return nil, fmt.Errorf("compute profile checksum: %w", err)
			}
			resolved.ProfileChecksum = checksum

			// Validate checksum if provided
			if m.Profile.Checksum != "" && m.Profile.Checksum != checksum {
				return nil, fmt.Errorf("profile checksum mismatch: expected %s, got %s", m.Profile.Checksum, checksum)
			}

			// Load profile content for inline distribution
			if m.Profile.Distribution == "inline" {
				content, err := os.ReadFile(profilePath)
				if err != nil {
					return nil, fmt.Errorf("read profile for inline distribution: %w", err)
				}
				resolved.ProfileContent = string(content)
			}
		}
	}

	// Build server args
	if m.Roles.Server != nil {
		resolved.ServerArgs = buildServerArgs(m, profilePath)
	}

	// Build client args
	if m.Roles.Client != nil {
		resolved.ClientArgs = buildClientArgs(m, profilePath)
	}

	return resolved, nil
}

// buildServerArgs constructs CLI arguments for the server role.
func buildServerArgs(m *Manifest, profilePath string) []string {
	args := []string{"server"}

	// Listen IP
	args = append(args, "--listen-ip", m.Network.DataPlane.ServerListenIP)

	// Port
	if m.Network.DataPlane.TargetPort != 0 {
		args = append(args, "--listen-port", strconv.Itoa(m.Network.DataPlane.TargetPort))
	}

	// Personality
	if m.Roles.Server.Personality != "" {
		args = append(args, "--personality", m.Roles.Server.Personality)
	}

	// Note: Server --profile expects a profile NAME (not path) that gets looked up in profiles/
	// The manifest profile.path is for client profile-based scenarios, not server config
	// Server config should be passed via --server-config if needed

	// PCAP from args
	if pcap, ok := m.Roles.Server.Args["pcap"].(string); ok && pcap != "" {
		args = append(args, "--pcap", pcap)
	}

	// Enable TUI stats for readiness detection
	args = append(args, "--tui-stats")

	// Additional args from manifest
	for key, val := range m.Roles.Server.Args {
		if key == "pcap" {
			continue // Already handled
		}
		switch v := val.(type) {
		case bool:
			if v {
				args = append(args, "--"+key)
			}
		case string:
			if v != "" {
				args = append(args, "--"+key, v)
			}
		case int:
			args = append(args, "--"+key, strconv.Itoa(v))
		case float64:
			args = append(args, "--"+key, strconv.Itoa(int(v)))
		}
	}

	return args
}

// buildClientArgs constructs CLI arguments for the client role.
func buildClientArgs(m *Manifest, profilePath string) []string {
	args := []string{"client"}

	// Target IP
	args = append(args, "--ip", m.Network.DataPlane.TargetIP)

	// Port
	if m.Network.DataPlane.TargetPort != 0 {
		args = append(args, "--port", strconv.Itoa(m.Network.DataPlane.TargetPort))
	}

	// Scenario
	if m.Roles.Client.Scenario == "profile" {
		args = append(args, "--profile", profilePath)
		if m.Roles.Client.ProfileRole != "" {
			args = append(args, "--role", m.Roles.Client.ProfileRole)
		}
	} else {
		args = append(args, "--scenario", m.Roles.Client.Scenario)
	}

	// Duration
	args = append(args, "--duration-seconds", strconv.Itoa(m.Roles.Client.DurationSeconds))

	// Interval
	if m.Roles.Client.IntervalMs > 0 {
		args = append(args, "--interval-ms", strconv.Itoa(m.Roles.Client.IntervalMs))
	}

	// PCAP from args
	if pcap, ok := m.Roles.Client.Args["pcap"].(string); ok && pcap != "" {
		args = append(args, "--pcap", pcap)
	}

	// Enable TUI stats
	args = append(args, "--tui-stats")

	// Additional args from manifest
	for key, val := range m.Roles.Client.Args {
		if key == "pcap" {
			continue // Already handled
		}
		switch v := val.(type) {
		case bool:
			if v {
				args = append(args, "--"+key)
			}
		case string:
			if v != "" {
				args = append(args, "--"+key, v)
			}
		case int:
			args = append(args, "--"+key, strconv.Itoa(v))
		case float64:
			args = append(args, "--"+key, strconv.Itoa(int(v)))
		}
	}

	return args
}

// computeFileChecksum calculates the SHA256 checksum of a file.
func computeFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ToYAML returns the resolved manifest as YAML bytes.
func (r *ResolvedManifest) ToYAML() ([]byte, error) {
	return yaml.Marshal(r)
}

// SaveYAML writes the resolved manifest to a YAML file.
func (r *ResolvedManifest) SaveYAML(path string) error {
	// Use the embedded Manifest's SaveYAML but with resolved content
	// We need to manually marshal since ResolvedManifest has additional fields

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	// Write header comment
	fmt.Fprintf(f, "# Resolved manifest generated at %s\n", r.ResolvedAt)
	fmt.Fprintf(f, "# Tool version: %s\n", r.ToolVersion)
	fmt.Fprintf(f, "# Controller: %s/%s\n\n", r.ControllerOS, r.ControllerArch)

	// Marshal the rest
	encoder := yaml.NewEncoder(f)
	encoder.SetIndent(2)
	if err := encoder.Encode(r); err != nil {
		return fmt.Errorf("encode YAML: %w", err)
	}

	return nil
}
