package ui

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AgentStatus represents the current status of an agent.
type AgentStatus string

const (
	AgentStatusUnknown     AgentStatus = "unknown"
	AgentStatusOK          AgentStatus = "ok"
	AgentStatusUnreachable AgentStatus = "unreachable"
	AgentStatusNoCipdip    AgentStatus = "no_cipdip"
	AgentStatusError       AgentStatus = "error"
)

// Agent represents a registered remote agent.
type Agent struct {
	Name        string      `yaml:"name"`
	Transport   string      `yaml:"transport"`
	Description string      `yaml:"description,omitempty"`
	LastCheck   time.Time   `yaml:"last_check,omitempty"`
	Status      AgentStatus `yaml:"status,omitempty"`
	StatusMsg   string      `yaml:"status_msg,omitempty"`

	// Cached capabilities (from last check)
	OSArch      string `yaml:"os_arch,omitempty"`
	CipdipVer   string `yaml:"cipdip_version,omitempty"`
	PCAPCapable bool   `yaml:"pcap_capable,omitempty"`
}

// AgentRegistry manages the collection of registered agents.
type AgentRegistry struct {
	Agents  map[string]*Agent `yaml:"agents"`
	path    string
	version string `yaml:"version,omitempty"`
}

// AgentsFileName is the name of the agents configuration file.
const AgentsFileName = "agents.yaml"

// LoadAgentRegistry loads the agent registry from a workspace path.
func LoadAgentRegistry(workspacePath string) (*AgentRegistry, error) {
	path := filepath.Join(workspacePath, AgentsFileName)

	registry := &AgentRegistry{
		Agents:  make(map[string]*Agent),
		path:    path,
		version: "v1",
	}

	// If file doesn't exist, return empty registry
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return registry, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agents file: %w", err)
	}

	if err := yaml.Unmarshal(data, registry); err != nil {
		return nil, fmt.Errorf("parse agents file: %w", err)
	}

	registry.path = path
	return registry, nil
}

// Save writes the agent registry to disk.
func (r *AgentRegistry) Save() error {
	if r.path == "" {
		return fmt.Errorf("no path set for agent registry")
	}

	// Ensure directory exists
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data, err := yaml.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal agents: %w", err)
	}

	if err := os.WriteFile(r.path, data, 0644); err != nil {
		return fmt.Errorf("write agents file: %w", err)
	}

	return nil
}

// Add adds or updates an agent in the registry.
func (r *AgentRegistry) Add(agent *Agent) {
	if r.Agents == nil {
		r.Agents = make(map[string]*Agent)
	}
	r.Agents[agent.Name] = agent
}

// Remove removes an agent from the registry.
func (r *AgentRegistry) Remove(name string) bool {
	if _, exists := r.Agents[name]; exists {
		delete(r.Agents, name)
		return true
	}
	return false
}

// Get retrieves an agent by name.
func (r *AgentRegistry) Get(name string) (*Agent, bool) {
	agent, exists := r.Agents[name]
	return agent, exists
}

// List returns all agents sorted by name.
func (r *AgentRegistry) List() []*Agent {
	agents := make([]*Agent, 0, len(r.Agents))
	for _, agent := range r.Agents {
		agents = append(agents, agent)
	}
	// Sort by name
	for i := 0; i < len(agents)-1; i++ {
		for j := i + 1; j < len(agents); j++ {
			if agents[i].Name > agents[j].Name {
				agents[i], agents[j] = agents[j], agents[i]
			}
		}
	}
	return agents
}

// Path returns the file path of the registry.
func (r *AgentRegistry) Path() string {
	return r.path
}

// SSHInfo contains parsed SSH connection details.
type SSHInfo struct {
	User     string
	Host     string
	Port     string
	KeyFile  string
	Insecure bool
}

// ParseSSHTransport parses an SSH transport string into components.
func ParseSSHTransport(transport string) (*SSHInfo, error) {
	info := &SSHInfo{
		Port: "22",
	}

	// Handle ssh:// URL format
	if strings.HasPrefix(transport, "ssh://") {
		transport = strings.TrimPrefix(transport, "ssh://")

		// Extract query params
		if idx := strings.Index(transport, "?"); idx != -1 {
			query := transport[idx+1:]
			transport = transport[:idx]

			for _, param := range strings.Split(query, "&") {
				parts := strings.SplitN(param, "=", 2)
				if len(parts) == 2 {
					switch parts[0] {
					case "key":
						info.KeyFile = parts[1]
					case "insecure":
						info.Insecure = parts[1] == "true"
					}
				}
			}
		}
	}

	// Parse user@host:port
	if idx := strings.Index(transport, "@"); idx != -1 {
		info.User = transport[:idx]
		transport = transport[idx+1:]
	}

	// Parse host:port
	if host, port, err := net.SplitHostPort(transport); err == nil {
		info.Host = host
		info.Port = port
	} else {
		info.Host = transport
	}

	if info.Host == "" {
		return nil, fmt.Errorf("no host specified")
	}

	return info, nil
}

// ToTransport converts SSHInfo back to a transport string.
func (s *SSHInfo) ToTransport() string {
	var sb strings.Builder
	sb.WriteString("ssh://")

	if s.User != "" {
		sb.WriteString(s.User)
		sb.WriteString("@")
	}

	sb.WriteString(s.Host)

	if s.Port != "" && s.Port != "22" {
		sb.WriteString(":")
		sb.WriteString(s.Port)
	}

	var params []string
	if s.KeyFile != "" {
		params = append(params, "key="+s.KeyFile)
	}
	if s.Insecure {
		params = append(params, "insecure=true")
	}

	if len(params) > 0 {
		sb.WriteString("?")
		sb.WriteString(strings.Join(params, "&"))
	}

	return sb.String()
}

// SSHKeyInfo contains information about an SSH key.
type SSHKeyInfo struct {
	Path        string
	Type        string // ed25519, rsa, ecdsa
	Fingerprint string
	HasPub      bool
}

// FindSSHKeys finds SSH keys in the default location.
func FindSSHKeys() ([]SSHKeyInfo, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	sshDir := filepath.Join(home, ".ssh")
	keyTypes := []string{"id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"}

	var keys []SSHKeyInfo
	for _, keyName := range keyTypes {
		keyPath := filepath.Join(sshDir, keyName)
		if _, err := os.Stat(keyPath); err == nil {
			keyType := strings.TrimPrefix(keyName, "id_")
			pubPath := keyPath + ".pub"
			hasPub := false
			if _, err := os.Stat(pubPath); err == nil {
				hasPub = true
			}

			keys = append(keys, SSHKeyInfo{
				Path:   keyPath,
				Type:   strings.ToUpper(keyType),
				HasPub: hasPub,
			})
		}
	}

	return keys, nil
}

// SSHAgentStatus checks if ssh-agent is running and has keys loaded.
type SSHAgentStatus struct {
	Running    bool
	SocketPath string
	KeyCount   int
	Keys       []string
}

// CheckSSHAgent checks the status of the SSH agent.
func CheckSSHAgent() *SSHAgentStatus {
	status := &SSHAgentStatus{}

	// Check for SSH_AUTH_SOCK
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		return status
	}

	status.SocketPath = socketPath

	// Try to list keys
	cmd := exec.Command("ssh-add", "-l")
	output, err := cmd.Output()
	if err != nil {
		// Exit code 1 means no keys, exit code 2 means agent not running
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				status.Running = true
				status.KeyCount = 0
				return status
			}
		}
		return status
	}

	status.Running = true
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line != "" && !strings.Contains(line, "no identities") {
			status.KeyCount++
			status.Keys = append(status.Keys, line)
		}
	}

	return status
}

// GenerateSSHKey generates a new SSH key pair.
func GenerateSSHKey(keyPath, comment string) error {
	// Use ed25519 as it's the most secure and modern
	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-f", keyPath,
		"-N", "", // Empty passphrase (user can add later)
		"-C", comment,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// AddToKnownHosts adds a host's key to known_hosts using ssh-keyscan.
func AddToKnownHosts(host, port string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")

	// Ensure .ssh directory exists
	sshDir := filepath.Dir(knownHostsPath)
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("create .ssh directory: %w", err)
	}

	// Run ssh-keyscan
	args := []string{"-H"} // Hash hostnames
	if port != "" && port != "22" {
		args = append(args, "-p", port)
	}
	args = append(args, host)

	cmd := exec.Command("ssh-keyscan", args...)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("ssh-keyscan failed: %w", err)
	}

	if len(output) == 0 {
		return fmt.Errorf("no host keys found for %s", host)
	}

	// Append to known_hosts
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open known_hosts: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(output); err != nil {
		return fmt.Errorf("write to known_hosts: %w", err)
	}

	return nil
}

// CheckHostInKnownHosts checks if a host is in known_hosts.
func CheckHostInKnownHosts(host, port string) (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}

	knownHostsPath := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(knownHostsPath); os.IsNotExist(err) {
		return false, nil
	}

	// Use ssh-keygen to check
	hostSpec := host
	if port != "" && port != "22" {
		hostSpec = fmt.Sprintf("[%s]:%s", host, port)
	}

	cmd := exec.Command("ssh-keygen", "-F", hostSpec)
	output, _ := cmd.Output()

	return len(output) > 0, nil
}

// RunSSHCopyID runs ssh-copy-id to set up key-based authentication.
// This will prompt for password interactively.
func RunSSHCopyID(user, host, port, keyFile string) error {
	args := []string{}

	if keyFile != "" {
		args = append(args, "-i", keyFile)
	}

	if port != "" && port != "22" {
		args = append(args, "-p", port)
	}

	target := host
	if user != "" {
		target = user + "@" + host
	}
	args = append(args, target)

	cmd := exec.Command("ssh-copy-id", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// GetHostKey retrieves the host key fingerprint for a remote host.
func GetHostKey(host, port string) (string, string, error) {
	args := []string{}
	if port != "" && port != "22" {
		args = append(args, "-p", port)
	}
	args = append(args, host)

	cmd := exec.Command("ssh-keyscan", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("ssh-keyscan failed: %w", err)
	}

	if len(output) == 0 {
		return "", "", fmt.Errorf("no host keys found")
	}

	// Parse first key line to get type
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			keyType := parts[1]

			// Get fingerprint
			cmd2 := exec.Command("ssh-keygen", "-lf", "-")
			cmd2.Stdin = strings.NewReader(line)
			fpOutput, err := cmd2.Output()
			if err == nil {
				fp := strings.TrimSpace(string(fpOutput))
				return keyType, fp, nil
			}
			return keyType, "", nil
		}
	}

	return "", "", fmt.Errorf("could not parse host key")
}

// TestSSHConnection tests SSH connectivity to a remote host.
func TestSSHConnection(user, host, port string) error {
	target := host
	if user != "" {
		target = user + "@" + host
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new",
	}

	if port != "" && port != "22" {
		args = append(args, "-p", port)
	}

	args = append(args, target, "echo", "ok")

	cmd := exec.Command("ssh", args...)
	_, err := cmd.Output()
	return err
}
