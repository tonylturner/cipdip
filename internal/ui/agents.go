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
	Elevate     bool        `yaml:"elevate,omitempty"` // Use sudo (Unix) or admin (Windows)

	// Cached capabilities (from last check)
	OSArch           string `yaml:"os_arch,omitempty"`
	CipdipVer        string `yaml:"cipdip_version,omitempty"`
	PCAPCapable      bool   `yaml:"pcap_capable,omitempty"`
	ElevateAvailable bool   `yaml:"elevate_available,omitempty"`
	ElevateMethod    string `yaml:"elevate_method,omitempty"` // "sudo" or "admin"
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
	OS       string // Remote OS: linux, windows, darwin (empty = linux)
	Elevate  bool   // Use sudo (Unix) or admin (Windows) for commands
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
					case "os":
						info.OS = parts[1]
					case "elevate":
						info.Elevate = parts[1] == "true"
					}
				}
			}
		}
	}

	// Parse user@host:port
	// Use LastIndex because usernames can contain @ (e.g., name@domain@host)
	if idx := strings.LastIndex(transport, "@"); idx != -1 {
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
	if s.OS != "" && s.OS != "linux" {
		params = append(params, "os="+s.OS)
	}
	if s.Elevate {
		params = append(params, "elevate=true")
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
	Name        string // Base name (e.g., "id_ed25519_cipdip")
	Type        string // ed25519, rsa, ecdsa
	Fingerprint string
	HasPub      bool
}

// FindSSHKeys finds all SSH private keys in ~/.ssh directory.
// Looks for any file that has a corresponding .pub file, or starts with "id_".
func FindSSHKeys() ([]SSHKeyInfo, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	sshDir := filepath.Join(home, ".ssh")
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}

	// Build a set of .pub files to identify private keys
	pubFiles := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".pub") {
			// Store the base name (without .pub)
			pubFiles[strings.TrimSuffix(name, ".pub")] = true
		}
	}

	var keys []SSHKeyInfo
	seen := make(map[string]bool)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Skip .pub files, known_hosts, config, etc.
		if strings.HasSuffix(name, ".pub") ||
			name == "known_hosts" ||
			name == "known_hosts.old" ||
			name == "config" ||
			name == "authorized_keys" {
			continue
		}

		// A file is likely a private key if:
		// 1. It has a corresponding .pub file, OR
		// 2. It starts with "id_"
		isKey := pubFiles[name] || strings.HasPrefix(name, "id_")
		if !isKey {
			continue
		}

		// Skip if already seen
		if seen[name] {
			continue
		}
		seen[name] = true

		keyPath := filepath.Join(sshDir, name)

		// Determine key type from name
		keyType := "UNKNOWN"
		if strings.Contains(name, "ed25519") {
			keyType = "ED25519"
		} else if strings.Contains(name, "ecdsa") {
			keyType = "ECDSA"
		} else if strings.Contains(name, "rsa") {
			keyType = "RSA"
		} else if strings.Contains(name, "dsa") {
			keyType = "DSA"
		}

		keys = append(keys, SSHKeyInfo{
			Path:   keyPath,
			Name:   name,
			Type:   keyType,
			HasPub: pubFiles[name],
		})
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
// keyFile is optional - if empty, uses default SSH key discovery.
func TestSSHConnection(user, host, port, keyFile string) error {
	target := host
	if user != "" {
		target = user + "@" + host
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new",
	}

	if keyFile != "" {
		args = append(args, "-i", keyFile)
	}

	if port != "" && port != "22" {
		args = append(args, "-p", port)
	}

	args = append(args, target, "echo", "ok")

	cmd := exec.Command("ssh", args...)
	_, err := cmd.Output()
	return err
}

// AgentCapabilities holds remote agent capability info.
type AgentCapabilities struct {
	OSArch           string
	Version          string
	PCAPCapable      bool
	ElevateAvailable bool   // sudo (Unix) or admin (Windows) available
	ElevateMethod    string // "sudo", "admin", or empty if not available
}

// GetRemoteAgentCapabilities queries a remote agent for its capabilities.
func GetRemoteAgentCapabilities(info *SSHInfo) (*AgentCapabilities, error) {
	target := info.Host
	if info.User != "" {
		target = info.User + "@" + info.Host
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new",
	}

	if info.KeyFile != "" {
		args = append(args, "-i", info.KeyFile)
	}

	if info.Port != "" && info.Port != "22" {
		args = append(args, "-p", info.Port)
	}

	args = append(args, target)

	// Use login shell to get full PATH on remote
	if info.OS == "windows" {
		args = append(args, "cipdip", "agent", "status")
	} else {
		// Source common profile files to get PATH (homebrew, go bin, etc.)
		args = append(args, "source ~/.zprofile 2>/dev/null; source ~/.bash_profile 2>/dev/null; source ~/.profile 2>/dev/null; cipdip agent status")
	}

	cmd := exec.Command("ssh", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse output - looks for lines like:
	// OS/Arch: darwin/arm64
	// Version: 0.2.1
	// Status:   OK (tcpdump)  or  Status:   NOT AVAILABLE
	caps := &AgentCapabilities{}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "OS/Arch:") {
			caps.OSArch = strings.TrimSpace(strings.TrimPrefix(line, "OS/Arch:"))
		} else if strings.HasPrefix(line, "Version:") {
			caps.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Status:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			// PCAP is available if status contains "OK" (e.g., "OK (tcpdump)" or "OK (npcap)")
			caps.PCAPCapable = strings.Contains(val, "OK")
		}
	}

	// Check elevation capabilities
	caps.ElevateAvailable, caps.ElevateMethod = checkRemoteElevation(info)

	return caps, nil
}

// checkRemoteElevation checks if elevated privileges are available on the remote host.
func checkRemoteElevation(info *SSHInfo) (bool, string) {
	target := info.Host
	if info.User != "" {
		target = info.User + "@" + info.Host
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		"-o", "StrictHostKeyChecking=accept-new",
	}

	if info.KeyFile != "" {
		args = append(args, "-i", info.KeyFile)
	}

	if info.Port != "" && info.Port != "22" {
		args = append(args, "-p", info.Port)
	}

	args = append(args, target)

	if info.OS == "windows" {
		// On Windows, check if user is admin by trying to access a protected resource
		// "net session" returns 0 if running as admin, non-zero otherwise
		checkArgs := append(args, "net", "session")
		cmd := exec.Command("ssh", checkArgs...)
		if err := cmd.Run(); err == nil {
			return true, "admin"
		}
		return false, ""
	}

	// On Unix, check if passwordless sudo is available
	// sudo -n true returns 0 if sudo works without password
	checkArgs := append(args, "sudo -n true 2>/dev/null")
	cmd := exec.Command("ssh", checkArgs...)
	if err := cmd.Run(); err == nil {
		return true, "sudo"
	}
	return false, ""
}
