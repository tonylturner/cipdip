package transport

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Parse parses a transport specification string and returns a Transport.
// Supported formats:
//   - "local" -> LocalTransport
//   - "ssh://user@host:port" -> SSHTransport
//   - "ssh://user@host:port?key=/path&insecure=true" -> SSHTransport with options
//   - "host" (bare hostname) -> SSHTransport with defaults
func Parse(spec string) (Transport, error) {
	return ParseWithOptions(spec, DefaultOptions())
}

// ParseWithOptions parses a transport specification with custom options.
func ParseWithOptions(spec string, opts Options) (Transport, error) {
	// Handle "local" specially
	if spec == "local" || spec == "" {
		return NewLocal(opts), nil
	}

	// Check if it's a URL
	if strings.Contains(spec, "://") {
		return parseURL(spec, opts)
	}

	// Treat as bare hostname for SSH
	return parseSSHHost(spec, opts)
}

// parseURL parses a URL-style transport spec.
func parseURL(spec string, opts Options) (Transport, error) {
	u, err := url.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	switch u.Scheme {
	case "local":
		return NewLocal(opts), nil
	case "ssh":
		return parseSSHURL(u, opts)
	default:
		return nil, fmt.Errorf("unsupported transport scheme: %s", u.Scheme)
	}
}

// parseSSHURL parses an ssh:// URL.
func parseSSHURL(u *url.URL, opts Options) (Transport, error) {
	sshOpts := SSHOptions{
		Options: opts,
	}

	// Extract user
	if u.User != nil {
		sshOpts.User = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			sshOpts.Password = pw
		}
	}

	// Extract host
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("SSH host is required")
	}

	// Extract port
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}
		sshOpts.Port = port
	}

	// Parse query parameters
	q := u.Query()

	if key := q.Get("key"); key != "" {
		sshOpts.KeyFile = key
	}
	if passphrase := q.Get("passphrase"); passphrase != "" {
		sshOpts.KeyPassphrase = passphrase
	}
	if knownHosts := q.Get("known_hosts"); knownHosts != "" {
		sshOpts.KnownHostsFile = knownHosts
	}
	if insecure := q.Get("insecure"); insecure == "true" || insecure == "1" {
		sshOpts.InsecureIgnoreHost = true
	}
	if agent := q.Get("agent"); agent == "false" || agent == "0" {
		sshOpts.Agent = false
	}

	// Remote OS specification (for path handling)
	if remoteOS := q.Get("os"); remoteOS != "" {
		sshOpts.RemoteOS = remoteOS
	}

	return NewSSH(host, sshOpts)
}

// parseSSHHost parses a bare hostname or user@host:port spec.
func parseSSHHost(spec string, opts Options) (Transport, error) {
	sshOpts := SSHOptions{
		Options: opts,
		Agent:   true,
	}

	// Check for user@host format
	// Use LastIndex because usernames can contain @ (e.g., name@domain@host)
	if idx := strings.LastIndex(spec, "@"); idx != -1 {
		sshOpts.User = spec[:idx]
		spec = spec[idx+1:]
	}

	// Check for host:port format
	host := spec
	if idx := strings.LastIndex(spec, ":"); idx != -1 {
		port, err := strconv.Atoi(spec[idx+1:])
		if err == nil {
			sshOpts.Port = port
			host = spec[:idx]
		}
		// If port parse fails, assume the whole thing is the host (e.g., IPv6)
	}

	if host == "" {
		return nil, fmt.Errorf("SSH host is required")
	}

	return NewSSH(host, sshOpts)
}

// ParseSpec is an alias for Parse for backward compatibility.
func ParseSpec(spec string) (Transport, error) {
	return Parse(spec)
}

// MustParse parses a transport spec and panics on error.
// Useful for tests and initialization.
func MustParse(spec string) Transport {
	t, err := Parse(spec)
	if err != nil {
		panic(err)
	}
	return t
}

// IsLocal returns true if the transport spec refers to local execution.
func IsLocal(spec string) bool {
	return spec == "" || spec == "local"
}

// IsSSH returns true if the transport spec refers to SSH execution.
func IsSSH(spec string) bool {
	if spec == "" || spec == "local" {
		return false
	}
	if strings.HasPrefix(spec, "ssh://") {
		return true
	}
	// Bare hostname or user@host
	return true
}
