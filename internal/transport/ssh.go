package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSH implements Transport for remote execution over SSH.
type SSH struct {
	opts   SSHOptions
	host   string
	client *ssh.Client
	sftp   *sftp.Client
	mu     sync.Mutex
}

// NewSSH creates a new SSH transport.
func NewSSH(host string, opts SSHOptions) (*SSH, error) {
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}

	s := &SSH{
		opts: opts,
		host: host,
	}

	return s, nil
}

// connect establishes the SSH connection if not already connected.
func (s *SSH) connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		return nil
	}

	config, err := s.buildSSHConfig()
	if err != nil {
		return fmt.Errorf("build SSH config: %w", err)
	}

	// Build address (use JoinHostPort to properly handle IPv6)
	port := s.opts.Port
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(s.host, strconv.Itoa(port))

	// Connect with timeout
	var conn net.Conn
	timeout := s.opts.ConnectTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err = dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}

	// SSH handshake
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SSH handshake: %w", err)
	}

	s.client = ssh.NewClient(sshConn, chans, reqs)

	// Set up keep-alive if configured
	if s.opts.KeepAlive > 0 {
		go s.keepAlive()
	}

	return nil
}

// buildSSHConfig builds the SSH client configuration.
func (s *SSH) buildSSHConfig() (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	// Try SSH agent first
	if s.opts.Agent {
		if agentAuth := sshAgentAuth(); agentAuth != nil {
			authMethods = append(authMethods, agentAuth)
		}
	}

	// Try key file
	if s.opts.KeyFile != "" {
		keyAuth, err := publicKeyAuth(s.opts.KeyFile, s.opts.KeyPassphrase)
		if err != nil {
			return nil, fmt.Errorf("key file auth: %w", err)
		}
		authMethods = append(authMethods, keyAuth)
	}

	// Try default key files if no key specified
	if s.opts.KeyFile == "" && !s.opts.Agent {
		for _, keyPath := range defaultKeyPaths() {
			if keyAuth, err := publicKeyAuth(keyPath, ""); err == nil {
				authMethods = append(authMethods, keyAuth)
				break
			}
		}
	}

	// Password authentication as fallback
	if s.opts.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.opts.Password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods available")
	}

	// Host key callback
	var hostKeyCallback ssh.HostKeyCallback
	if s.opts.InsecureIgnoreHost {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else if s.opts.KnownHostsFile != "" {
		var err error
		hostKeyCallback, err = knownhosts.New(s.opts.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("known hosts: %w", err)
		}
	} else {
		// Try default known_hosts (cross-platform home directory)
		if home, err := os.UserHomeDir(); err == nil {
			defaultKnownHosts := filepath.Join(home, ".ssh", "known_hosts")
			if _, err := os.Stat(defaultKnownHosts); err == nil {
				hostKeyCallback, _ = knownhosts.New(defaultKnownHosts)
			}
		}
		if hostKeyCallback == nil {
			// Fall back to insecure if no known_hosts available
			// In production, you'd want to handle this more carefully
			hostKeyCallback = ssh.InsecureIgnoreHostKey()
		}
	}

	user := s.opts.User
	if user == "" {
		// Cross-platform username detection
		user = os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME") // Windows
		}
	}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         s.opts.ConnectTimeout,
	}, nil
}

// keepAlive sends periodic keep-alive requests.
func (s *SSH) keepAlive() {
	ticker := time.NewTicker(s.opts.KeepAlive)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		client := s.client
		s.mu.Unlock()

		if client == nil {
			return
		}

		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			return
		}
	}
}

// getSFTP returns the SFTP client, creating it if necessary.
func (s *SSH) getSFTP() (*sftp.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sftp != nil {
		return s.sftp, nil
	}

	if s.client == nil {
		return nil, fmt.Errorf("not connected")
	}

	sftpClient, err := sftp.NewClient(s.client)
	if err != nil {
		return nil, fmt.Errorf("create SFTP client: %w", err)
	}

	s.sftp = sftpClient
	return s.sftp, nil
}

// Exec runs a command remotely and returns exit code, stdout, stderr.
func (s *SSH) Exec(ctx context.Context, cmd []string, env map[string]string, cwd string) (int, string, string, error) {
	if err := s.connect(); err != nil {
		return -1, "", "", err
	}

	session, err := s.client.NewSession()
	if err != nil {
		return -1, "", "", fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Set environment variables
	for k, v := range env {
		if err := session.Setenv(k, v); err != nil {
			// Some servers don't allow setting env vars, ignore
		}
	}

	// Build command string with elevation if configured
	cmdStr := buildCommandString(cmd, cwd, s.opts.Elevate, s.opts.RemoteOS)

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Handle context cancellation
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmdStr)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return -1, stdout.String(), stderr.String(), ctx.Err()
	case err := <-done:
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				exitCode = exitErr.ExitStatus()
				err = nil
			}
		}
		return exitCode, stdout.String(), stderr.String(), err
	}
}

// ExecStream runs a command with streaming stdout/stderr.
func (s *SSH) ExecStream(ctx context.Context, cmd []string, env map[string]string, cwd string, stdout, stderr io.Writer) (int, error) {
	if err := s.connect(); err != nil {
		return -1, err
	}

	session, err := s.client.NewSession()
	if err != nil {
		return -1, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Set environment variables
	for k, v := range env {
		session.Setenv(k, v)
	}

	// Build command string with elevation if configured
	cmdStr := buildCommandString(cmd, cwd, s.opts.Elevate, s.opts.RemoteOS)

	session.Stdout = stdout
	session.Stderr = stderr

	// Handle context cancellation
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmdStr)
	}()

	select {
	case <-ctx.Done():
		session.Signal(ssh.SIGKILL)
		return -1, ctx.Err()
	case err := <-done:
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*ssh.ExitError); ok {
				exitCode = exitErr.ExitStatus()
				err = nil
			}
		}
		return exitCode, err
	}
}

// Put copies a local file to the remote host.
func (s *SSH) Put(ctx context.Context, localPath, remotePath string) error {
	if err := s.connect(); err != nil {
		return err
	}

	sftpClient, err := s.getSFTP()
	if err != nil {
		return err
	}

	// Open local file
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer localFile.Close()

	// Get local file info for permissions
	localInfo, err := localFile.Stat()
	if err != nil {
		return fmt.Errorf("stat local file: %w", err)
	}

	// Ensure remote directory exists
	remoteDir := filepath.Dir(remotePath)
	if err := sftpClient.MkdirAll(remoteDir); err != nil {
		// Ignore error, directory might exist
	}

	// Create remote file
	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file: %w", err)
	}
	defer remoteFile.Close()

	// Copy content
	if _, err := io.Copy(remoteFile, localFile); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	// Set permissions
	if err := sftpClient.Chmod(remotePath, localInfo.Mode()); err != nil {
		// Ignore permission errors
	}

	return nil
}

// Get copies a remote file to the local host.
func (s *SSH) Get(ctx context.Context, remotePath, localPath string) error {
	if err := s.connect(); err != nil {
		return err
	}

	sftpClient, err := s.getSFTP()
	if err != nil {
		return err
	}

	// Open remote file
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open remote file: %w", err)
	}
	defer remoteFile.Close()

	// Get remote file info for permissions
	remoteInfo, err := remoteFile.Stat()
	if err != nil {
		return fmt.Errorf("stat remote file: %w", err)
	}

	// Ensure local directory exists
	localDir := filepath.Dir(localPath)
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return fmt.Errorf("create local directory: %w", err)
	}

	// Create local file
	localFile, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, remoteInfo.Mode())
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}
	defer localFile.Close()

	// Copy content
	if _, err := io.Copy(localFile, remoteFile); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return localFile.Sync()
}

// Mkdir creates a directory on the remote host.
func (s *SSH) Mkdir(ctx context.Context, path string) error {
	if err := s.connect(); err != nil {
		return err
	}

	sftpClient, err := s.getSFTP()
	if err != nil {
		return err
	}

	return sftpClient.MkdirAll(path)
}

// Stat returns file info for a remote path.
func (s *SSH) Stat(ctx context.Context, path string) (os.FileInfo, error) {
	if err := s.connect(); err != nil {
		return nil, err
	}

	sftpClient, err := s.getSFTP()
	if err != nil {
		return nil, err
	}

	return sftpClient.Stat(path)
}

// Remove deletes a file or empty directory on the remote host.
func (s *SSH) Remove(ctx context.Context, path string) error {
	if err := s.connect(); err != nil {
		return err
	}

	sftpClient, err := s.getSFTP()
	if err != nil {
		return err
	}

	return sftpClient.Remove(path)
}

// Close closes the SSH connection.
func (s *SSH) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error

	if s.sftp != nil {
		if err := s.sftp.Close(); err != nil {
			errs = append(errs, err)
		}
		s.sftp = nil
	}

	if s.client != nil {
		if err := s.client.Close(); err != nil {
			errs = append(errs, err)
		}
		s.client = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// String returns a description of this transport.
func (s *SSH) String() string {
	user := s.opts.User
	if user == "" {
		// Cross-platform username detection
		user = os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME") // Windows
		}
		if user == "" {
			user = "unknown"
		}
	}
	port := s.opts.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("ssh://%s@%s:%d", user, s.host, port)
}

// RemoteOS returns the configured remote operating system.
// Returns "linux" if not specified.
func (s *SSH) RemoteOS() string {
	if s.opts.RemoteOS != "" {
		return s.opts.RemoteOS
	}
	return "linux"
}

// IsWindows returns true if the remote host is Windows.
func (s *SSH) IsWindows() bool {
	return s.RemoteOS() == "windows"
}

// NeedsElevation returns true if commands should run with elevated privileges.
func (s *SSH) NeedsElevation() bool {
	return s.opts.Elevate
}

// Helper functions

// sshAgentAuth returns an SSH agent authentication method.
// Supports Unix sockets (Linux/macOS). On Windows, SSH agent is handled via
// sshAgentAuthWindows in ssh_agent_windows.go, or falls back to key file auth.
func sshAgentAuth() ssh.AuthMethod {
	// Check for SSH_AUTH_SOCK (works on Unix, and some Windows SSH tools)
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		// On Windows, try platform-specific agent connection
		if runtime.GOOS == "windows" {
			return sshAgentAuthWindows()
		}
		return nil
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}

	agentClient := agent.NewClient(conn)
	return ssh.PublicKeysCallback(agentClient.Signers)
}

// sshAgentAuthWindows attempts to connect to Windows OpenSSH agent.
// This is a stub that returns nil - Windows named pipe support requires
// the github.com/Microsoft/go-winio package which isn't imported.
// Users should use explicit key file authentication on Windows instead:
//   ssh://user@host?key=C:/Users/name/.ssh/id_ed25519&agent=false
func sshAgentAuthWindows() ssh.AuthMethod {
	// Windows OpenSSH agent uses named pipe: \\.\pipe\openssh-ssh-agent
	// Full support requires go-winio. For now, users should use key file auth.
	// To enable: add "github.com/Microsoft/go-winio" and use winio.DialPipe()
	return nil
}

// publicKeyAuth returns a public key authentication method.
func publicKeyAuth(keyPath, passphrase string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(key)
	}
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(signer), nil
}

// defaultKeyPaths returns default SSH key file paths.
// Uses os.UserHomeDir() for cross-platform compatibility (works on Windows, macOS, Linux).
func defaultKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}
}

// buildCommandString builds a shell command string.
func buildCommandString(cmd []string, cwd string, elevate bool, remoteOS string) string {
	if len(cmd) == 0 {
		return ""
	}

	// Quote arguments that need it
	var parts []string
	for _, arg := range cmd {
		if needsQuoting(arg) {
			parts = append(parts, fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''")))
		} else {
			parts = append(parts, arg)
		}
	}

	cmdStr := strings.Join(parts, " ")

	// Prepend sudo for Unix systems if elevation is requested
	if elevate && remoteOS != "windows" {
		cmdStr = "sudo " + cmdStr
	}

	if cwd != "" {
		if elevate && remoteOS != "windows" {
			// For elevated commands with cwd, use sudo for the cd as well
			return fmt.Sprintf("cd %s && sudo %s", cwd, strings.Join(parts, " "))
		}
		return fmt.Sprintf("cd %s && %s", cwd, cmdStr)
	}

	return cmdStr
}

// needsQuoting returns true if the string needs shell quoting.
func needsQuoting(s string) bool {
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '"', '\'', '\\', '$', '`', '!', '*', '?', '[', ']', '(', ')', '{', '}', '<', '>', '|', '&', ';':
			return true
		}
	}
	return false
}

// Ensure SSH implements Transport
var _ Transport = (*SSH)(nil)
