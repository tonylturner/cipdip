// Package transport provides abstractions for local and remote command execution
// and file transfer, supporting both local execution and SSH-based remote execution.
package transport

import (
	"context"
	"io"
	"os"
	"time"
)

// Transport abstracts remote/local execution and file transfer.
type Transport interface {
	// Exec runs a command and returns exit code, stdout, stderr.
	// cmd is the command as argv (not shell string).
	// env is additional environment variables.
	// cwd is the working directory (empty = default).
	Exec(ctx context.Context, cmd []string, env map[string]string, cwd string) (exitCode int, stdout, stderr string, err error)

	// ExecStream runs a command with streaming stdout/stderr.
	// Used for long-running processes where we need to monitor output.
	ExecStream(ctx context.Context, cmd []string, env map[string]string, cwd string, stdout, stderr io.Writer) (exitCode int, err error)

	// Put copies a local file to remote path.
	Put(ctx context.Context, localPath, remotePath string) error

	// Get copies a remote file to local path.
	Get(ctx context.Context, remotePath, localPath string) error

	// Mkdir creates a directory (and parents) on remote.
	Mkdir(ctx context.Context, remotePath string) error

	// Stat returns file info for remote path.
	Stat(ctx context.Context, remotePath string) (os.FileInfo, error)

	// Remove deletes a file or empty directory.
	Remove(ctx context.Context, remotePath string) error

	// Close releases any held resources (e.g., SSH connection).
	Close() error

	// String returns a human-readable description of the transport.
	String() string
}

// Options configures transport behavior.
type Options struct {
	Timeout       time.Duration // Default command timeout
	RetryAttempts int           // Retries on transient failures
	RetryDelay    time.Duration // Delay between retries
}

// DefaultOptions returns sensible default options.
func DefaultOptions() Options {
	return Options{
		Timeout:       5 * time.Minute,
		RetryAttempts: 3,
		RetryDelay:    time.Second,
	}
}

// SSHOptions configures SSH-specific transport behavior.
type SSHOptions struct {
	Options

	// Authentication
	User           string // SSH username
	KeyFile        string // Path to private key file
	KeyPassphrase  string // Passphrase for encrypted key (optional)
	Password       string // Password authentication (fallback)
	Agent          bool   // Use SSH agent for authentication

	// Host verification
	KnownHostsFile     string // Path to known_hosts file
	InsecureIgnoreHost bool   // Skip host key verification (dangerous)

	// Connection
	Port           int           // SSH port (default 22)
	ConnectTimeout time.Duration // Connection timeout
	KeepAlive      time.Duration // Keep-alive interval
}

// DefaultSSHOptions returns sensible default SSH options.
func DefaultSSHOptions() SSHOptions {
	return SSHOptions{
		Options:        DefaultOptions(),
		Port:           22,
		ConnectTimeout: 30 * time.Second,
		KeepAlive:      30 * time.Second,
		Agent:          true, // Try SSH agent by default
	}
}
