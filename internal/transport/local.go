package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// Local implements Transport for local execution.
type Local struct {
	opts Options
}

// NewLocal creates a new local transport.
func NewLocal(opts Options) *Local {
	return &Local{opts: opts}
}

// Exec runs a command locally and returns exit code, stdout, stderr.
func (l *Local) Exec(ctx context.Context, cmd []string, env map[string]string, cwd string) (int, string, string, error) {
	if len(cmd) == 0 {
		return -1, "", "", fmt.Errorf("empty command")
	}

	// Apply timeout if set
	if l.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.opts.Timeout)
		defer cancel()
	}

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	// Set environment
	if len(env) > 0 {
		c.Env = os.Environ()
		for k, v := range env {
			c.Env = append(c.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Set working directory
	if cwd != "" {
		c.Dir = cwd
	}

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			err = nil // Exit with non-zero is not an error per se
		}
	}

	return exitCode, stdout.String(), stderr.String(), err
}

// ExecStream runs a command with streaming stdout/stderr.
func (l *Local) ExecStream(ctx context.Context, cmd []string, env map[string]string, cwd string, stdout, stderr io.Writer) (int, error) {
	if len(cmd) == 0 {
		return -1, fmt.Errorf("empty command")
	}

	// Apply timeout if set
	if l.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.opts.Timeout)
		defer cancel()
	}

	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)

	// Set environment
	if len(env) > 0 {
		c.Env = os.Environ()
		for k, v := range env {
			c.Env = append(c.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Set working directory
	if cwd != "" {
		c.Dir = cwd
	}

	c.Stdout = stdout
	c.Stderr = stderr

	err := c.Run()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			err = nil // Exit with non-zero is not an error per se
		}
	}

	return exitCode, err
}

// Put copies a local file to another local path.
func (l *Local) Put(ctx context.Context, srcPath, dstPath string) error {
	return copyFile(srcPath, dstPath)
}

// Get copies a local file to another local path (same as Put for local).
func (l *Local) Get(ctx context.Context, srcPath, dstPath string) error {
	return copyFile(srcPath, dstPath)
}

// Mkdir creates a directory locally.
func (l *Local) Mkdir(ctx context.Context, path string) error {
	return os.MkdirAll(path, 0755)
}

// Stat returns file info for a local path.
func (l *Local) Stat(ctx context.Context, path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// Remove deletes a file or empty directory locally.
func (l *Local) Remove(ctx context.Context, path string) error {
	return os.Remove(path)
}

// Close is a no-op for local transport.
func (l *Local) Close() error {
	return nil
}

// String returns a description of this transport.
func (l *Local) String() string {
	return "local"
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer srcFile.Close()

	// Get source file info for permissions
	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	return dstFile.Sync()
}

// Ensure Local implements Transport
var _ Transport = (*Local)(nil)
