package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tturner/cipdip/internal/orch/bundle"
)

// Runner manages execution of a single role (server or client).
type Runner struct {
	role     string
	args     []string
	bundle   *bundle.Bundle
	cmd      *exec.Cmd
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	meta     *bundle.RoleMeta

	// Synchronization
	mu       sync.Mutex
	started  bool
	finished bool
	exitCode int
	err      error

	// Output capture
	stdoutBuf strings.Builder
	stderrBuf strings.Builder

	// Readiness detection
	readyCh chan struct{}
	ready   bool

	// Output streaming
	outputCh chan OutputEvent
}

// NewRunner creates a new runner for a role.
func NewRunner(role string, args []string, b *bundle.Bundle) (*Runner, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for role %s", role)
	}

	return &Runner{
		role:     role,
		args:     args,
		bundle:   b,
		readyCh:  make(chan struct{}),
		outputCh: make(chan OutputEvent, 100), // Buffered to avoid blocking
		meta: &bundle.RoleMeta{
			Role: role,
			Argv: args,
		},
	}, nil
}

// Start launches the role process.
func (r *Runner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return fmt.Errorf("runner already started")
	}

	// Build command
	r.cmd = exec.CommandContext(ctx, r.args[0], r.args[1:]...)

	// Set up pipes for stdout/stderr
	var err error
	r.stdout, err = r.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	r.stderr, err = r.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	// Start process
	r.meta.StartedAt = time.Now()
	if err := r.cmd.Start(); err != nil {
		return fmt.Errorf("start process: %w", err)
	}

	r.started = true
	r.meta.AgentID = "local"

	// Start output capture goroutines
	go r.captureStdout()
	go r.captureStderr()

	// Start wait goroutine
	go r.waitForExit()

	return nil
}

// captureStdout reads and captures stdout.
func (r *Runner) captureStdout() {
	scanner := bufio.NewScanner(r.stdout)
	for scanner.Scan() {
		line := scanner.Text()
		now := time.Now()

		r.mu.Lock()
		r.stdoutBuf.WriteString(line)
		r.stdoutBuf.WriteString("\n")
		r.mu.Unlock()

		// Emit output event (non-blocking)
		select {
		case r.outputCh <- OutputEvent{Role: r.role, Stream: "stdout", Line: line, Time: now}:
		default:
			// Channel full, drop event to avoid blocking
		}

		// Check for readiness event
		if !r.ready && strings.Contains(line, `"event":"server_ready"`) {
			r.mu.Lock()
			if !r.ready {
				r.ready = true
				close(r.readyCh)
			}
			r.mu.Unlock()
		}
	}
}

// captureStderr reads and captures stderr.
func (r *Runner) captureStderr() {
	scanner := bufio.NewScanner(r.stderr)
	for scanner.Scan() {
		line := scanner.Text()
		now := time.Now()

		r.mu.Lock()
		r.stderrBuf.WriteString(line)
		r.stderrBuf.WriteString("\n")
		r.mu.Unlock()

		// Emit output event (non-blocking)
		select {
		case r.outputCh <- OutputEvent{Role: r.role, Stream: "stderr", Line: line, Time: now}:
		default:
			// Channel full, drop event to avoid blocking
		}
	}
}

// waitForExit waits for the process to exit.
func (r *Runner) waitForExit() {
	err := r.cmd.Wait()

	r.mu.Lock()
	r.finished = true
	r.meta.FinishedAt = time.Now()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			r.exitCode = exitErr.ExitCode()
			r.meta.ExitCode = r.exitCode
		} else {
			r.err = err
			r.exitCode = -1
			r.meta.ExitCode = -1
		}
	} else {
		r.exitCode = 0
		r.meta.ExitCode = 0
	}
	r.mu.Unlock()

	// Close output channel after process exits
	close(r.outputCh)
}

// Wait waits for the process to complete.
func (r *Runner) Wait(ctx context.Context) (int, error) {
	// Poll for completion
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-ticker.C:
			r.mu.Lock()
			if r.finished {
				exitCode := r.exitCode
				err := r.err
				r.mu.Unlock()
				return exitCode, err
			}
			r.mu.Unlock()
		}
	}
}

// WaitForReadyStdout waits for a readiness event on stdout.
func (r *Runner) WaitForReadyStdout(ctx context.Context, timeout time.Duration) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-timeoutCtx.Done():
		if timeoutCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timeout waiting for server readiness after %v", timeout)
		}
		return timeoutCtx.Err()
	case <-r.readyCh:
		return nil
	}
}

// Stop gracefully stops the process.
func (r *Runner) Stop(ctx context.Context, gracePeriod time.Duration) error {
	r.mu.Lock()
	if !r.started || r.finished {
		r.mu.Unlock()
		return nil
	}
	cmd := r.cmd
	r.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// Send SIGTERM for graceful shutdown
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// Process may have already exited
		if !isProcessExited(err) {
			return fmt.Errorf("send SIGTERM: %w", err)
		}
		return nil
	}

	// Wait for graceful shutdown with timeout
	gracefulCtx, cancel := context.WithTimeout(ctx, gracePeriod)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-gracefulCtx.Done():
			// Grace period expired, force kill
			if err := cmd.Process.Kill(); err != nil {
				if !isProcessExited(err) {
					return fmt.Errorf("kill process: %w", err)
				}
			}
			return nil
		case <-ticker.C:
			r.mu.Lock()
			finished := r.finished
			r.mu.Unlock()
			if finished {
				return nil
			}
		}
	}
}

// isProcessExited checks if an error indicates the process already exited.
func isProcessExited(err error) bool {
	return strings.Contains(err.Error(), "process already finished") ||
		strings.Contains(err.Error(), "no such process")
}

// GetMeta returns the role metadata.
func (r *Runner) GetMeta() *bundle.RoleMeta {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Copy metadata
	meta := *r.meta

	// Add log files
	if r.bundle != nil {
		// Write logs to bundle
		roleDir := r.bundle.RoleDir(r.role)
		stdoutPath := filepath.Join(roleDir, bundle.StdoutLog)
		stderrPath := filepath.Join(roleDir, bundle.StderrLog)

		// SECURITY: Use 0600 for log files as they may contain sensitive data
		os.WriteFile(stdoutPath, []byte(r.stdoutBuf.String()), 0600)
		os.WriteFile(stderrPath, []byte(r.stderrBuf.String()), 0600)
	}

	return &meta
}

// GetStdout returns captured stdout.
func (r *Runner) GetStdout() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stdoutBuf.String()
}

// GetStderr returns captured stderr.
func (r *Runner) GetStderr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stderrBuf.String()
}

// ReadyEvent represents a server readiness event.
type ReadyEvent struct {
	Event     string `json:"event"`
	Listen    string `json:"listen"`
	Timestamp string `json:"timestamp"`
}

// ParseReadyEvent parses a readiness event from a JSON line.
func ParseReadyEvent(line string) (*ReadyEvent, error) {
	var event ReadyEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return nil, err
	}
	if event.Event != "server_ready" {
		return nil, fmt.Errorf("not a server_ready event")
	}
	return &event, nil
}

// OutputCh returns the channel for real-time output events.
func (r *Runner) OutputCh() <-chan OutputEvent {
	return r.outputCh
}
