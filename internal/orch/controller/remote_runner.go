package controller

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/orch/bundle"
	"github.com/tturner/cipdip/internal/transport"
)

// RemoteRunner manages execution of a role on a remote host via SSH.
type RemoteRunner struct {
	role      string
	args      []string
	bundle    *bundle.Bundle
	transport transport.Transport
	agentID   string
	workDir   string // Remote working directory
	meta      *bundle.RoleMeta

	// Synchronization
	mu       sync.Mutex
	started  bool
	finished bool
	exitCode int
	err      error

	// Output capture
	stdoutBuf strings.Builder
	stderrBuf strings.Builder

	// Process control - for remote, we track via a done channel
	doneCh  chan struct{}
	readyCh chan struct{}
	ready   bool

	// Cancel function for stopping the remote process
	cancelFn context.CancelFunc
}

// NewRemoteRunner creates a new runner for executing a role on a remote host.
func NewRemoteRunner(role string, args []string, b *bundle.Bundle, t transport.Transport, agentID string) (*RemoteRunner, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no arguments provided for role %s", role)
	}
	if t == nil {
		return nil, fmt.Errorf("transport is required for remote runner")
	}

	return &RemoteRunner{
		role:      role,
		args:      args,
		bundle:    b,
		transport: t,
		agentID:   agentID,
		workDir:   fmt.Sprintf("/tmp/cipdip-%s", role),
		doneCh:    make(chan struct{}),
		readyCh:   make(chan struct{}),
		meta: &bundle.RoleMeta{
			Role:    role,
			AgentID: agentID,
			Argv:    args,
		},
	}, nil
}

// SetWorkDir sets the remote working directory.
func (r *RemoteRunner) SetWorkDir(dir string) {
	r.workDir = dir
}

// Start launches the role process on the remote host.
func (r *RemoteRunner) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.started {
		return fmt.Errorf("runner already started")
	}

	// Create remote working directory
	if err := r.transport.Mkdir(ctx, r.workDir); err != nil {
		return fmt.Errorf("create remote workdir: %w", err)
	}

	// Create a cancellable context for the remote command
	cmdCtx, cancel := context.WithCancel(ctx)
	r.cancelFn = cancel

	r.meta.StartedAt = time.Now()
	r.started = true

	// Run command in background goroutine
	go r.runRemoteCommand(cmdCtx)

	return nil
}

// runRemoteCommand executes the command on the remote host.
func (r *RemoteRunner) runRemoteCommand(ctx context.Context) {
	// Prepare command - prepend "cipdip" if not already there
	cmd := r.args
	if len(cmd) > 0 && cmd[0] != "cipdip" {
		cmd = append([]string{"cipdip"}, cmd...)
	}

	// Create writers that capture to our buffers and check for readiness
	stdoutWriter := &readinessWriter{
		buf:     &r.stdoutBuf,
		mu:      &r.mu,
		readyCh: r.readyCh,
		ready:   &r.ready,
	}
	stderrWriter := &bufWriter{buf: &r.stderrBuf, mu: &r.mu}

	// Execute via transport
	exitCode, err := r.transport.ExecStream(ctx, cmd, nil, r.workDir, stdoutWriter, stderrWriter)

	r.mu.Lock()
	r.finished = true
	r.exitCode = exitCode
	r.err = err
	r.meta.FinishedAt = time.Now()
	r.meta.ExitCode = exitCode
	r.mu.Unlock()

	close(r.doneCh)
}

// Wait waits for the process to complete.
func (r *RemoteRunner) Wait(ctx context.Context) (int, error) {
	select {
	case <-ctx.Done():
		return -1, ctx.Err()
	case <-r.doneCh:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.exitCode, r.err
	}
}

// WaitForReadyStdout waits for a readiness event on stdout.
func (r *RemoteRunner) WaitForReadyStdout(ctx context.Context, timeout time.Duration) error {
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
	case <-r.doneCh:
		// Process exited before becoming ready
		return fmt.Errorf("process exited before becoming ready")
	}
}

// Stop gracefully stops the remote process.
func (r *RemoteRunner) Stop(ctx context.Context, gracePeriod time.Duration) error {
	r.mu.Lock()
	if !r.started || r.finished {
		r.mu.Unlock()
		return nil
	}
	cancelFn := r.cancelFn
	r.mu.Unlock()

	// Cancel the context to trigger remote command termination
	if cancelFn != nil {
		cancelFn()
	}

	// Wait for completion with grace period
	gracefulCtx, cancel := context.WithTimeout(ctx, gracePeriod)
	defer cancel()

	select {
	case <-gracefulCtx.Done():
		// Grace period expired, try to kill remotely
		// Note: SSH transport context cancellation should handle this
		return nil
	case <-r.doneCh:
		return nil
	}
}

// GetMeta returns the role metadata.
func (r *RemoteRunner) GetMeta() *bundle.RoleMeta {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Copy metadata
	meta := *r.meta
	return &meta
}

// GetStdout returns captured stdout.
func (r *RemoteRunner) GetStdout() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stdoutBuf.String()
}

// GetStderr returns captured stderr.
func (r *RemoteRunner) GetStderr() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stderrBuf.String()
}

// IsRemote returns true for remote runners.
func (r *RemoteRunner) IsRemote() bool {
	return true
}

// CollectArtifacts collects artifacts from the remote host to the bundle.
func (r *RemoteRunner) CollectArtifacts(ctx context.Context) error {
	r.mu.Lock()
	roleDir := r.bundle.RoleDir(r.role)
	stdout := r.stdoutBuf.String()
	stderr := r.stderrBuf.String()
	r.mu.Unlock()

	// Write captured logs locally
	if err := os.WriteFile(filepath.Join(roleDir, bundle.StdoutLog), []byte(stdout), 0644); err != nil {
		return fmt.Errorf("write stdout log: %w", err)
	}
	if err := os.WriteFile(filepath.Join(roleDir, bundle.StderrLog), []byte(stderr), 0644); err != nil {
		return fmt.Errorf("write stderr log: %w", err)
	}

	// Collect PCAP files from remote
	pcapFiles := []string{
		fmt.Sprintf("%s.pcap", r.role),
		fmt.Sprintf("%s.pcapng", r.role),
	}

	var collectedPcaps []string
	for _, pcapFile := range pcapFiles {
		remotePath := filepath.Join(r.workDir, pcapFile)
		localPath := filepath.Join(roleDir, pcapFile)

		// Check if file exists on remote
		if _, err := r.transport.Stat(ctx, remotePath); err != nil {
			continue // File doesn't exist
		}

		// Copy from remote
		if err := r.transport.Get(ctx, remotePath, localPath); err != nil {
			return fmt.Errorf("get pcap %s: %w", pcapFile, err)
		}
		collectedPcaps = append(collectedPcaps, pcapFile)
	}

	// Update metadata with collected pcaps
	r.mu.Lock()
	r.meta.PcapFiles = collectedPcaps
	r.mu.Unlock()

	return nil
}

// PushProfile copies a profile file to the remote host.
func (r *RemoteRunner) PushProfile(ctx context.Context, localPath string) (string, error) {
	remotePath := filepath.Join(r.workDir, filepath.Base(localPath))

	if err := r.transport.Mkdir(ctx, r.workDir); err != nil {
		return "", fmt.Errorf("create remote workdir: %w", err)
	}

	if err := r.transport.Put(ctx, localPath, remotePath); err != nil {
		return "", fmt.Errorf("push profile: %w", err)
	}

	return remotePath, nil
}

// Cleanup removes the remote working directory.
func (r *RemoteRunner) Cleanup(ctx context.Context) error {
	// Try to remove workdir contents
	// Note: This is best-effort cleanup
	r.transport.Remove(ctx, r.workDir)
	return nil
}

// Helper types for output capture

// bufWriter writes to a string builder with mutex protection.
type bufWriter struct {
	buf *strings.Builder
	mu  *sync.Mutex
}

func (w *bufWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// readinessWriter writes to a buffer and checks for readiness events.
type readinessWriter struct {
	buf     *strings.Builder
	mu      *sync.Mutex
	readyCh chan struct{}
	ready   *bool
	line    strings.Builder
}

func (w *readinessWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.buf.Write(p)

	// Check each byte for newlines and detect readiness
	for _, b := range p {
		if b == '\n' {
			line := w.line.String()
			w.line.Reset()

			// Check for readiness event
			if !*w.ready && strings.Contains(line, `"event":"server_ready"`) {
				*w.ready = true
				close(w.readyCh)
			}
		} else {
			w.line.WriteByte(b)
		}
	}

	return len(p), nil
}

// Ensure RemoteRunner implements RoleRunner
var _ RoleRunner = (*RemoteRunner)(nil)

// Ensure writers implement io.Writer
var _ io.Writer = (*bufWriter)(nil)
var _ io.Writer = (*readinessWriter)(nil)
