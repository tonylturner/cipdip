package controller

import (
	"context"
	"time"

	"github.com/tturner/cipdip/internal/orch/bundle"
)

// RoleRunner is the interface for running server/client roles.
// It abstracts local and remote execution.
type RoleRunner interface {
	// Start launches the role process.
	Start(ctx context.Context) error

	// Wait waits for the process to complete and returns the exit code.
	Wait(ctx context.Context) (int, error)

	// WaitForReadyStdout waits for a readiness event on stdout.
	WaitForReadyStdout(ctx context.Context, timeout time.Duration) error

	// Stop gracefully stops the process.
	Stop(ctx context.Context, gracePeriod time.Duration) error

	// GetMeta returns the role metadata.
	GetMeta() *bundle.RoleMeta

	// GetStdout returns captured stdout.
	GetStdout() string

	// GetStderr returns captured stderr.
	GetStderr() string

	// IsRemote returns true if this is a remote runner.
	IsRemote() bool

	// CollectArtifacts collects artifacts to the bundle.
	// For remote runners, this copies files from the remote host.
	CollectArtifacts(ctx context.Context) error
}

// Ensure Runner implements RoleRunner
var _ RoleRunner = (*Runner)(nil)

// IsRemote returns false for local runners.
func (r *Runner) IsRemote() bool {
	return false
}

// CollectArtifacts for local runner just writes the logs.
func (r *Runner) CollectArtifacts(ctx context.Context) error {
	// Local runner already writes logs in GetMeta()
	// Just ensure the meta is written
	_ = r.GetMeta()
	return nil
}
