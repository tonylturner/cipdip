// Package controller provides the orchestration controller for distributed runs.
package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tturner/cipdip/internal/manifest"
	"github.com/tturner/cipdip/internal/orch/bundle"
	"github.com/tturner/cipdip/internal/transport"
)

// Phase represents an execution phase.
type Phase string

const (
	PhaseInit        Phase = "init"
	PhaseStage       Phase = "stage"
	PhaseServerStart Phase = "server_start"
	PhaseServerReady Phase = "server_ready"
	PhaseClientStart Phase = "client_start"
	PhaseClientDone  Phase = "client_done"
	PhaseServerStop  Phase = "server_stop"
	PhaseCollect     Phase = "collect"
	PhaseBundle      Phase = "bundle"
	PhaseAnalyze     Phase = "analyze"
	PhaseDiff        Phase = "diff"
	PhaseDone        Phase = "done"
)

// Options configures the controller.
type Options struct {
	BundleDir    string            // Base directory for bundles
	BundleFormat string            // "dir" or "zip"
	Timeout      time.Duration     // Overall run timeout
	DryRun       bool              // Validate and plan only
	NoAnalyze    bool              // Skip post-run analysis
	NoDiff       bool              // Skip diff even if baseline specified
	Verbose      bool              // Verbose output
	Agents       map[string]string // Role to transport spec mapping (e.g., "server" -> "ssh://user@host")
}

// DefaultOptions returns sensible default options.
func DefaultOptions() Options {
	return Options{
		BundleDir:    "runs",
		BundleFormat: "dir",
		Timeout:      30 * time.Minute,
		DryRun:       false,
		NoAnalyze:    false,
		NoDiff:       false,
		Verbose:      false,
	}
}

// Result contains the outcome of a run.
type Result struct {
	RunID           string
	BundlePath      string
	Status          string  // "success", "failed", "timeout"
	PhasesCompleted []Phase
	Error           error
	StartTime       time.Time
	EndTime         time.Time
}

// PhaseCallback is called when a phase changes.
type PhaseCallback func(phase Phase, msg string)

// Controller orchestrates a distributed run.
type Controller struct {
	manifest      *manifest.Manifest
	resolved      *manifest.ResolvedManifest
	opts          Options
	bundle        *bundle.Bundle
	phaseCallback PhaseCallback

	// Transports for remote execution
	transports map[string]transport.Transport

	// Internal state - use RoleRunner interface to abstract local/remote
	serverRunner RoleRunner
	clientRunner RoleRunner
}

// New creates a new controller for the given manifest.
func New(m *manifest.Manifest, opts Options) (*Controller, error) {
	if m == nil {
		return nil, fmt.Errorf("manifest is required")
	}

	c := &Controller{
		manifest:   m,
		opts:       opts,
		transports: make(map[string]transport.Transport),
	}

	// Parse and create transports for each agent
	for role, spec := range opts.Agents {
		if transport.IsLocal(spec) {
			continue // Skip local, will use local Runner
		}
		t, err := transport.Parse(spec)
		if err != nil {
			return nil, fmt.Errorf("parse transport for %s: %w", role, err)
		}
		c.transports[role] = t
	}

	return c, nil
}

// Close cleans up controller resources including transports.
func (c *Controller) Close() error {
	var lastErr error
	for role, t := range c.transports {
		if err := t.Close(); err != nil {
			lastErr = fmt.Errorf("close transport for %s: %w", role, err)
		}
	}
	return lastErr
}

// ValidateAgents validates connectivity to all remote agents.
// Returns a map of role to any connection error encountered.
func (c *Controller) ValidateAgents(ctx context.Context) map[string]error {
	results := make(map[string]error)

	for role, t := range c.transports {
		// Try a simple command to validate connectivity
		exitCode, _, _, err := t.Exec(ctx, []string{"true"}, nil, "")
		if err != nil {
			results[role] = fmt.Errorf("connectivity check failed: %w", err)
		} else if exitCode != 0 {
			results[role] = fmt.Errorf("connectivity check returned exit code %d", exitCode)
		} else {
			results[role] = nil // Success
		}
	}

	return results
}

// HasRemoteAgents returns true if any roles are configured for remote execution.
func (c *Controller) HasRemoteAgents() bool {
	return len(c.transports) > 0
}

// createRunner creates the appropriate runner (local or remote) for a role.
func (c *Controller) createRunner(role string, args []string) (RoleRunner, error) {
	agentSpec := c.opts.Agents[role]

	// Check if we have a remote transport for this role
	if t, ok := c.transports[role]; ok {
		// For remote execution, prepend "cipdip" (assumed to be in PATH on remote)
		fullArgs := append([]string{"cipdip"}, args...)
		return NewRemoteRunner(role, fullArgs, c.bundle, t, agentSpec)
	}

	// For local execution, use the current executable path
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}
	fullArgs := append([]string{execPath}, args...)

	// Default to local runner
	return NewRunner(role, fullArgs, c.bundle)
}

// SetPhaseCallback sets a callback for phase changes.
func (c *Controller) SetPhaseCallback(cb PhaseCallback) {
	c.phaseCallback = cb
}

// reportPhase reports the current phase.
func (c *Controller) reportPhase(phase Phase, msg string) {
	if c.phaseCallback != nil {
		c.phaseCallback(phase, msg)
	}
	if c.opts.Verbose {
		fmt.Fprintf(os.Stdout, "[%s] %s\n", phase, msg)
	}
}

// Run executes the orchestrated run.
func (c *Controller) Run(ctx context.Context) (*Result, error) {
	result := &Result{
		StartTime: time.Now(),
		Status:    "running",
	}

	// Apply timeout
	if c.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}

	// Execute phases
	if err := c.runPhases(ctx, result); err != nil {
		result.Error = err
		result.Status = "failed"
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
		}
	} else {
		result.Status = "success"
	}

	result.EndTime = time.Now()
	return result, result.Error
}

// runPhases executes all phases in sequence.
func (c *Controller) runPhases(ctx context.Context, result *Result) error {
	// Phase: Init
	if err := c.phaseInit(ctx, result); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	result.PhasesCompleted = append(result.PhasesCompleted, PhaseInit)

	if c.opts.DryRun {
		c.reportPhase(PhaseDone, "Dry run complete")
		result.PhasesCompleted = append(result.PhasesCompleted, PhaseDone)
		return nil
	}

	// Phase: Stage
	if err := c.phaseStage(ctx, result); err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	result.PhasesCompleted = append(result.PhasesCompleted, PhaseStage)

	// Phase: Server Start (if server role defined)
	if c.manifest.Roles.Server != nil {
		if err := c.phaseServerStart(ctx, result); err != nil {
			return fmt.Errorf("server_start: %w", err)
		}
		result.PhasesCompleted = append(result.PhasesCompleted, PhaseServerStart)

		// Phase: Server Ready
		if err := c.phaseServerReady(ctx, result); err != nil {
			c.stopServer(ctx) // Clean up on failure
			return fmt.Errorf("server_ready: %w", err)
		}
		result.PhasesCompleted = append(result.PhasesCompleted, PhaseServerReady)
	}

	// Phase: Client Start (if client role defined)
	if c.manifest.Roles.Client != nil {
		if err := c.phaseClientStart(ctx, result); err != nil {
			c.stopServer(ctx) // Clean up on failure
			return fmt.Errorf("client_start: %w", err)
		}
		result.PhasesCompleted = append(result.PhasesCompleted, PhaseClientStart)

		// Phase: Client Done
		if err := c.phaseClientDone(ctx, result); err != nil {
			c.stopServer(ctx) // Clean up on failure
			return fmt.Errorf("client_done: %w", err)
		}
		result.PhasesCompleted = append(result.PhasesCompleted, PhaseClientDone)
	}

	// Phase: Server Stop
	if c.manifest.Roles.Server != nil {
		if err := c.phaseServerStop(ctx, result); err != nil {
			return fmt.Errorf("server_stop: %w", err)
		}
		result.PhasesCompleted = append(result.PhasesCompleted, PhaseServerStop)
	}

	// Phase: Collect
	if err := c.phaseCollect(ctx, result); err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	result.PhasesCompleted = append(result.PhasesCompleted, PhaseCollect)

	// Phase: Bundle
	if err := c.phaseBundle(ctx, result); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	result.PhasesCompleted = append(result.PhasesCompleted, PhaseBundle)

	// Phase: Analyze (optional)
	if !c.opts.NoAnalyze && c.manifest.PostRun.Analyze {
		if err := c.phaseAnalyze(ctx, result); err != nil {
			// Analysis failure is a warning, not a fatal error
			c.reportPhase(PhaseAnalyze, fmt.Sprintf("Analysis failed: %v", err))
		} else {
			result.PhasesCompleted = append(result.PhasesCompleted, PhaseAnalyze)
		}
	}

	// Phase: Diff (optional)
	if !c.opts.NoDiff && c.manifest.PostRun.DiffBaseline != "" {
		if err := c.phaseDiff(ctx, result); err != nil {
			// Diff failure is a warning, not a fatal error
			c.reportPhase(PhaseDiff, fmt.Sprintf("Diff failed: %v", err))
		} else {
			result.PhasesCompleted = append(result.PhasesCompleted, PhaseDiff)
		}
	}

	// Phase: Done
	c.reportPhase(PhaseDone, "Run complete")
	result.PhasesCompleted = append(result.PhasesCompleted, PhaseDone)

	return nil
}

// phaseInit initializes the run.
func (c *Controller) phaseInit(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseInit, "Initializing run")

	// Resolve manifest
	resolved, err := c.manifest.Resolve()
	if err != nil {
		return fmt.Errorf("resolve manifest: %w", err)
	}
	c.resolved = resolved
	result.RunID = resolved.RunID

	// Create bundle directory
	b, err := bundle.Create(c.opts.BundleDir, resolved.RunID)
	if err != nil {
		return fmt.Errorf("create bundle: %w", err)
	}
	c.bundle = b
	result.BundlePath = b.Path

	// Write manifest files
	manifestData, err := c.manifest.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize manifest: %w", err)
	}
	if err := b.WriteManifest(manifestData); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	resolvedData, err := resolved.ToYAML()
	if err != nil {
		return fmt.Errorf("serialize resolved manifest: %w", err)
	}
	if err := b.WriteResolvedManifest(resolvedData); err != nil {
		return fmt.Errorf("write resolved manifest: %w", err)
	}

	// Write versions
	versions := &bundle.Versions{
		CipdipVersion:  getVersion(),
		GitCommit:      getCommit(),
		ControllerOS:   runtime.GOOS,
		ControllerArch: runtime.GOARCH,
	}
	if err := b.WriteVersions(versions); err != nil {
		return fmt.Errorf("write versions: %w", err)
	}

	c.reportPhase(PhaseInit, fmt.Sprintf("Bundle created: %s", b.Path))
	return nil
}

// phaseStage stages profiles and resources.
func (c *Controller) phaseStage(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseStage, "Staging resources")

	// Read and copy profile to bundle
	profilePath := c.resolved.ProfilePath
	if profilePath != "" {
		data, err := os.ReadFile(profilePath)
		if err != nil {
			return fmt.Errorf("read profile: %w", err)
		}
		if err := c.bundle.WriteProfile(data); err != nil {
			return fmt.Errorf("write profile: %w", err)
		}
		c.reportPhase(PhaseStage, fmt.Sprintf("Profile staged: %s", filepath.Base(profilePath)))

		// Push profile to remote agents
		for role, t := range c.transports {
			c.reportPhase(PhaseStage, fmt.Sprintf("Pushing profile to remote %s agent", role))
			if err := c.pushProfileToRemote(ctx, profilePath, role, t); err != nil {
				return fmt.Errorf("push profile to %s: %w", role, err)
			}
		}
	}

	return nil
}

// pushProfileToRemote copies a profile file to a remote host.
func (c *Controller) pushProfileToRemote(ctx context.Context, localPath, role string, t transport.Transport) error {
	// Create remote work directory
	remoteWorkDir := fmt.Sprintf("/tmp/cipdip-%s", role)
	if err := t.Mkdir(ctx, remoteWorkDir); err != nil {
		return fmt.Errorf("create remote workdir: %w", err)
	}

	// Copy profile to remote
	remotePath := filepath.Join(remoteWorkDir, filepath.Base(localPath))
	if err := t.Put(ctx, localPath, remotePath); err != nil {
		return fmt.Errorf("copy profile: %w", err)
	}

	c.reportPhase(PhaseStage, fmt.Sprintf("Profile pushed to %s: %s", role, remotePath))
	return nil
}

// phaseServerStart starts the server role.
func (c *Controller) phaseServerStart(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseServerStart, "Starting server")

	runner, err := c.createRunner("server", c.resolved.ServerArgs)
	if err != nil {
		return fmt.Errorf("create server runner: %w", err)
	}
	c.serverRunner = runner

	if runner.IsRemote() {
		c.reportPhase(PhaseServerStart, fmt.Sprintf("Using remote agent: %s", c.opts.Agents["server"]))
	}

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	return nil
}

// phaseServerReady waits for server readiness.
func (c *Controller) phaseServerReady(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseServerReady, "Waiting for server readiness")

	timeout := time.Duration(c.manifest.Readiness.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	method := c.manifest.Readiness.Method
	if method == "" {
		method = "tcp_connect"
	}

	var err error
	switch method {
	case "structured_stdout":
		err = c.serverRunner.WaitForReadyStdout(ctx, timeout)
	case "tcp_connect":
		addr := fmt.Sprintf("%s:%d", c.manifest.Network.DataPlane.ServerListenIP, 44818)
		err = WaitForTCPReady(ctx, addr, timeout)
	default:
		err = fmt.Errorf("unknown readiness method: %s", method)
	}

	if err != nil {
		return fmt.Errorf("server not ready: %w", err)
	}

	c.reportPhase(PhaseServerReady, "Server is ready")
	return nil
}

// phaseClientStart starts the client role.
func (c *Controller) phaseClientStart(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseClientStart, "Starting client")

	runner, err := c.createRunner("client", c.resolved.ClientArgs)
	if err != nil {
		return fmt.Errorf("create client runner: %w", err)
	}
	c.clientRunner = runner

	if runner.IsRemote() {
		c.reportPhase(PhaseClientStart, fmt.Sprintf("Using remote agent: %s", c.opts.Agents["client"]))
	}

	if err := runner.Start(ctx); err != nil {
		return fmt.Errorf("start client: %w", err)
	}

	return nil
}

// phaseClientDone waits for client completion.
func (c *Controller) phaseClientDone(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseClientDone, "Waiting for client completion")

	exitCode, err := c.clientRunner.Wait(ctx)
	if err != nil {
		return fmt.Errorf("client error: %w", err)
	}

	if exitCode != 0 {
		c.reportPhase(PhaseClientDone, fmt.Sprintf("Client exited with code %d", exitCode))
	} else {
		c.reportPhase(PhaseClientDone, "Client completed successfully")
	}

	return nil
}

// phaseServerStop stops the server role.
func (c *Controller) phaseServerStop(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseServerStop, "Stopping server")

	if err := c.serverRunner.Stop(ctx, 10*time.Second); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	c.reportPhase(PhaseServerStop, "Server stopped")
	return nil
}

// stopServer is a helper to stop the server on error paths.
func (c *Controller) stopServer(ctx context.Context) {
	if c.serverRunner != nil {
		c.serverRunner.Stop(ctx, 5*time.Second)
	}
}

// phaseCollect collects artifacts from roles.
func (c *Controller) phaseCollect(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseCollect, "Collecting artifacts")

	// Server artifacts
	if c.serverRunner != nil {
		if c.serverRunner.IsRemote() {
			c.reportPhase(PhaseCollect, "Collecting server artifacts from remote")
		}
		if err := c.serverRunner.CollectArtifacts(ctx); err != nil {
			return fmt.Errorf("collect server artifacts: %w", err)
		}
		meta := c.serverRunner.GetMeta()
		if err := c.bundle.WriteRoleMeta("server", meta); err != nil {
			return fmt.Errorf("write server meta: %w", err)
		}
	}

	// Client artifacts
	if c.clientRunner != nil {
		if c.clientRunner.IsRemote() {
			c.reportPhase(PhaseCollect, "Collecting client artifacts from remote")
		}
		if err := c.clientRunner.CollectArtifacts(ctx); err != nil {
			return fmt.Errorf("collect client artifacts: %w", err)
		}
		meta := c.clientRunner.GetMeta()
		if err := c.bundle.WriteRoleMeta("client", meta); err != nil {
			return fmt.Errorf("write client meta: %w", err)
		}
	}

	return nil
}

// phaseBundle finalizes the bundle.
func (c *Controller) phaseBundle(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseBundle, "Finalizing bundle")

	// Write run metadata
	runMeta := &bundle.RunMeta{
		RunID:           result.RunID,
		StartedAt:       result.StartTime,
		FinishedAt:      time.Now(),
		DurationSeconds: time.Since(result.StartTime).Seconds(),
		Status:          result.Status,
		ControllerHost:  hostname(),
		PhasesCompleted: phaseStrings(result.PhasesCompleted),
	}
	if result.Error != nil {
		runMeta.Error = result.Error.Error()
	}

	if err := c.bundle.WriteRunMeta(runMeta); err != nil {
		return fmt.Errorf("write run meta: %w", err)
	}

	// Finalize with hashes
	if err := c.bundle.Finalize(); err != nil {
		return fmt.Errorf("finalize bundle: %w", err)
	}

	// Verify bundle
	verifyResult, err := c.bundle.Verify(bundle.DefaultVerifyOptions())
	if err != nil {
		return fmt.Errorf("verify bundle: %w", err)
	}
	if !verifyResult.Valid {
		c.reportPhase(PhaseBundle, "Bundle verification failed")
		for _, e := range verifyResult.Errors {
			c.reportPhase(PhaseBundle, fmt.Sprintf("  - %s", e))
		}
	} else {
		c.reportPhase(PhaseBundle, "Bundle verified successfully")
	}

	return nil
}

// phaseAnalyze runs post-run analysis.
func (c *Controller) phaseAnalyze(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseAnalyze, "Running analysis")
	// TODO: Implement PCAP analysis
	return nil
}

// phaseDiff runs diff against baseline.
func (c *Controller) phaseDiff(ctx context.Context, result *Result) error {
	c.reportPhase(PhaseDiff, "Running diff")
	// TODO: Implement bundle diff
	return nil
}

// Helper functions

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func phaseStrings(phases []Phase) []string {
	result := make([]string, len(phases))
	for i, p := range phases {
		result[i] = string(p)
	}
	return result
}

// These are set at build time
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
)

func getVersion() string {
	return buildVersion
}

func getCommit() string {
	return buildCommit
}
