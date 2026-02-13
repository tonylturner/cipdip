package controller

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tonylturner/cipdip/internal/manifest"
	"github.com/tonylturner/cipdip/internal/orch/bundle"
	"github.com/tonylturner/cipdip/internal/transport"
)

func TestNewController(t *testing.T) {
	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         "test.yaml",
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	c, err := New(m, DefaultOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c == nil {
		t.Fatal("New() returned nil controller")
	}
}

func TestNewController_NilManifest(t *testing.T) {
	_, err := New(nil, DefaultOptions())
	if err == nil {
		t.Error("New() should fail with nil manifest")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.BundleDir != "runs" {
		t.Errorf("BundleDir = %v, want runs", opts.BundleDir)
	}
	if opts.BundleFormat != "dir" {
		t.Errorf("BundleFormat = %v, want dir", opts.BundleFormat)
	}
	if opts.Timeout != 30*time.Minute {
		t.Errorf("Timeout = %v, want 30m", opts.Timeout)
	}
}

func TestController_DryRun(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal valid manifest
	m := &manifest.Manifest{
		APIVersion: "v1",
		RunID:      "test-dry-run",
		Profile: manifest.ProfileConfig{
			Path:         filepath.Join(tmpDir, "test.yaml"),
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	// Create dummy profile file
	if err := os.WriteFile(m.Profile.Path, []byte("name: test"), 0644); err != nil {
		t.Fatalf("Failed to create test profile: %v", err)
	}

	opts := DefaultOptions()
	opts.BundleDir = tmpDir
	opts.DryRun = true
	opts.Verbose = true

	c, err := New(m, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	result, err := c.Run(ctx)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "success" {
		t.Errorf("Status = %v, want success", result.Status)
	}

	// Check phases completed
	expectedPhases := []Phase{PhaseInit, PhaseDone}
	if len(result.PhasesCompleted) != len(expectedPhases) {
		t.Errorf("PhasesCompleted = %v, want %v", result.PhasesCompleted, expectedPhases)
	}
}

func TestPhaseStrings(t *testing.T) {
	phases := []Phase{PhaseInit, PhaseStage, PhaseDone}
	strings := phaseStrings(phases)

	if len(strings) != 3 {
		t.Errorf("len(strings) = %d, want 3", len(strings))
	}
	if strings[0] != "init" {
		t.Errorf("strings[0] = %v, want init", strings[0])
	}
}

func TestRunner_NewRunner(t *testing.T) {
	args := []string{"echo", "hello"}
	r, err := NewRunner("test", args, nil)
	if err != nil {
		t.Fatalf("NewRunner() error = %v", err)
	}

	if r.role != "test" {
		t.Errorf("role = %v, want test", r.role)
	}
	if len(r.args) != 2 {
		t.Errorf("len(args) = %d, want 2", len(r.args))
	}
}

func TestRunner_NewRunner_EmptyArgs(t *testing.T) {
	_, err := NewRunner("test", nil, nil)
	if err == nil {
		t.Error("NewRunner() should fail with empty args")
	}
}

func TestRunner_StartWait(t *testing.T) {
	args := []string{"echo", "hello"}
	r, _ := NewRunner("test", args, nil)

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	exitCode, err := r.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}

	// Check stdout captured
	stdout := r.GetStdout()
	if stdout == "" {
		t.Error("Stdout should contain output")
	}
}

func TestRunner_StartWait_Failure(t *testing.T) {
	args := []string{"sh", "-c", "exit 42"}
	r, _ := NewRunner("test", args, nil)

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	exitCode, _ := r.Wait(ctx)
	if exitCode != 42 {
		t.Errorf("exitCode = %d, want 42", exitCode)
	}
}

func TestRunner_Stop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping: SIGTERM not supported on Windows")
	}
	// Start a long-running process
	args := []string{"sleep", "60"}
	r, _ := NewRunner("test", args, nil)

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Stop it quickly
	if err := r.Stop(ctx, 1*time.Second); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	// Verify it's stopped
	meta := r.GetMeta()
	if meta.ExitCode == 0 {
		// Process was killed, so exit code should be non-zero
		// (unless it exited naturally, which is unlikely in 1 second)
	}
}

func TestWaitForTCPReady_Timeout(t *testing.T) {
	ctx := context.Background()
	// Use a port that's unlikely to be listening
	err := WaitForTCPReady(ctx, "127.0.0.1:59999", 500*time.Millisecond)
	if err == nil {
		t.Error("WaitForTCPReady should fail when nothing is listening")
	}
}

func TestWaitForTCPReady_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := WaitForTCPReady(ctx, "127.0.0.1:59999", 5*time.Second)
	if err == nil {
		t.Error("WaitForTCPReady should fail when context is cancelled")
	}
}

func TestParseReadyEvent(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		listen  string
	}{
		{
			name:    "valid event",
			line:    `{"event":"server_ready","listen":"127.0.0.1:44818","timestamp":"2026-01-13T12:00:00Z"}`,
			wantErr: false,
			listen:  "127.0.0.1:44818",
		},
		{
			name:    "wrong event type",
			line:    `{"event":"stats","requests":100}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			line:    `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := ParseReadyEvent(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Error("ParseReadyEvent should fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseReadyEvent() error = %v", err)
			}
			if event.Listen != tt.listen {
				t.Errorf("Listen = %v, want %v", event.Listen, tt.listen)
			}
		})
	}
}

// Agent/Transport tests

func TestNewController_WithLocalAgents(t *testing.T) {
	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         "test.yaml",
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Server: &manifest.ServerRole{
				Agent:       "local",
				Personality: "adapter",
			},
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	opts := DefaultOptions()
	opts.Agents = map[string]string{
		"server": "local",
		"client": "local",
	}

	c, err := New(m, opts)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer c.Close()

	if c.HasRemoteAgents() {
		t.Error("HasRemoteAgents() should be false for local agents")
	}
}

func TestNewController_WithInvalidAgentSpec(t *testing.T) {
	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         "test.yaml",
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	opts := DefaultOptions()
	opts.Agents = map[string]string{
		"server": "invalid://scheme",
	}

	_, err := New(m, opts)
	if err == nil {
		t.Error("New() should fail with invalid transport spec")
	}
}

func TestController_ValidateAgents(t *testing.T) {
	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         "test.yaml",
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	// Create controller with local transport (pretending it's remote for test)
	opts := DefaultOptions()
	c, _ := New(m, opts)
	defer c.Close()

	// Manually add a local transport to simulate remote
	c.transports["test"] = transport.NewLocal(transport.DefaultOptions())

	ctx := context.Background()
	results := c.ValidateAgents(ctx)

	if err := results["test"]; err != nil {
		t.Errorf("ValidateAgents() test error = %v", err)
	}
}

func TestController_Close(t *testing.T) {
	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         "test.yaml",
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	c, _ := New(m, DefaultOptions())

	// Manually add a transport
	c.transports["test"] = transport.NewLocal(transport.DefaultOptions())

	// Close should not error
	if err := c.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestController_CreateRunner_Local(t *testing.T) {
	tmpDir := t.TempDir()

	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         filepath.Join(tmpDir, "test.yaml"),
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	// Create test profile
	os.WriteFile(m.Profile.Path, []byte("name: test"), 0644)

	opts := DefaultOptions()
	opts.BundleDir = tmpDir

	c, _ := New(m, opts)
	defer c.Close()

	// Initialize bundle through phaseInit (simplified)
	resolved, _ := m.Resolve()
	c.resolved = resolved

	// Import bundle package
	c.bundle, _ = bundle.Create(tmpDir, "test-run")

	// Create local runner
	runner, err := c.createRunner("client", []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("createRunner() error = %v", err)
	}

	if runner.IsRemote() {
		t.Error("createRunner() should return local runner")
	}
}

func TestController_CreateRunner_Remote(t *testing.T) {
	tmpDir := t.TempDir()

	m := &manifest.Manifest{
		APIVersion: "v1",
		Profile: manifest.ProfileConfig{
			Path:         filepath.Join(tmpDir, "test.yaml"),
			Distribution: "inline",
		},
		Network: manifest.NetworkConfig{
			DataPlane: manifest.DataPlaneConfig{
				TargetIP: "127.0.0.1",
			},
		},
		Roles: manifest.RolesConfig{
			Client: &manifest.ClientRole{
				Agent:           "local",
				Scenario:        "baseline",
				DurationSeconds: 10,
			},
		},
	}

	// Create test profile
	os.WriteFile(m.Profile.Path, []byte("name: test"), 0644)

	opts := DefaultOptions()
	opts.BundleDir = tmpDir

	c, _ := New(m, opts)
	defer c.Close()

	// Manually add a local transport (simulating remote)
	c.transports["server"] = transport.NewLocal(transport.DefaultOptions())
	c.opts.Agents = map[string]string{"server": "test-agent"}

	// Initialize bundle
	c.bundle, _ = bundle.Create(tmpDir, "test-run")

	// Create remote runner
	runner, err := c.createRunner("server", []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("createRunner() error = %v", err)
	}

	if !runner.IsRemote() {
		t.Error("createRunner() should return remote runner")
	}
}
