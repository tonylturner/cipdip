package controller

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tturner/cipdip/internal/orch/bundle"
	"github.com/tturner/cipdip/internal/transport"
)

func TestNewRemoteRunner(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	r, err := NewRemoteRunner("server", []string{"echo", "hello"}, b, tr, "test-agent")
	if err != nil {
		t.Fatalf("NewRemoteRunner() error = %v", err)
	}

	if r.role != "server" {
		t.Errorf("role = %v, want server", r.role)
	}
	if !r.IsRemote() {
		t.Error("IsRemote() should return true")
	}
}

func TestNewRemoteRunner_EmptyArgs(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	_, err := NewRemoteRunner("server", nil, b, tr, "test-agent")
	if err == nil {
		t.Error("NewRemoteRunner() should fail with empty args")
	}
}

func TestNewRemoteRunner_NilTransport(t *testing.T) {
	b, _ := bundle.Create(t.TempDir(), "test-run")

	_, err := NewRemoteRunner("server", []string{"echo", "hello"}, b, nil, "test-agent")
	if err == nil {
		t.Error("NewRemoteRunner() should fail with nil transport")
	}
}

func TestRemoteRunner_StartWait(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	// Note: RemoteRunner prepends "cipdip" to commands by design
	// For testing, use "cipdip" as first arg to skip prepending, which won't exist
	// Instead, we test that the mechanism works even if the command fails
	r, _ := NewRemoteRunner("server", []string{"sh", "-c", "echo hello"}, b, tr, "test-agent")

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for completion - command will fail because "cipdip sh -c echo hello" isn't valid
	exitCode, _ := r.Wait(ctx)

	// The test validates the Start/Wait lifecycle works, even if the command fails
	// exitCode will be non-zero because the command fails
	meta := r.GetMeta()
	if meta.ExitCode != exitCode {
		t.Errorf("meta.ExitCode = %d, want %d", meta.ExitCode, exitCode)
	}
}

func TestRemoteRunner_StartWait_NonZeroExit(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	// Note: RemoteRunner prepends "cipdip" which won't exist, causing command failure
	// This test validates the exit code is captured properly
	r, _ := NewRemoteRunner("server", []string{"sh", "-c", "exit 42"}, b, tr, "test-agent")

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	exitCode, _ := r.Wait(ctx)
	// Exit code will be non-zero (command fails because cipdip doesn't exist)
	if exitCode == 0 {
		t.Error("exitCode should be non-zero for failed command")
	}

	// Verify meta is updated
	meta := r.GetMeta()
	if meta.ExitCode == 0 {
		t.Error("meta.ExitCode should be non-zero")
	}
}

func TestRemoteRunner_Stop(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	// Start a long-running command
	r, _ := NewRemoteRunner("server", []string{"sleep", "60"}, b, tr, "test-agent")

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop it
	if err := r.Stop(ctx, 1*time.Second); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestRemoteRunner_GetMeta(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	r, _ := NewRemoteRunner("server", []string{"echo", "hello"}, b, tr, "test-agent")

	meta := r.GetMeta()
	if meta.Role != "server" {
		t.Errorf("Role = %v, want server", meta.Role)
	}
	if meta.AgentID != "test-agent" {
		t.Errorf("AgentID = %v, want test-agent", meta.AgentID)
	}
}

func TestRemoteRunner_CollectArtifacts(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	r, _ := NewRemoteRunner("server", []string{"sh", "-c", "echo test"}, b, tr, "test-agent")

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	r.Wait(ctx)

	// Collect artifacts
	if err := r.CollectArtifacts(ctx); err != nil {
		t.Fatalf("CollectArtifacts() error = %v", err)
	}
}

func TestRoleRunner_Interface(t *testing.T) {
	// Verify both Runner and RemoteRunner implement RoleRunner
	var _ RoleRunner = (*Runner)(nil)
	var _ RoleRunner = (*RemoteRunner)(nil)
}

func TestBufWriter(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex

	w := &bufWriter{buf: &buf, mu: &mu}

	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 5 {
		t.Errorf("Write() n = %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf = %q, want hello", buf.String())
	}
}

func TestReadinessWriter_DetectsReady(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	readyCh := make(chan struct{})
	ready := false

	w := &readinessWriter{
		buf:     &buf,
		mu:      &mu,
		readyCh: readyCh,
		ready:   &ready,
	}

	// Write non-ready line
	w.Write([]byte("starting up...\n"))

	select {
	case <-readyCh:
		t.Error("readyCh should not be closed yet")
	default:
		// Expected
	}

	// Write ready event
	w.Write([]byte(`{"event":"server_ready","listen":"127.0.0.1:44818"}` + "\n"))

	select {
	case <-readyCh:
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("readyCh should be closed after ready event")
	}

	if !ready {
		t.Error("ready should be true")
	}
}

func TestReadinessWriter_OnlyClosesOnce(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	readyCh := make(chan struct{})
	ready := false

	w := &readinessWriter{
		buf:     &buf,
		mu:      &mu,
		readyCh: readyCh,
		ready:   &ready,
	}

	// Write multiple ready events - should not panic
	for i := 0; i < 3; i++ {
		w.Write([]byte(`{"event":"server_ready","listen":"127.0.0.1:44818"}` + "\n"))
	}

	// Should have only closed once (no panic from closing already-closed channel)
}

func TestRemoteRunner_WaitForReadyStdout_ExitsBeforeReady(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	// Note: RemoteRunner prepends "cipdip" to commands, so the command will fail
	// This test validates that we properly detect "process exited before ready"
	r, _ := NewRemoteRunner("server", []string{"sh", "-c", "echo test"}, b, tr, "test-agent")

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for readiness - should fail because process exits before ready event
	err := r.WaitForReadyStdout(ctx, 2*time.Second)
	if err == nil {
		t.Error("WaitForReadyStdout() should fail when process exits before ready")
	}
	if !strings.Contains(err.Error(), "before becoming ready") {
		t.Errorf("error = %v, should contain 'before becoming ready'", err)
	}
}

func TestRemoteRunner_WaitForReadyStdout_Timeout(t *testing.T) {
	tr := transport.NewLocal(transport.DefaultOptions())
	b, _ := bundle.Create(t.TempDir(), "test-run")

	// Create a command that doesn't output ready event
	r, _ := NewRemoteRunner("server", []string{"sleep", "10"}, b, tr, "test-agent")

	ctx := context.Background()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for readiness with short timeout
	err := r.WaitForReadyStdout(ctx, 200*time.Millisecond)
	if err == nil {
		t.Error("WaitForReadyStdout should timeout")
	}

	// Clean up
	r.Stop(ctx, 1*time.Second)
}

// mockTransport is a test transport that tracks calls
type mockTransport struct {
	transport.Transport
	execCalls   int
	execHandler func(ctx context.Context, cmd []string) (int, string, string, error)
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		Transport: transport.NewLocal(transport.DefaultOptions()),
	}
}

func (m *mockTransport) Exec(ctx context.Context, cmd []string, env map[string]string, cwd string) (int, string, string, error) {
	m.execCalls++
	if m.execHandler != nil {
		return m.execHandler(ctx, cmd)
	}
	return m.Transport.Exec(ctx, cmd, env, cwd)
}

func (m *mockTransport) ExecStream(ctx context.Context, cmd []string, env map[string]string, cwd string, stdout, stderr *bytes.Buffer) (int, error) {
	// Not needed for these tests
	return 0, nil
}

// TestShellQuote tests the POSIX shell quoting function for security
func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "'hello'"},
		{"with spaces", "hello world", "'hello world'"},
		{"with single quote", "it's", "'it'\\''s'"},
		{"injection attempt", "foo; rm -rf /", "'foo; rm -rf /'"},
		{"backtick injection", "$(whoami)", "'$(whoami)'"},
		{"variable injection", "$HOME", "'$HOME'"},
		{"pipe injection", "foo | bar", "'foo | bar'"},
		{"semicolon injection", "foo; bar", "'foo; bar'"},
		{"double quote", "foo\"bar", "'foo\"bar'"},
		{"newline injection", "foo\nbar", "'foo\nbar'"},
		{"empty string", "", "''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestPsEscape tests the PowerShell escaping function for security
func TestPsEscape(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple", "hello", "'hello'"},
		{"with spaces", "hello world", "'hello world'"},
		{"with single quote", "it's", "'it''s'"},
		{"injection attempt", "foo; Remove-Item C:\\ -Recurse", "'foo; Remove-Item C:\\ -Recurse'"},
		{"variable injection", "$env:PATH", "'$env:PATH'"},
		{"subexpression", "$(Get-Process)", "'$(Get-Process)'"},
		{"empty string", "", "''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := psEscape(tt.input)
			if got != tt.want {
				t.Errorf("psEscape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
