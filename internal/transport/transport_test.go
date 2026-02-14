package transport

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewLocal(t *testing.T) {
	l := NewLocal(DefaultOptions())
	if l == nil {
		t.Fatal("NewLocal returned nil")
	}
	if l.String() != "local" {
		t.Errorf("String() = %v, want local", l.String())
	}
}

func TestLocal_Exec(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()

	// Test simple command
	exitCode, stdout, stderr, err := l.Exec(ctx, []string{"echo", "hello"}, nil, "")
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if stdout != "hello\n" {
		t.Errorf("stdout = %q, want %q", stdout, "hello\n")
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
}

func TestLocal_Exec_EmptyCommand(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()

	_, _, _, err := l.Exec(ctx, nil, nil, "")
	if err == nil {
		t.Error("Exec() should fail with empty command")
	}
}

func TestLocal_Exec_NonZeroExit(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()

	exitCode, _, _, err := l.Exec(ctx, []string{"sh", "-c", "exit 42"}, nil, "")
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exitCode = %d, want 42", exitCode)
	}
}

func TestLocal_Exec_WithEnv(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()

	env := map[string]string{"TEST_VAR": "test_value"}
	exitCode, stdout, _, err := l.Exec(ctx, []string{"sh", "-c", "echo $TEST_VAR"}, env, "")
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if stdout != "test_value\n" {
		t.Errorf("stdout = %q, want %q", stdout, "test_value\n")
	}
}

func TestLocal_Exec_WithCwd(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()

	tmpDir := t.TempDir()
	exitCode, stdout, _, err := l.Exec(ctx, []string{"pwd"}, nil, tmpDir)
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	// stdout should contain the temp directory path.
	// On Windows, pwd may return MSYS2-style paths that differ from t.TempDir().
	got := strings.TrimSpace(stdout)
	if runtime.GOOS == "windows" {
		base := filepath.Base(tmpDir)
		if !strings.Contains(got, base) {
			t.Errorf("stdout = %q, expected to contain %q", got, base)
		}
	} else if got != tmpDir {
		t.Errorf("stdout = %q, want %q", stdout, tmpDir+"\n")
	}
}

func TestLocal_ExecStream(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()

	var stdout, stderr bytes.Buffer
	exitCode, err := l.ExecStream(ctx, []string{"echo", "hello"}, nil, "", &stdout, &stderr)
	if err != nil {
		t.Fatalf("ExecStream() error = %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exitCode = %d, want 0", exitCode)
	}
	if stdout.String() != "hello\n" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "hello\n")
	}
}

func TestLocal_PutGet(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create source file
	srcPath := filepath.Join(tmpDir, "source.txt")
	content := []byte("test content")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Put (copy)
	dstPath := filepath.Join(tmpDir, "dest.txt")
	if err := l.Put(ctx, srcPath, dstPath); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	// Verify destination exists
	data, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content = %q, want %q", string(data), string(content))
	}

	// Get (copy back)
	dst2Path := filepath.Join(tmpDir, "dest2.txt")
	if err := l.Get(ctx, dstPath, dst2Path); err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// Verify
	data, err = os.ReadFile(dst2Path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content = %q, want %q", string(data), string(content))
	}
}

func TestLocal_Mkdir(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()
	tmpDir := t.TempDir()

	newDir := filepath.Join(tmpDir, "a", "b", "c")
	if err := l.Mkdir(ctx, newDir); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	info, err := os.Stat(newDir)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if !info.IsDir() {
		t.Error("Path should be a directory")
	}
}

func TestLocal_Stat(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create file
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	info, err := l.Stat(ctx, filePath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Name() != "test.txt" {
		t.Errorf("Name() = %v, want test.txt", info.Name())
	}
	if info.IsDir() {
		t.Error("IsDir() should be false")
	}
}

func TestLocal_Remove(t *testing.T) {
	l := NewLocal(DefaultOptions())
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Create file
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Remove
	if err := l.Remove(ctx, filePath); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	// Verify gone
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Error("File should not exist after Remove()")
	}
}

func TestLocal_Close(t *testing.T) {
	l := NewLocal(DefaultOptions())
	if err := l.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestLocal_Timeout(t *testing.T) {
	opts := DefaultOptions()
	opts.Timeout = 100 * time.Millisecond
	l := NewLocal(opts)
	ctx := context.Background()

	// This should timeout - either returns an error or a non-zero exit code
	// because the process is killed by context deadline
	start := time.Now()
	exitCode, _, _, err := l.Exec(ctx, []string{"sleep", "10"}, nil, "")
	elapsed := time.Since(start)

	// Should complete in around the timeout duration, not 10 seconds
	if elapsed > 2*time.Second {
		t.Errorf("Exec() took %v, should have timed out around %v", elapsed, opts.Timeout)
	}

	// Either we get an error or a non-zero exit (signal killed)
	if err == nil && exitCode == 0 {
		t.Error("Exec() should fail or exit non-zero with timeout")
	}
}

// Parse tests

func TestParse_Local(t *testing.T) {
	tests := []string{"local", ""}
	for _, spec := range tests {
		t.Run(spec, func(t *testing.T) {
			tr, err := Parse(spec)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", spec, err)
			}
			if tr.String() != "local" {
				t.Errorf("String() = %v, want local", tr.String())
			}
		})
	}
}

func TestParse_SSH(t *testing.T) {
	tests := []struct {
		spec     string
		wantHost string
		wantUser string
		wantPort int
	}{
		{
			spec:     "ssh://user@host:2222",
			wantHost: "host",
			wantUser: "user",
			wantPort: 2222,
		},
		{
			spec:     "ssh://host",
			wantHost: "host",
			wantPort: 0, // default
		},
		{
			spec:     "user@host",
			wantHost: "host",
			wantUser: "user",
		},
		{
			spec:     "host",
			wantHost: "host",
		},
		{
			spec:     "user@host:22",
			wantHost: "host",
			wantUser: "user",
			wantPort: 22,
		},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			tr, err := Parse(tt.spec)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.spec, err)
			}

			ssh, ok := tr.(*SSH)
			if !ok {
				t.Fatalf("Parse(%q) returned %T, want *SSH", tt.spec, tr)
			}

			if ssh.host != tt.wantHost {
				t.Errorf("host = %v, want %v", ssh.host, tt.wantHost)
			}
			if tt.wantUser != "" && ssh.opts.User != tt.wantUser {
				t.Errorf("user = %v, want %v", ssh.opts.User, tt.wantUser)
			}
			if tt.wantPort != 0 && ssh.opts.Port != tt.wantPort {
				t.Errorf("port = %v, want %v", ssh.opts.Port, tt.wantPort)
			}
		})
	}
}

func TestParse_SSHWithOptions(t *testing.T) {
	tr, err := Parse("ssh://user@host?key=/path/to/key&insecure=true")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	ssh, ok := tr.(*SSH)
	if !ok {
		t.Fatalf("Parse() returned %T, want *SSH", tr)
	}

	if ssh.opts.KeyFile != "/path/to/key" {
		t.Errorf("KeyFile = %v, want /path/to/key", ssh.opts.KeyFile)
	}
	if !ssh.opts.InsecureIgnoreHost {
		t.Error("InsecureIgnoreHost should be true")
	}
}

func TestParse_InvalidScheme(t *testing.T) {
	_, err := Parse("ftp://host")
	if err == nil {
		t.Error("Parse() should fail with unsupported scheme")
	}
}

func TestIsLocal(t *testing.T) {
	if !IsLocal("") {
		t.Error("IsLocal(\"\") should be true")
	}
	if !IsLocal("local") {
		t.Error("IsLocal(\"local\") should be true")
	}
	if IsLocal("host") {
		t.Error("IsLocal(\"host\") should be false")
	}
}

func TestIsSSH(t *testing.T) {
	if IsSSH("") {
		t.Error("IsSSH(\"\") should be false")
	}
	if IsSSH("local") {
		t.Error("IsSSH(\"local\") should be false")
	}
	if !IsSSH("host") {
		t.Error("IsSSH(\"host\") should be true")
	}
	if !IsSSH("ssh://host") {
		t.Error("IsSSH(\"ssh://host\") should be true")
	}
}

func TestMustParse(t *testing.T) {
	tr := MustParse("local")
	if tr.String() != "local" {
		t.Errorf("String() = %v, want local", tr.String())
	}
}

func TestMustParse_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustParse should panic on invalid scheme")
		}
	}()
	MustParse("invalid://scheme")
}

func TestBuildCommandString(t *testing.T) {
	tests := []struct {
		name     string
		cmd      []string
		cwd      string
		elevate  bool
		remoteOS string
		want     string
	}{
		{
			name: "simple command",
			cmd:  []string{"echo", "hello"},
			want: "echo hello",
		},
		{
			name: "command with spaces",
			cmd:  []string{"echo", "hello world"},
			want: "echo 'hello world'",
		},
		{
			name: "command with cwd",
			cmd:  []string{"ls", "-la"},
			cwd:  "/tmp",
			want: "cd '/tmp' && ls -la",
		},
		{
			name: "shell command",
			cmd:  []string{"sh", "-c", "echo $HOME"},
			want: "sh -c 'echo $HOME'",
		},
		{
			name:    "elevated command unix",
			cmd:     []string{"cat", "/etc/shadow"},
			elevate: true,
			want:    "sudo cat /etc/shadow",
		},
		{
			name:     "elevated command windows ignored",
			cmd:      []string{"type", "C:\\file.txt"},
			elevate:  true,
			remoteOS: "windows",
			want:     "type \"C:\\file.txt\"",
		},
		{
			name:    "elevated with cwd unix",
			cmd:     []string{"ls", "-la"},
			cwd:     "/root",
			elevate: true,
			want:    "cd '/root' && sudo ls -la",
		},
		{
			name:     "command with cwd windows",
			cmd:      []string{"dir"},
			cwd:      "C:\\Users",
			remoteOS: "windows",
			want:     "cd /d \"C:\\Users\" && dir",
		},
		// Security tests - verify malicious inputs are properly escaped
		{
			name: "cwd injection attempt unix",
			cmd:  []string{"ls"},
			cwd:  "/tmp; rm -rf /",
			want: "cd '/tmp; rm -rf /' && ls",
		},
		{
			name:     "cwd injection attempt windows",
			cmd:      []string{"dir"},
			cwd:      "C:\\Users & del C:\\",
			remoteOS: "windows",
			want:     "cd /d \"C:\\Users & del C:\\\" && dir",
		},
		{
			name: "command injection attempt",
			cmd:  []string{"echo", "$(whoami)"},
			want: "echo '$(whoami)'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCommandString(tt.cmd, tt.cwd, tt.elevate, tt.remoteOS)
			if got != tt.want {
				t.Errorf("buildCommandString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrependEnvVars(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		cmdStr   string
		remoteOS string
		want     string
	}{
		{
			name:   "nil env",
			env:    nil,
			cmdStr: "cipdip client",
			want:   "cipdip client",
		},
		{
			name:   "empty env",
			env:    map[string]string{},
			cmdStr: "cipdip client",
			want:   "cipdip client",
		},
		{
			name:   "unix PATH with shell vars",
			env:    map[string]string{"PATH": "/usr/local/bin:$HOME/go/bin:$PATH"},
			cmdStr: "cipdip client --ip 10.0.0.50",
			want:   `export PATH="/usr/local/bin:$HOME/go/bin:$PATH"; cipdip client --ip 10.0.0.50`,
		},
		{
			name:     "windows env",
			env:      map[string]string{"PATH": "C:\\bin;%PATH%"},
			cmdStr:   "cipdip.exe client",
			remoteOS: "windows",
			want:     "$env:PATH='C:\\bin;%PATH%'; cipdip.exe client",
		},
		{
			name:   "value with double quotes",
			env:    map[string]string{"MSG": `say "hello"`},
			cmdStr: "echo test",
			want:   `export MSG="say \"hello\""; echo test`,
		},
		{
			name:   "value with backticks",
			env:    map[string]string{"CMD": "run `cmd`"},
			cmdStr: "echo test",
			want:   "export CMD=\"run \\`cmd\\`\"; echo test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prependEnvVars(tt.env, tt.cmdStr, tt.remoteOS)
			if got != tt.want {
				t.Errorf("prependEnvVars() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNeedsQuoting(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"hello", false},
		{"hello world", true},
		{"$HOME", true},
		{"file.txt", false},
		{"path/to/file", false},
		{"echo 'test'", true},
		{"a|b", true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := needsQuoting(tt.s); got != tt.want {
				t.Errorf("needsQuoting(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 5*time.Minute {
		t.Errorf("Timeout = %v, want 5m", opts.Timeout)
	}
	if opts.RetryAttempts != 3 {
		t.Errorf("RetryAttempts = %d, want 3", opts.RetryAttempts)
	}
}

func TestDefaultSSHOptions(t *testing.T) {
	opts := DefaultSSHOptions()
	if opts.Port != 22 {
		t.Errorf("Port = %d, want 22", opts.Port)
	}
	if opts.ConnectTimeout != 30*time.Second {
		t.Errorf("ConnectTimeout = %v, want 30s", opts.ConnectTimeout)
	}
	if !opts.Agent {
		t.Error("Agent should be true by default")
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"simple relative", "foo/bar", false},
		{"simple filename", "file.txt", false},
		{"absolute path", "/etc/passwd", false},
		{"traversal at start", "../etc/passwd", true},
		{"traversal double", "../../etc/passwd", true},
		{"traversal in middle", "foo/../../../etc/passwd", true},
		{"current dir", "./foo", false},
		{"empty path", "", true},
		{"just dots", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRelativePath(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		relPath  string
		wantErr  bool
	}{
		{"simple relative", "/home/user/work", "subdir/file.txt", false},
		{"nested relative", "/home/user/work", "a/b/c/file.txt", false},
		{"traversal escape", "/home/user/work", "../../etc/passwd", true},
		{"hidden traversal", "/home/user/work", "subdir/../../etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRelativePath(tt.basePath, tt.relPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRelativePath(%q, %q) error = %v, wantErr %v", tt.basePath, tt.relPath, err, tt.wantErr)
			}
		})
	}
}

// --- Issue 1: SFTP path traversal enforcement ---

func newTestSSH(t *testing.T) *SSH {
	t.Helper()
	opts := DefaultSSHOptions()
	opts.ConnectTimeout = 10 * time.Millisecond // prevent slow DNS/TCP in tests
	s, err := NewSSH("192.0.2.1", opts)        // RFC 5737 TEST-NET, won't route
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSSH_Put_RejectsTraversalPath(t *testing.T) {
	tests := []struct {
		name       string
		remotePath string
		wantTraversalErr bool
	}{
		{"traversal up", "../../../etc/crontab", true},
		{"traversal double", "../../etc/passwd", true},
		{"double dot only", "..", true},
		{"valid absolute", "/tmp/cipdip/file.txt", false},
		{"valid relative", "workdir/file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSSH(t)
			err := s.Put(context.Background(), "/dev/null", tt.remotePath)
			if tt.wantTraversalErr {
				if err == nil {
					t.Fatalf("Put() should reject traversal path %q", tt.remotePath)
				}
				if !strings.Contains(err.Error(), "traversal") {
					t.Errorf("Put() error should mention traversal, got: %v", err)
				}
			} else if err != nil && strings.Contains(err.Error(), "traversal") {
				t.Errorf("Put() should not reject valid path %q as traversal", tt.remotePath)
			}
		})
	}
}

func TestSSH_Get_RejectsTraversalPath(t *testing.T) {
	tests := []struct {
		name       string
		remotePath string
		wantTraversalErr bool
	}{
		{"traversal up", "../../../etc/shadow", true},
		{"traversal double", "../../etc/passwd", true},
		{"valid absolute", "/tmp/cipdip/output.txt", false},
		{"valid relative", "data/results.csv", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSSH(t)
			err := s.Get(context.Background(), tt.remotePath, "/dev/null")
			if tt.wantTraversalErr {
				if err == nil {
					t.Fatalf("Get() should reject traversal path %q", tt.remotePath)
				}
				if !strings.Contains(err.Error(), "traversal") {
					t.Errorf("Get() error should mention traversal, got: %v", err)
				}
			} else if err != nil && strings.Contains(err.Error(), "traversal") {
				t.Errorf("Get() should not reject valid path %q as traversal", tt.remotePath)
			}
		})
	}
}

func TestSSH_Mkdir_RejectsTraversalPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantTraversalErr bool
	}{
		{"traversal up", "../../etc", true},
		{"traversal double", "../../../root", true},
		{"valid absolute", "/tmp/cipdip/workdir", false},
		{"valid relative", "runs/output", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSSH(t)
			err := s.Mkdir(context.Background(), tt.path)
			if tt.wantTraversalErr {
				if err == nil {
					t.Fatalf("Mkdir() should reject traversal path %q", tt.path)
				}
				if !strings.Contains(err.Error(), "traversal") {
					t.Errorf("Mkdir() error should mention traversal, got: %v", err)
				}
			} else if err != nil && strings.Contains(err.Error(), "traversal") {
				t.Errorf("Mkdir() should not reject valid path %q as traversal", tt.path)
			}
		})
	}
}

func TestSSH_Stat_RejectsTraversalPath(t *testing.T) {
	s := newTestSSH(t)
	_, err := s.Stat(context.Background(), "../../../etc/passwd")
	if err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Errorf("Stat() should reject traversal path, got: %v", err)
	}
}

func TestSSH_Remove_RejectsTraversalPath(t *testing.T) {
	s := newTestSSH(t)
	err := s.Remove(context.Background(), "../../../etc/passwd")
	if err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Errorf("Remove() should reject traversal path, got: %v", err)
	}
}

// --- Issue 2: SSH password auth gating ---

func TestSSH_PasswordAuth_BlockedByDefault(t *testing.T) {
	// Point HOME to empty dir so no default keys are found.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")

	s, err := NewSSH("example.com", SSHOptions{
		Password: "secret",
		Agent:    false,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.buildSSHConfig()
	// With no agent, no key files, and AllowPassword=false,
	// there should be no auth methods available.
	if err == nil {
		t.Fatal("buildSSHConfig() should fail with no auth methods when AllowPassword is false")
	}
	if !strings.Contains(err.Error(), "no authentication methods") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSSH_PasswordAuth_AllowedWhenExplicit(t *testing.T) {
	s, err := NewSSH("example.com", SSHOptions{
		Password:           "secret",
		AllowPassword:      true,
		Agent:              false,
		InsecureIgnoreHost: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	config, err := s.buildSSHConfig()
	if err != nil {
		t.Fatalf("buildSSHConfig() should succeed when AllowPassword=true, got: %v", err)
	}
	if len(config.Auth) == 0 {
		t.Error("should have at least one auth method (password)")
	}
}

func TestParse_SSHPassword_SetsAllowPassword(t *testing.T) {
	tr, err := Parse("ssh://user:mypass@host?insecure=true")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	s, ok := tr.(*SSH)
	if !ok {
		t.Fatal("expected *SSH transport")
	}
	if s.opts.Password != "mypass" {
		t.Errorf("Password = %q, want %q", s.opts.Password, "mypass")
	}
	if !s.opts.AllowPassword {
		t.Error("AllowPassword should be true when password is provided in URL")
	}
}

func TestDefaultSSHOptions_AllowPasswordFalse(t *testing.T) {
	opts := DefaultSSHOptions()
	if opts.AllowPassword {
		t.Error("AllowPassword should be false by default")
	}
}
