package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	t.Run("no file", func(t *testing.T) {
		l, err := NewLogger(LogLevelInfo, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer l.Close()
		if l.level != LogLevelInfo {
			t.Errorf("level = %d, want %d", l.level, LogLevelInfo)
		}
		if l.file != nil {
			t.Error("file should be nil when no path given")
		}
	})

	t.Run("with file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test.log")
		l, err := NewLogger(LogLevelDebug, path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer l.Close()
		if l.file == nil {
			t.Error("file should not be nil")
		}
		if l.fileLog == nil {
			t.Error("fileLog should not be nil")
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		_, err := NewLogger(LogLevelInfo, "/nonexistent/dir/test.log")
		if err == nil {
			t.Error("expected error for invalid path")
		}
	})
}

func TestNewLoggerWithOptions(t *testing.T) {
	l, err := NewLoggerWithOptions(LogLevelVerbose, "", "json", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close()

	if l.format != "json" {
		t.Errorf("format = %q, want %q", l.format, "json")
	}
	if l.logEvery != 5 {
		t.Errorf("logEvery = %d, want 5", l.logEvery)
	}
}

func TestNewLoggerWithOptions_Defaults(t *testing.T) {
	l, err := NewLoggerWithOptions(LogLevelInfo, "", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer l.Close()

	if l.format != "text" {
		t.Errorf("format = %q, want %q", l.format, "text")
	}
	if l.logEvery != 1 {
		t.Errorf("logEvery = %d, want 1", l.logEvery)
	}
}

func TestLoggerLevels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelInfo, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.Error("error msg")
	l.Info("info msg")
	l.Verbose("verbose msg")
	l.Debug("debug msg")

	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "ERROR: error msg") {
		t.Error("log should contain error message")
	}
	if !strings.Contains(content, "INFO: info msg") {
		t.Error("log should contain info message")
	}
	if strings.Contains(content, "VERBOSE: verbose msg") {
		t.Error("log should NOT contain verbose message at Info level")
	}
	if strings.Contains(content, "DEBUG: debug msg") {
		t.Error("log should NOT contain debug message at Info level")
	}
}

func TestLoggerSilentLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelSilent, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.Error("should not appear")
	l.Info("should not appear")
	l.Close()

	data, _ := os.ReadFile(path)
	if len(strings.TrimSpace(string(data))) > 0 {
		t.Error("silent logger should produce no output")
	}
}

func TestLoggerDebugLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelDebug, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.Error("e")
	l.Info("i")
	l.Verbose("v")
	l.Debug("d")
	l.Close()

	data, _ := os.ReadFile(path)
	content := string(data)

	for _, want := range []string{"ERROR: e", "INFO: i", "VERBOSE: v", "DEBUG: d"} {
		if !strings.Contains(content, want) {
			t.Errorf("log should contain %q", want)
		}
	}
}

func TestLoggerSampling(t *testing.T) {
	// Sampling only affects console output when there's no file logger.
	// When a file is present, all messages are written to the file regardless of logEvery.
	// Test that without a file, sampled messages are skipped entirely (no console output).

	// With a file: all 9 messages written to the file
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLoggerWithOptions(LogLevelInfo, path, "text", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i := 0; i < 9; i++ {
		l.Info("msg %d", i)
	}
	l.Close()

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 9 {
		t.Errorf("file logger should write all 9 messages, got %d", len(lines))
	}

	// Without a file: logEvery=3 causes 2/3 of messages to be dropped
	l2, err := NewLoggerWithOptions(LogLevelInfo, "", "text", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Counter starts at 0, increments before check:
	// counter=1 -> 1%3!=0 -> skip (no file, returns)
	// counter=2 -> 2%3!=0 -> skip
	// counter=3 -> 3%3==0 -> write
	// So 3 out of 9 pass the sampling gate
	for i := 0; i < 9; i++ {
		l2.Info("sampled %d", i)
	}
	// Can't easily capture stdout in this test, but verify counter advanced
	if l2.counter != 9 {
		t.Errorf("counter = %d, want 9", l2.counter)
	}
	l2.Close()
}

func TestLoggerJSONFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLoggerWithOptions(LogLevelError, path, "json", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.Error("test message")
	l.Close()

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, `"level":"error"`) {
		t.Errorf("JSON output should contain level, got: %s", content)
	}
	if !strings.Contains(content, `"message"`) {
		t.Errorf("JSON output should contain message key, got: %s", content)
	}
}

func TestSetGetLevel(t *testing.T) {
	l, _ := NewLogger(LogLevelInfo, "")
	defer l.Close()

	if l.GetLevel() != LogLevelInfo {
		t.Errorf("GetLevel() = %d, want %d", l.GetLevel(), LogLevelInfo)
	}

	l.SetLevel(LogLevelDebug)
	if l.GetLevel() != LogLevelDebug {
		t.Errorf("GetLevel() = %d, want %d", l.GetLevel(), LogLevelDebug)
	}
}

func TestLogOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelVerbose, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.LogOperation("GetAttributeSingle", "InputBlock1", "0x0E", true, 1.234, 0x00, nil)
	l.LogOperation("SetAttributeSingle", "OutputBlock1", "0x10", false, 5.678, 0x08, nil)
	l.Close()

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "SUCCESS") {
		t.Error("should contain SUCCESS")
	}
	if !strings.Contains(content, "FAILED") {
		t.Error("should contain FAILED")
	}
	if !strings.Contains(content, "InputBlock1") {
		t.Error("should contain target name")
	}
	if !strings.Contains(content, "1.234ms") {
		t.Error("should contain RTT")
	}
}

func TestLogStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelVerbose, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.LogStartup("baseline", "10.0.0.50", 44818, 250, 600, "config.yaml")
	l.Close()

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "Starting CIPDIP client") {
		t.Error("should contain startup message")
	}
	if !strings.Contains(content, "baseline") {
		t.Error("should contain scenario name")
	}
}

func TestLogHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelDebug, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.LogHex("packet", []byte{0xDE, 0xAD, 0xBE, 0xEF})
	l.Close()

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "de ad be ef") {
		t.Errorf("should contain hex dump, got: %s", content)
	}
}

func TestLogHex_SkipsAtLowLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	l, err := NewLogger(LogLevelInfo, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l.LogHex("packet", []byte{0xDE, 0xAD})
	l.Close()

	data, _ := os.ReadFile(path)
	if len(strings.TrimSpace(string(data))) > 0 {
		t.Error("LogHex at Info level should produce no output")
	}
}

func TestClose_NilFile(t *testing.T) {
	l, _ := NewLogger(LogLevelInfo, "")
	if err := l.Close(); err != nil {
		t.Errorf("Close with nil file should not error: %v", err)
	}
}

func TestMultiWriter(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	mw := NewMultiWriter(&buf1, &buf2)

	msg := []byte("hello")
	n, err := mw.Write(msg)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(msg) {
		t.Errorf("Write returned %d, want %d", n, len(msg))
	}
	if buf1.String() != "hello" {
		t.Errorf("buf1 = %q, want %q", buf1.String(), "hello")
	}
	if buf2.String() != "hello" {
		t.Errorf("buf2 = %q, want %q", buf2.String(), "hello")
	}
}

type errWriter struct{}

func (e errWriter) Write([]byte) (int, error) {
	return 0, os.ErrClosed
}

func TestMultiWriter_Error(t *testing.T) {
	var buf bytes.Buffer
	mw := NewMultiWriter(&buf, errWriter{})

	_, err := mw.Write([]byte("test"))
	if err == nil {
		t.Error("expected error from failing writer")
	}
}

func TestLevelLabel(t *testing.T) {
	if levelLabel(true) != "error" {
		t.Errorf("levelLabel(true) = %q, want %q", levelLabel(true), "error")
	}
	if levelLabel(false) != "info" {
		t.Errorf("levelLabel(false) = %q, want %q", levelLabel(false), "info")
	}
}
