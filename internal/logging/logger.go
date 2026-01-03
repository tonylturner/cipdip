package logging

// Structured logging for CIPDIP

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// LogLevel represents the logging level
type LogLevel int

const (
	LogLevelSilent LogLevel = iota
	LogLevelError
	LogLevelInfo
	LogLevelVerbose
	LogLevelDebug
)

// Logger provides structured logging
type Logger struct {
	mu      sync.Mutex
	level   LogLevel
	file    *os.File
	fileLog *log.Logger
	stdout  *log.Logger
	stderr  *log.Logger
}

// NewLogger creates a new logger
func NewLogger(level LogLevel, logFile string) (*Logger, error) {
	l := &Logger{
		level:  level,
		stdout: log.New(os.Stdout, "", 0),
		stderr: log.New(os.Stderr, "", 0),
	}

	// Open log file if specified
	if logFile != "" {
		file, err := os.Create(logFile)
		if err != nil {
			return nil, fmt.Errorf("create log file: %w", err)
		}
		l.file = file
		l.fileLog = log.New(file, "", log.LstdFlags)
	}

	return l, nil
}

// Close closes the logger and flushes all data
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	if l.level >= LogLevelError {
		msg := fmt.Sprintf("ERROR: "+format, v...)
		l.write(msg, true)
	}
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	if l.level >= LogLevelInfo {
		msg := fmt.Sprintf("INFO: "+format, v...)
		l.write(msg, false)
	}
}

// Verbose logs a verbose message
func (l *Logger) Verbose(format string, v ...interface{}) {
	if l.level >= LogLevelVerbose {
		msg := fmt.Sprintf("VERBOSE: "+format, v...)
		l.write(msg, false)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level >= LogLevelDebug {
		msg := fmt.Sprintf("DEBUG: "+format, v...)
		l.write(msg, false)
	}
}

// write writes a message to the appropriate outputs
func (l *Logger) write(msg string, isError bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Always write to log file if available
	if l.fileLog != nil {
		l.fileLog.Println(msg)
	}

	// Write to stdout/stderr based on level and error status
	// Errors go to stderr, others to stdout (but only if verbose/debug)
	if isError {
		l.stderr.Println(msg)
	} else if l.level >= LogLevelVerbose {
		// Only print to stdout if verbose or debug
		l.stdout.Println(msg)
	}
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() LogLevel {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// LogOperation logs a CIP operation
func (l *Logger) LogOperation(operation, target, serviceCode string, success bool, rttMs float64, status uint8, err error) {
	var statusStr string
	if success {
		statusStr = "SUCCESS"
	} else {
		statusStr = "FAILED"
	}

	var errStr string
	if err != nil {
		errStr = fmt.Sprintf(" - error: %v", err)
	}

	msg := fmt.Sprintf("%s %s on %s (service: %s, status: 0x%02X, RTT: %.3fms)%s",
		statusStr, operation, target, serviceCode, status, rttMs, errStr)

	if success {
		l.Verbose(msg)
	} else {
		l.Info(msg)
	}
}

// LogStartup logs startup information
func (l *Logger) LogStartup(scenario, ip string, port int, intervalMs, durationSec int, configPath string) {
	l.Info("Starting CIPDIP client")
	l.Verbose("  Scenario: %s", scenario)
	l.Verbose("  Target: %s:%d", ip, port)
	l.Verbose("  Interval: %d ms", intervalMs)
	l.Verbose("  Duration: %d seconds", durationSec)
	l.Verbose("  Config: %s", configPath)
}

// LogHex logs hex data (for debug level)
func (l *Logger) LogHex(label string, data []byte) {
	if l.level >= LogLevelDebug {
		hexStr := fmt.Sprintf("%x", data)
		// Format as hex with spaces every 2 bytes
		formatted := ""
		for i := 0; i < len(hexStr); i += 2 {
			if i > 0 {
				formatted += " "
			}
			if i+2 <= len(hexStr) {
				formatted += hexStr[i : i+2]
			} else {
				formatted += hexStr[i:]
			}
		}
		l.Debug("%s: %s", label, formatted)
	}
}

// MultiWriter creates an io.Writer that writes to multiple writers
type MultiWriter struct {
	writers []io.Writer
}

// NewMultiWriter creates a new multi-writer
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Write writes to all writers
func (m *MultiWriter) Write(p []byte) (n int, err error) {
	for _, w := range m.writers {
		n, err = w.Write(p)
		if err != nil {
			return n, err
		}
	}
	return len(p), nil
}
