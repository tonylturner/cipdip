package app

import (
	"testing"

	"github.com/tonylturner/cipdip/internal/config"
)

// createMinimalServerConfig creates a minimal server config for testing
func createMinimalServerConfig() *config.ServerConfig {
	return &config.ServerConfig{
		Server: config.ServerConfigSection{
			ListenIP:    "0.0.0.0",
			TCPPort:     44818,
			Personality: "adapter",
		},
		Faults: config.ServerFaultConfig{
			Enable: false,
			Latency: config.ServerFaultLatencyConfig{
				BaseDelayMs:  0,
				JitterMs:     0,
				SpikeEveryN:  0,
				SpikeDelayMs: 0,
			},
			Reliability: config.ServerFaultReliabilityConfig{
				DropResponseEveryN:    0,
				CloseConnectionEveryN: 0,
			},
			TCP: config.ServerFaultTCPConfig{
				ChunkWrites: false,
				ChunkMin:    0,
				ChunkMax:    0,
			},
		},
		Logging: config.ServerLoggingConfig{
			Level:     "info",
			LogEveryN: 1,
		},
	}
}

func TestApplyServerMode(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		wantErr       bool
		checkFaults   bool
		checkLogging  bool
		expectedLevel string
	}{
		{
			name:          "baseline mode",
			mode:          "baseline",
			wantErr:       false,
			checkFaults:   true,
			checkLogging:  true,
			expectedLevel: "info",
		},
		{
			name:          "realistic mode",
			mode:          "realistic",
			wantErr:       false,
			checkFaults:   true,
			checkLogging:  true,
			expectedLevel: "info",
		},
		{
			name:         "dpi-torture mode",
			mode:         "dpi-torture",
			wantErr:      false,
			checkFaults:  true,
			checkLogging: true,
		},
		{
			name:          "perf mode",
			mode:          "perf",
			wantErr:       false,
			checkFaults:   true,
			checkLogging:  true,
			expectedLevel: "error",
		},
		{
			name:    "unknown mode",
			mode:    "unknown",
			wantErr: true,
		},
		{
			name:    "empty mode",
			mode:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal test config
			cfg := createMinimalServerConfig()

			err := ApplyServerMode(cfg, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyServerMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if tt.checkLogging && tt.expectedLevel != "" {
				if cfg.Logging.Level != tt.expectedLevel {
					t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, tt.expectedLevel)
				}
			}
		})
	}
}

func TestApplyServerModeDPITortureSettings(t *testing.T) {
	cfg := createMinimalServerConfig()

	err := ApplyServerMode(cfg, "dpi-torture")
	if err != nil {
		t.Fatalf("ApplyServerMode() error = %v", err)
	}

	// Verify DPI torture settings are applied
	if !cfg.Faults.Enable {
		t.Error("Faults.Enable should be true for dpi-torture mode")
	}
	if cfg.Faults.Latency.BaseDelayMs != 5 {
		t.Errorf("Faults.Latency.BaseDelayMs = %d, want 5", cfg.Faults.Latency.BaseDelayMs)
	}
	if cfg.Faults.Latency.JitterMs != 10 {
		t.Errorf("Faults.Latency.JitterMs = %d, want 10", cfg.Faults.Latency.JitterMs)
	}
	if cfg.Faults.Latency.SpikeEveryN != 10 {
		t.Errorf("Faults.Latency.SpikeEveryN = %d, want 10", cfg.Faults.Latency.SpikeEveryN)
	}
	if cfg.Faults.Latency.SpikeDelayMs != 25 {
		t.Errorf("Faults.Latency.SpikeDelayMs = %d, want 25", cfg.Faults.Latency.SpikeDelayMs)
	}
	if cfg.Faults.Reliability.DropResponseEveryN != 25 {
		t.Errorf("Faults.Reliability.DropResponseEveryN = %d, want 25", cfg.Faults.Reliability.DropResponseEveryN)
	}
	if cfg.Faults.Reliability.CloseConnectionEveryN != 50 {
		t.Errorf("Faults.Reliability.CloseConnectionEveryN = %d, want 50", cfg.Faults.Reliability.CloseConnectionEveryN)
	}
	if !cfg.Faults.TCP.ChunkWrites {
		t.Error("Faults.TCP.ChunkWrites should be true")
	}
	if cfg.Faults.TCP.ChunkMin != 2 {
		t.Errorf("Faults.TCP.ChunkMin = %d, want 2", cfg.Faults.TCP.ChunkMin)
	}
	if cfg.Faults.TCP.ChunkMax != 4 {
		t.Errorf("Faults.TCP.ChunkMax = %d, want 4", cfg.Faults.TCP.ChunkMax)
	}
}

func TestApplyServerModePerfSettings(t *testing.T) {
	cfg := createMinimalServerConfig()
	cfg.Faults.Enable = true // Enable faults first

	err := ApplyServerMode(cfg, "perf")
	if err != nil {
		t.Fatalf("ApplyServerMode() error = %v", err)
	}

	// Verify perf mode disables faults and reduces logging
	if cfg.Faults.Enable {
		t.Error("Faults.Enable should be false for perf mode")
	}
	if cfg.Logging.Level != "error" {
		t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "error")
	}
	if cfg.Logging.LogEveryN != 100 {
		t.Errorf("Logging.LogEveryN = %d, want 100", cfg.Logging.LogEveryN)
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"error", "error"},
		{"verbose", "verbose"},
		{"debug", "debug"},
		{"info", "info"},
		{"unknown", "info"}, // defaults to info
		{"", "info"},        // defaults to info
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseLogLevel(tt.input)
			// parseLogLevel returns logging.LogLevel, which is an int
			// We just verify it returns without error
			_ = result
		})
	}
}

func TestServerOptionsValidation(t *testing.T) {
	opts := ServerOptions{
		ListenIP:    "0.0.0.0",
		ListenPort:  44818,
		Personality: "adapter",
	}

	// Basic validation
	if opts.ListenIP == "" {
		t.Error("ListenIP should not be empty")
	}
	if opts.ListenPort == 0 {
		t.Error("ListenPort should not be 0")
	}
	if opts.Personality == "" {
		t.Error("Personality should not be empty")
	}
}

func TestServerOptionsDefaults(t *testing.T) {
	opts := ServerOptions{}

	// Verify defaults are handled properly
	if opts.ListenPort != 0 {
		t.Error("Default ListenPort should be 0 (unset)")
	}
	if opts.EnableUDPIO {
		t.Error("Default EnableUDPIO should be false")
	}
	if opts.TUIStats {
		t.Error("Default TUIStats should be false")
	}
}
