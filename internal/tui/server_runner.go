package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tonylturner/cipdip/internal/ui"
)

// ServerRunConfig contains the configuration for a server run.
type ServerRunConfig struct {
	ListenAddr         string
	Port               int
	Personality        string
	PCAPFile           string
	Interface          string
	Profile            string
	OutputDir          string
	EnableUDPIO        bool
	UDPPort            int
	MulticastGroup     string
	MulticastInterface string

	// Fault injection
	FaultEnabled       bool
	LatencyBaseMs      int
	LatencyJitterMs    int
	DropResponseEveryN int
	CloseConnEveryN    int

	// Session policy
	MaxSessions      int
	MaxSessionsPerIP int
	SessionTimeoutMs int

	// Identity customization
	VendorID    int
	DeviceType  int
	ProductCode int
	ProductName string

	// Modbus configuration
	ModbusEnabled   bool
	ModbusCIPTunnel bool
	ModbusPort      int
}

// startServerRunMsg signals the model to start a server run.
type startServerRunMsg struct {
	config ServerRunConfig
}

// serverRunResultMsg is the bubbletea message for server run completion.
type serverRunResultMsg struct {
	output   string
	exitCode int
	err      error
}

// serverStatsMsg is the bubbletea message for server stats updates.
type serverStatsMsg struct {
	stats StatsUpdate
}

// BuildCommandArgs builds CLI arguments from the config.
func (cfg ServerRunConfig) BuildCommandArgs() []string {
	args := []string{"cipdip", "server"}

	// Always pass listen address and port if set
	if cfg.ListenAddr != "" {
		args = append(args, "--listen-ip", cfg.ListenAddr)
	}
	if cfg.Port != 0 {
		args = append(args, "--listen-port", strconv.Itoa(cfg.Port))
	}

	if cfg.Profile != "" {
		// Profile sets personality and data model
		args = append(args, "--profile", cfg.Profile)
	} else {
		// Manual config - need personality
		if cfg.Personality != "" {
			args = append(args, "--personality", cfg.Personality)
		}
	}

	if cfg.EnableUDPIO {
		args = append(args, "--enable-udp-io")
		if cfg.UDPPort != 0 {
			args = append(args, "--udp-port", strconv.Itoa(cfg.UDPPort))
		}
	}

	if cfg.MulticastGroup != "" {
		args = append(args, "--multicast-group", cfg.MulticastGroup)
		if cfg.MulticastInterface != "" {
			args = append(args, "--multicast-interface", cfg.MulticastInterface)
		}
	}

	if cfg.PCAPFile != "" {
		// Combine OutputDir (workspace root) with relative PCAP path
		pcapPath := cfg.PCAPFile
		if cfg.OutputDir != "" && !filepath.IsAbs(cfg.PCAPFile) {
			pcapPath = filepath.Join(cfg.OutputDir, cfg.PCAPFile)
		}
		args = append(args, "--pcap", pcapPath)
		if cfg.Interface != "" {
			args = append(args, "--capture-interface", cfg.Interface)
		}
	}

	// Fault injection options
	if cfg.FaultEnabled {
		args = append(args, "--fault-enabled")
		if cfg.LatencyBaseMs > 0 {
			args = append(args, "--latency-base-ms", strconv.Itoa(cfg.LatencyBaseMs))
		}
		if cfg.LatencyJitterMs > 0 {
			args = append(args, "--latency-jitter-ms", strconv.Itoa(cfg.LatencyJitterMs))
		}
		if cfg.DropResponseEveryN > 0 {
			args = append(args, "--drop-response-every-n", strconv.Itoa(cfg.DropResponseEveryN))
		}
		if cfg.CloseConnEveryN > 0 {
			args = append(args, "--close-conn-every-n", strconv.Itoa(cfg.CloseConnEveryN))
		}
	}

	// Session policy options
	if cfg.MaxSessions > 0 && cfg.MaxSessions != 256 {
		args = append(args, "--max-sessions", strconv.Itoa(cfg.MaxSessions))
	}
	if cfg.MaxSessionsPerIP > 0 && cfg.MaxSessionsPerIP != 64 {
		args = append(args, "--max-sessions-per-ip", strconv.Itoa(cfg.MaxSessionsPerIP))
	}
	if cfg.SessionTimeoutMs > 0 && cfg.SessionTimeoutMs != 60000 {
		args = append(args, "--session-timeout-ms", strconv.Itoa(cfg.SessionTimeoutMs))
	}

	// Identity customization
	if cfg.VendorID > 0 {
		args = append(args, "--vendor-id", strconv.Itoa(cfg.VendorID))
	}
	if cfg.DeviceType > 0 {
		args = append(args, "--device-type", strconv.Itoa(cfg.DeviceType))
	}
	if cfg.ProductCode > 0 {
		args = append(args, "--product-code", strconv.Itoa(cfg.ProductCode))
	}
	if cfg.ProductName != "" {
		args = append(args, "--product-name", cfg.ProductName)
	}

	// Modbus configuration
	if cfg.ModbusEnabled {
		args = append(args, "--modbus-enabled")
		if cfg.ModbusCIPTunnel {
			args = append(args, "--modbus-cip-tunnel")
		}
		if cfg.ModbusPort > 0 && cfg.ModbusPort != 502 {
			args = append(args, "--modbus-port", strconv.Itoa(cfg.ModbusPort))
		}
	}

	return args
}

// StartServerRunCmd starts the server and forwards stats to the provided channels.
// Returns a tea.Cmd that signals when the server exits.
func StartServerRunCmd(ctx context.Context, cfg ServerRunConfig, statsChan chan<- StatsUpdate, resultChan chan<- CommandResult) tea.Cmd {
	return func() tea.Msg {
		// Build command
		args := cfg.BuildCommandArgs()
		command := ui.CommandSpec{Args: args}

		// Use ui's streaming command execution
		uiStatsChan, uiResultChan, err := ui.StartStreamingCommand(ctx, command)
		if err != nil {
			result := CommandResult{
				Output:   fmt.Sprintf("Failed to start: %v", err),
				ExitCode: 1,
				Err:      err,
			}
			if resultChan != nil {
				resultChan <- result
			}
			return serverRunResultMsg{
				output:   result.Output,
				exitCode: result.ExitCode,
				err:      result.Err,
			}
		}

		// Forward stats to the model's channel
		go func() {
			for stats := range uiStatsChan {
				if statsChan != nil {
					select {
					case statsChan <- StatsUpdate(stats):
					default:
						// Don't block if channel is full
					}
				}
			}
		}()

		// Wait for result
		result := <-uiResultChan
		cmdResult := CommandResult{
			Output:   result.Output,
			ExitCode: result.ExitCode,
			Err:      result.Err,
		}

		// Forward result to model's channel
		if resultChan != nil {
			resultChan <- cmdResult
		}

		return serverRunResultMsg{
			output:   result.Output,
			exitCode: result.ExitCode,
			err:      result.Err,
		}
	}
}

// GenerateServerPCAPFilename generates a PCAP filename for server capture.
func GenerateServerPCAPFilename(cfg ServerRunConfig, workspaceRoot string) string {
	timestamp := time.Now().Format("2006-01-02T150405")
	name := fmt.Sprintf("server_%s_%s.pcap", cfg.Personality, timestamp)

	if workspaceRoot != "" {
		pcapDir := filepath.Join(workspaceRoot, "pcaps")
		return filepath.Join(pcapDir, name)
	}

	return name
}
