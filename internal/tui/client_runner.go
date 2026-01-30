package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/ui"
)

// ClientRunConfig contains the configuration for a client run.
type ClientRunConfig struct {
	TargetIP   string
	Port       int
	Scenario   string
	DurationS  int
	IntervalMs int
	PCAPFile   string
	Interface  string
	Profile    string
	Role       string
	OutputDir  string
	TargetTags string // Comma-separated list of tags to filter targets
}

// ClientRunResult is sent when the client run completes.
type ClientRunResult struct {
	Success  bool
	Error    error
	Output   string
	Duration time.Duration
	Stats    StatsUpdate
}

// startClientRunMsg signals the model to start a client run.
type startClientRunMsg struct {
	config ClientRunConfig
}

// clientRunResultMsg is the bubbletea message for client run completion.
type clientRunResultMsg struct {
	result ClientRunResult
}

// clientStatsMsg is the bubbletea message for client stats updates.
type clientStatsMsg struct {
	stats StatsUpdate
}

// BuildCommandArgs builds CLI arguments from the config.
func (cfg ClientRunConfig) BuildCommandArgs() []string {
	args := []string{"cipdip", "client",
		"--ip", cfg.TargetIP,
		"--port", strconv.Itoa(cfg.Port),
		"--duration-seconds", strconv.Itoa(cfg.DurationS),
	}

	if cfg.Profile != "" {
		args = append(args, "--profile", cfg.Profile)
		if cfg.Role != "" {
			args = append(args, "--role", cfg.Role)
		}
	} else {
		args = append(args, "--scenario", cfg.Scenario)
		if cfg.IntervalMs > 0 {
			args = append(args, "--interval-ms", strconv.Itoa(cfg.IntervalMs))
		}
	}

	if cfg.PCAPFile != "" {
		args = append(args, "--pcap", cfg.PCAPFile)
		if cfg.Interface != "" {
			args = append(args, "--capture-interface", cfg.Interface)
		}
	}

	if cfg.OutputDir != "" {
		args = append(args, "--output-dir", cfg.OutputDir)
	}

	if cfg.TargetTags != "" {
		args = append(args, "--target-tags", cfg.TargetTags)
	}

	return args
}

// StartClientRun starts the client using ui.StartStreamingCommand.
// Returns a command that monitors the run and sends result messages.
func StartClientRun(ctx context.Context, cfg ClientRunConfig, statsChan chan<- StatsUpdate, resultChan chan<- CommandResult) {
	// Build command
	args := cfg.BuildCommandArgs()
	command := ui.CommandSpec{Args: args}

	// Use ui's streaming command execution
	uiStatsChan, uiResultChan, err := ui.StartStreamingCommand(ctx, command)
	if err != nil {
		resultChan <- CommandResult{
			Output:   fmt.Sprintf("Failed to start: %v", err),
			ExitCode: 1,
			Err:      err,
		}
		return
	}

	// Forward stats and results
	go func() {
		for stats := range uiStatsChan {
			// Convert ui.StatsUpdate to tui.StatsUpdate
			statsChan <- StatsUpdate{
				ActiveConnections:  stats.ActiveConnections,
				TotalConnections:   stats.TotalConnections,
				TotalRequests:      stats.TotalRequests,
				TotalErrors:        stats.TotalErrors,
				RecentClients:      stats.RecentClients,
				SuccessfulRequests: stats.SuccessfulRequests,
				FailedRequests:     stats.FailedRequests,
				Timeouts:           stats.Timeouts,
			}
		}
	}()

	go func() {
		result := <-uiResultChan
		resultChan <- CommandResult{
			Output:   result.Output,
			ExitCode: result.ExitCode,
			Err:      result.Err,
		}
	}()
}

// StartClientRunCmd returns a tea.Cmd that starts the client run.
// Stats and results are forwarded to the provided channels.
func StartClientRunCmd(ctx context.Context, cfg ClientRunConfig, statsChan chan<- StatsUpdate, resultChan chan<- CommandResult) tea.Cmd {
	return func() tea.Msg {
		// Build command
		args := cfg.BuildCommandArgs()
		command := ui.CommandSpec{Args: args}

		// Create timeout context
		deadline := time.Duration(cfg.DurationS)*time.Second + 30*time.Second
		runCtx, cancel := context.WithTimeout(ctx, deadline)
		defer cancel()

		// Use ui's streaming command execution
		uiStatsChan, uiResultChan, err := ui.StartStreamingCommand(runCtx, command)
		if err != nil {
			result := CommandResult{
				Output:   fmt.Sprintf("Failed to start: %v", err),
				ExitCode: 1,
				Err:      err,
			}
			if resultChan != nil {
				resultChan <- result
			}
			return clientRunResultMsg{
				result: ClientRunResult{
					Error:  err,
					Output: result.Output,
				},
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

		return clientRunResultMsg{
			result: ClientRunResult{
				Success:  result.Err == nil,
				Error:    result.Err,
				Output:   result.Output,
				Duration: time.Duration(cfg.DurationS) * time.Second,
			},
		}
	}
}

// GeneratePCAPFilename generates a PCAP filename based on the run configuration.
func GeneratePCAPFilename(cfg ClientRunConfig, workspaceRoot string) string {
	timestamp := time.Now().Format("2006-01-02T150405")
	var name string
	if cfg.Profile != "" {
		name = fmt.Sprintf("client_%s_%s_%s.pcap", cfg.Profile, cfg.Role, timestamp)
	} else {
		name = fmt.Sprintf("client_%s_%s.pcap", cfg.Scenario, timestamp)
	}

	if workspaceRoot != "" {
		pcapDir := filepath.Join(workspaceRoot, "pcaps")
		return filepath.Join(pcapDir, name)
	}

	return name
}
