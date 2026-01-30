package tui

import (
	"context"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/ui"
)

// DiscoverRunConfig contains the configuration for a discover operation.
type DiscoverRunConfig struct {
	Interface string        // Network interface (empty = all)
	Timeout   time.Duration // Discovery timeout
	Output    string        // Output format: text|json
}

// startDiscoverRunMsg signals the model to start a discover operation.
type startDiscoverRunMsg struct {
	config DiscoverRunConfig
}

// discoverRunResultMsg is the bubbletea message for discover completion.
type discoverRunResultMsg struct {
	output   string
	exitCode int
	err      error
}

// BuildCommandArgs builds CLI arguments from the config.
func (cfg DiscoverRunConfig) BuildCommandArgs() []string {
	args := []string{"cipdip", "discover"}

	if cfg.Interface != "" {
		args = append(args, "--interface", cfg.Interface)
	}

	if cfg.Timeout > 0 {
		args = append(args, "--timeout", cfg.Timeout.String())
	}

	if cfg.Output != "" && cfg.Output != "text" {
		args = append(args, "--output", cfg.Output)
	}

	return args
}

// StartDiscoverRunCmd starts the discovery and returns results.
func StartDiscoverRunCmd(ctx context.Context, cfg DiscoverRunConfig) tea.Cmd {
	return func() tea.Msg {
		args := cfg.BuildCommandArgs()
		command := ui.CommandSpec{Args: args}

		// Discovery operations are quick, use simple execution
		stdout, exitCode, err := ui.ExecuteCommand(ctx, command)

		return discoverRunResultMsg{
			output:   stdout,
			exitCode: exitCode,
			err:      err,
		}
	}
}
