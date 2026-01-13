package tui

import (
	"context"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/manifest"
	"github.com/tturner/cipdip/internal/orch/controller"
)

// OrchRunConfig holds configuration for an orchestration run.
type OrchRunConfig struct {
	Manifest      *manifest.Manifest
	BundleDir     string
	Timeout       time.Duration
	DryRun        bool
	Verbose       bool
	Agents        map[string]string // role -> transport mapping
	WorkspaceRoot string
}

// orchOutputMsg delivers real-time output from a runner.
type orchOutputMsg struct {
	event controller.OutputEvent
}

// orchPhaseUpdateMsg delivers phase change updates.
type orchPhaseUpdateMsg struct {
	phase   string
	message string
}

// orchRunDoneMsg signals run completion.
type orchRunDoneMsg struct {
	result *controller.Result
	err    error
}

// StartOrchRunCmd starts the orchestration controller and returns output/phase events.
func StartOrchRunCmd(ctx context.Context, cfg OrchRunConfig, outputCh chan<- controller.OutputEvent, phaseCh chan<- orchPhaseUpdateMsg) tea.Cmd {
	return func() tea.Msg {
		// Set up controller options
		bundleDir := cfg.BundleDir
		if bundleDir == "" {
			bundleDir = filepath.Join(cfg.WorkspaceRoot, "runs")
		}

		opts := controller.Options{
			BundleDir:    bundleDir,
			BundleFormat: "dir",
			Timeout:      cfg.Timeout,
			DryRun:       cfg.DryRun,
			Verbose:      cfg.Verbose,
			Agents:       cfg.Agents,
		}

		// Create controller
		ctrl, err := controller.New(cfg.Manifest, opts)
		if err != nil {
			return orchRunDoneMsg{err: err}
		}
		defer ctrl.Close()

		// Set up phase callback
		ctrl.SetPhaseCallback(func(phase controller.Phase, msg string) {
			select {
			case phaseCh <- orchPhaseUpdateMsg{phase: string(phase), message: msg}:
			default:
			}
		})

		// Run the controller
		result, err := ctrl.Run(ctx)

		return orchRunDoneMsg{result: result, err: err}
	}
}

// ForwardOrchOutputCmd forwards output events from runners to the TUI.
func ForwardOrchOutputCmd(outputCh <-chan controller.OutputEvent) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-outputCh
		if !ok {
			return nil
		}
		return orchOutputMsg{event: event}
	}
}

// ForwardOrchPhaseCmd forwards phase events to the TUI.
func ForwardOrchPhaseCmd(phaseCh <-chan orchPhaseUpdateMsg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-phaseCh
		if !ok {
			return nil
		}
		return msg
	}
}
