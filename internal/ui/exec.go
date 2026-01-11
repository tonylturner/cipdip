package ui

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
)

// ExecuteCommand runs a command spec and returns stdout/stderr and exit code.
func ExecuteCommand(ctx context.Context, command CommandSpec) (string, int, error) {
	if len(command.Args) == 0 {
		return "", 0, fmt.Errorf("command is empty")
	}
	executable, err := os.Executable()
	if err != nil {
		executable = command.Args[0]
	}
	args := command.Args[1:]
	if command.Args[0] != "cipdip" {
		executable = command.Args[0]
		args = command.Args[1:]
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}
	return output.String(), exitCode, err
}

// StatsUpdate represents a stats update message from a running subprocess.
type StatsUpdate struct {
	ActiveConnections int      `json:"active_connections"`
	TotalConnections  int      `json:"total_connections"`
	TotalRequests     int      `json:"total_requests"`
	TotalErrors       int      `json:"total_errors"`
	RecentClients     []string `json:"recent_clients,omitempty"`
	// Client stats fields
	SuccessfulRequests int `json:"successful_requests"`
	FailedRequests     int `json:"failed_requests"`
	Timeouts           int `json:"timeouts"`
}

// serverStatsMsg is sent to update server stats from subprocess output.
type serverStatsMsg struct {
	Stats StatsUpdate
}

// clientStatsMsg is sent to update client stats from subprocess output.
type clientStatsMsg struct {
	Stats StatsUpdate
}

// clientStatusMsg represents the final status of a client command.
type clientStatusMsg struct {
	Stopped  bool
	Stdout   string
	RunDir   string
	ExitCode int
	Err      error
}

// ExecuteStreamingCommand runs a command and streams stats updates as messages.
// It returns a command that sends stats updates and a final serverStatusMsg or clientStatusMsg.
func ExecuteStreamingCommand(ctx context.Context, command CommandSpec, isServer bool) tea.Cmd {
	return func() tea.Msg {
		if len(command.Args) == 0 {
			if isServer {
				return serverStatusMsg{Stopped: true, Err: fmt.Errorf("command is empty")}
			}
			return clientStatusMsg{Stopped: true, Err: fmt.Errorf("command is empty")}
		}

		executable, err := os.Executable()
		if err != nil {
			executable = command.Args[0]
		}
		args := command.Args[1:]
		if command.Args[0] != "cipdip" {
			executable = command.Args[0]
			args = command.Args[1:]
		}

		// Add --tui-stats flag
		args = append(args, "--tui-stats")

		cmd := exec.CommandContext(ctx, executable, args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			if isServer {
				return serverStatusMsg{Stopped: true, Err: err}
			}
			return clientStatusMsg{Stopped: true, Err: err}
		}

		var outputBuf bytes.Buffer

		if err := cmd.Start(); err != nil {
			if isServer {
				return serverStatusMsg{Stopped: true, Err: err}
			}
			return clientStatusMsg{Stopped: true, Err: err}
		}

		// Read stdout line by line
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			outputBuf.WriteString(line)
			outputBuf.WriteString("\n")

			// Try to parse as JSON stats
			var msg struct {
				Type  string      `json:"type"`
				Stats StatsUpdate `json:"stats"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err == nil && msg.Type == "stats" {
				// Stats line - we can't send a message from here directly
				// but we record the latest stats
				continue
			}
		}

		// Wait for command to finish
		err = cmd.Wait()
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}

		if isServer {
			return serverStatusMsg{
				Stopped:  true,
				Stdout:   outputBuf.String(),
				ExitCode: exitCode,
				Err:      err,
			}
		}
		return clientStatusMsg{
			Stopped:  true,
			Stdout:   outputBuf.String(),
			ExitCode: exitCode,
			Err:      err,
		}
	}
}

// StartStreamingCommand starts a command and returns channels for stats and completion.
func StartStreamingCommand(ctx context.Context, command CommandSpec) (<-chan StatsUpdate, <-chan CommandResult, error) {
	if len(command.Args) == 0 {
		return nil, nil, fmt.Errorf("command is empty")
	}

	executable, err := os.Executable()
	if err != nil {
		executable = command.Args[0]
	}
	args := command.Args[1:]
	if command.Args[0] != "cipdip" {
		executable = command.Args[0]
		args = command.Args[1:]
	}

	// Add --tui-stats flag
	args = append(args, "--tui-stats")

	cmd := exec.CommandContext(ctx, executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}

	statsChan := make(chan StatsUpdate, 100)
	resultChan := make(chan CommandResult, 1)

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	go func() {
		defer close(statsChan)
		defer close(resultChan)

		var outputBuf bytes.Buffer
		var outputMu sync.Mutex
		lineChan := make(chan string, 1000)

		// Read stdout in a goroutine
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				select {
				case lineChan <- scanner.Text():
				default:
					// Drop line if channel is full to prevent blocking
				}
			}
		}()

		// Read stderr in a goroutine
		go func() {
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				select {
				case lineChan <- scanner.Text():
				default:
					// Drop line if channel is full to prevent blocking
				}
			}
		}()

		// Process lines until command exits
		done := make(chan struct{})
		go func() {
			for line := range lineChan {
				outputMu.Lock()
				outputBuf.WriteString(line)
				outputBuf.WriteString("\n")
				outputMu.Unlock()

				// Try to parse as JSON stats
				var msg struct {
					Type  string      `json:"type"`
					Stats StatsUpdate `json:"stats"`
				}
				if err := json.Unmarshal([]byte(line), &msg); err == nil && msg.Type == "stats" {
					// Drain any old stats to make room for new one
					for {
						select {
						case <-statsChan:
							// Drained one old stat
						default:
							// Channel is not full, we can send
							goto sendStats
						}
					}
				sendStats:
					// Now send the new stats (non-blocking in case channel closed)
					select {
					case statsChan <- msg.Stats:
					default:
					}
				}
			}
			close(done)
		}()

		// Wait for command to finish
		err := cmd.Wait()
		close(lineChan)
		<-done // Wait for line processing to complete

		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}

		outputMu.Lock()
		output := outputBuf.String()
		outputMu.Unlock()

		resultChan <- CommandResult{
			Output:   output,
			ExitCode: exitCode,
			Err:      err,
		}
	}()

	return statsChan, resultChan, nil
}

// CommandResult represents the final result of a command execution.
type CommandResult struct {
	Output   string
	ExitCode int
	Err      error
}
