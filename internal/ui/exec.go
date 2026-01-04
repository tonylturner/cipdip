package ui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
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
