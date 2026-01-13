//go:build windows

package ui

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW prevents the subprocess from creating a console window.
// This is a Windows API constant (0x08000000).
const CREATE_NO_WINDOW = 0x08000000

// hideWindow sets Windows-specific process attributes to hide the console window
// for subprocess execution. This prevents output from bleeding through to the TUI.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NO_WINDOW,
		HideWindow:    true,
	}
}
