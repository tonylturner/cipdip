package ui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// OpenEditor opens a file in the user's preferred editor.
func OpenEditor(path string) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		if runtime.GOOS == "windows" {
			editor = "notepad"
		} else {
			editor = "nano"
		}
	}
	cmd := exec.Command(editor, path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("open editor: %w", err)
	}
	return nil
}
