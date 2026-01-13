package tui

import (
	"os/exec"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// clipboardCopyMsg is sent after a clipboard copy operation.
type clipboardCopyMsg struct {
	success bool
	content string
	err     error
}

// copyToClipboard copies text to the system clipboard.
// Returns a tea.Cmd that will send a clipboardCopyMsg when complete.
func copyToClipboard(text string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd

		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("pbcopy")
		case "linux":
			// Try xclip first, fall back to xsel
			if _, err := exec.LookPath("xclip"); err == nil {
				cmd = exec.Command("xclip", "-selection", "clipboard")
			} else if _, err := exec.LookPath("xsel"); err == nil {
				cmd = exec.Command("xsel", "--clipboard", "--input")
			} else {
				return clipboardCopyMsg{success: false, content: text, err: nil}
			}
		case "windows":
			cmd = exec.Command("clip")
		default:
			return clipboardCopyMsg{success: false, content: text, err: nil}
		}

		cmd.Stdin = strings.NewReader(text)
		err := cmd.Run()
		if err != nil {
			return clipboardCopyMsg{success: false, content: text, err: err}
		}

		return clipboardCopyMsg{success: true, content: text, err: nil}
	}
}
