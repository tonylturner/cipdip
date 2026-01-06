package pcap

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ResolveTsharkPath resolves the tshark executable path using explicit path, env var, or defaults.
func ResolveTsharkPath(explicit string) (string, error) {
	if explicit == "" {
		explicit = os.Getenv("TSHARK")
	}
	if explicit != "" {
		if filepath.Base(explicit) == explicit {
			path, err := exec.LookPath(explicit)
			if err != nil {
				return "", tsharkNotFoundError()
			}
			return path, nil
		}
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("tshark path not found: %w", err)
		}
		return explicit, nil
	}

	if path, err := exec.LookPath("tshark"); err == nil {
		return path, nil
	}
	if runtime.GOOS == "windows" {
		if path := defaultTsharkWindows(); path != "" {
			return path, nil
		}
	}
	if runtime.GOOS == "darwin" {
		if path := defaultTsharkDarwin(); path != "" {
			return path, nil
		}
	}

	return "", tsharkNotFoundError()
}

func defaultTsharkWindows() string {
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Wireshark", "tshark.exe"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Wireshark", "tshark.exe"),
	}
	for _, candidate := range paths {
		if candidate == "Wireshark\\tshark.exe" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

func defaultTsharkDarwin() string {
	candidate := "/Applications/Wireshark.app/Contents/MacOS/tshark"
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func tsharkNotFoundError() error {
	switch runtime.GOOS {
	case "windows":
		return fmt.Errorf("tshark not found in PATH or default locations; install Wireshark or pass --tshark")
	case "darwin":
		return fmt.Errorf("tshark not found in PATH or /Applications/Wireshark.app/Contents/MacOS/tshark; install Wireshark or pass --tshark")
	default:
		return fmt.Errorf("tshark not found in PATH; install wireshark/tshark or pass --tshark")
	}
}
