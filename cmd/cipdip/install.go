package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

type installFlags struct {
	binaryPath string
	force      bool
}

func newInstallCmd() *cobra.Command {
	flags := &installFlags{}

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install cipdip binary and shell completion",
		Long: `Install the cipdip binary to a directory in your PATH and set up shell completion.

This command:
  1. Detects a suitable directory in your PATH (e.g., /usr/local/bin, ~/bin)
  2. Copies the cipdip binary to that directory
  3. Detects your shell (zsh, bash, fish, PowerShell)
  4. Generates and installs tab completion scripts

After installation, you can:
  - Run 'cipdip' from anywhere (it's in your PATH)
  - Use tab completion for commands and flags
  - Get command suggestions when typing

The command will prompt before overwriting existing files unless --force is used.
On macOS/Linux, you may need to add the completion directory to your shell config
if it's not already configured (the command will provide instructions).

Supported shells:
  - zsh (macOS default, Linux)
  - bash (Linux, macOS)
  - fish (Linux, macOS)
  - PowerShell (Windows)`,
		Example: `  # Install to auto-detected PATH directory
  cipdip install

  # Install to specific directory
  cipdip install --binary-path /usr/local/bin

  # Force overwrite existing files
  cipdip install --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(flags)
		},
	}

	cmd.Flags().StringVar(&flags.binaryPath, "binary-path", "", "Custom path to install binary (default: auto-detect PATH directory)")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite existing binary and completion files")

	return cmd
}

func runInstall(flags *installFlags) error {
	// Detect current binary path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get current binary path: %w", err)
	}

	// Resolve absolute path
	currentBinary, err = filepath.Abs(currentBinary)
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}

	// Determine install directory
	installDir, err := getInstallDirectory(flags.binaryPath)
	if err != nil {
		return fmt.Errorf("get install directory: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Installing cipdip to %s\n", installDir)

	// Create install directory if it doesn't exist
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("create install directory: %w", err)
	}

	// Install binary
	installPath := filepath.Join(installDir, "cipdip")
	if runtime.GOOS == "windows" {
		installPath += ".exe"
	}

	// Check if binary already exists
	if _, err := os.Stat(installPath); err == nil && !flags.force {
		return fmt.Errorf("binary already exists at %s (use --force to overwrite)", installPath)
	}

	// Copy binary
	if err := copyFile(currentBinary, installPath); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}

	// Make executable (Unix-like systems)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(installPath, 0755); err != nil {
			return fmt.Errorf("make binary executable: %w", err)
		}
	}

	fmt.Fprintf(os.Stdout, "Binary installed to %s\n", installPath)

	// Detect shell and install completion
	shell := detectShell()
	if shell == "" {
		fmt.Fprintf(os.Stderr, "warning: could not detect shell, skipping completion installation\n")
		fmt.Fprintf(os.Stdout, "Installation complete! (binary only)\n")
		return nil
	}

	fmt.Fprintf(os.Stdout, "Detected shell: %s\n", shell)

	// Install shell completion (non-fatal if it fails)
	if err := installShellCompletion(shell, installPath, flags.force); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to install shell completion: %v\n", err)
		fmt.Fprintf(os.Stderr, "Binary installation succeeded. You can manually install completion later.\n")
		fmt.Fprintf(os.Stdout, "Installation complete! (binary only, completion skipped)\n")
		return nil
	}

	fmt.Fprintf(os.Stdout, "Installation complete!\n")
	
	// Provide instructions for enabling completion
	sourceFile := getCompletionSourceFile(shell)
	if sourceFile != "" {
		fmt.Fprintf(os.Stdout, "To enable completion, restart your shell or run:\n")
		if shell == "zsh" {
			fmt.Fprintf(os.Stdout, "  source %s\n", sourceFile)
		} else if shell == "bash" {
			fmt.Fprintf(os.Stdout, "  source %s\n", sourceFile)
		} else if shell == "fish" {
			fmt.Fprintf(os.Stdout, "  (completion should work automatically)\n")
		} else if shell == "powershell" {
			fmt.Fprintf(os.Stdout, "  (restart PowerShell to load profile)\n")
		}
	}

	return nil
}

func getInstallDirectory(customPath string) (string, error) {
	if customPath != "" {
		return customPath, nil
	}

	// Get PATH environment variable
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", fmt.Errorf("PATH environment variable not set")
	}

	// Split PATH and find first writable directory
	paths := strings.Split(pathEnv, getPathSeparator())
	for _, p := range paths {
		if p == "" {
			continue
		}

		// Check if directory exists and is writable
		info, err := os.Stat(p)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			continue
		}

		// Try to create a test file to check write permissions
		testFile := filepath.Join(p, ".cipdip-test")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			continue
		}
		os.Remove(testFile)

		return p, nil
	}

	// Fallback to common directories
	if runtime.GOOS == "windows" {
		// Try common Windows locations
		homeDir, err := os.UserHomeDir()
		if err == nil {
			localBin := filepath.Join(homeDir, "AppData", "Local", "bin")
			return localBin, nil
		}
		return "", fmt.Errorf("no writable directory found in PATH")
	}

	// Unix-like: try /usr/local/bin, ~/bin, ~/.local/bin
	homeDir, err := os.UserHomeDir()
	if err == nil {
		// Try ~/.local/bin first (user-specific)
		localBin := filepath.Join(homeDir, ".local", "bin")
		if err := os.MkdirAll(localBin, 0755); err == nil {
			return localBin, nil
		}

		// Try ~/bin
		homeBin := filepath.Join(homeDir, "bin")
		if err := os.MkdirAll(homeBin, 0755); err == nil {
			return homeBin, nil
		}
	}

	// Try /usr/local/bin (requires sudo, but common)
	return "/usr/local/bin", nil
}

func getPathSeparator() string {
	if runtime.GOOS == "windows" {
		return ";"
	}
	return ":"
}

func detectShell() string {
	// Check SHELL environment variable (Unix-like systems)
	shell := os.Getenv("SHELL")
	if shell != "" {
		base := filepath.Base(shell)
		baseLower := strings.ToLower(base)
		if strings.Contains(baseLower, "zsh") {
			return "zsh"
		}
		if strings.Contains(baseLower, "bash") {
			return "bash"
		}
		if strings.Contains(baseLower, "fish") {
			return "fish"
		}
	}

	// On Windows, check COMSPEC and PSModulePath
	if runtime.GOOS == "windows" {
		// Check for PowerShell
		psModulePath := os.Getenv("PSModulePath")
		if psModulePath != "" {
			return "powershell"
		}
		
		comspec := os.Getenv("COMSPEC")
		if strings.Contains(strings.ToLower(comspec), "powershell") {
			return "powershell"
		}
		
		// Check for Git Bash or other bash on Windows
		if shell != "" && strings.Contains(strings.ToLower(shell), "bash") {
			return "bash"
		}
		
		// Default to cmd.exe (though completion may not work well)
		return "cmd"
	}

	// On macOS, default to zsh if SHELL is not set (macOS Catalina+ uses zsh by default)
	if runtime.GOOS == "darwin" {
		return "zsh"
	}

	// On Linux, default to bash
	if runtime.GOOS == "linux" {
		return "bash"
	}

	// Unknown system
	return ""
}

func installShellCompletion(shell, binaryPath string, force bool) error {
	switch shell {
	case "zsh":
		return installZshCompletion(binaryPath, force)
	case "bash":
		return installBashCompletion(binaryPath, force)
	case "fish":
		return installFishCompletion(binaryPath, force)
	case "powershell":
		return installPowershellCompletion(binaryPath, force)
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}
}

func installZshCompletion(binaryPath string, force bool) error {
	// Get zsh completion directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	completionDir := filepath.Join(homeDir, ".zsh", "completions")
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("create completion directory: %w", err)
	}

	completionFile := filepath.Join(completionDir, "_cipdip")

	// Check if file exists
	if _, err := os.Stat(completionFile); err == nil && !force {
		return fmt.Errorf("completion file already exists at %s (use --force to overwrite)", completionFile)
	}

	// Generate completion script using Cobra's completion command
	// Note: Cobra uses "completion zsh" format
	cmd := exec.Command(binaryPath, "completion", "zsh")
	output, err := cmd.Output()
	if err != nil {
		// If completion command fails, try to get stderr for better error message
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("generate zsh completion: %s", string(exitErr.Stderr))
		}
		return fmt.Errorf("generate zsh completion: %w", err)
	}

	// Write completion file
	if err := os.WriteFile(completionFile, output, 0644); err != nil {
		return fmt.Errorf("write completion file: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Zsh completion installed to %s\n", completionFile)
	return nil
}

func installBashCompletion(binaryPath string, force bool) error {
	// Get bash completion directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Try ~/.local/share/bash-completion/completions (user-specific)
	completionDir := filepath.Join(homeDir, ".local", "share", "bash-completion", "completions")
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		// Fallback to system directory (requires sudo)
		completionDir = "/etc/bash_completion.d"
	}

	completionFile := filepath.Join(completionDir, "cipdip")

	// Check if file exists
	if _, err := os.Stat(completionFile); err == nil && !force {
		return fmt.Errorf("completion file already exists at %s (use --force to overwrite)", completionFile)
	}

	// Generate completion script using Cobra's completion command
	cmd := exec.Command(binaryPath, "completion", "bash")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("generate bash completion: %s", string(exitErr.Stderr))
		}
		return fmt.Errorf("generate bash completion: %w", err)
	}

	// Write completion file
	if err := os.WriteFile(completionFile, output, 0644); err != nil {
		return fmt.Errorf("write completion file: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Bash completion installed to %s\n", completionFile)
	return nil
}

func installFishCompletion(binaryPath string, force bool) error {
	// Get fish completion directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	completionDir := filepath.Join(homeDir, ".config", "fish", "completions")
	if err := os.MkdirAll(completionDir, 0755); err != nil {
		return fmt.Errorf("create completion directory: %w", err)
	}

	completionFile := filepath.Join(completionDir, "cipdip.fish")

	// Check if file exists
	if _, err := os.Stat(completionFile); err == nil && !force {
		return fmt.Errorf("completion file already exists at %s (use --force to overwrite)", completionFile)
	}

	// Generate completion script using Cobra's completion command
	cmd := exec.Command(binaryPath, "completion", "fish")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("generate fish completion: %s", string(exitErr.Stderr))
		}
		return fmt.Errorf("generate fish completion: %w", err)
	}

	// Write completion file
	if err := os.WriteFile(completionFile, output, 0644); err != nil {
		return fmt.Errorf("write completion file: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Fish completion installed to %s\n", completionFile)
	return nil
}

func installPowershellCompletion(binaryPath string, force bool) error {
	// PowerShell completion is more complex, using profiles
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home directory: %w", err)
	}

	// Get PowerShell profile path
	profilePath := filepath.Join(homeDir, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1")
	if runtime.GOOS == "windows" {
		// Windows PowerShell
		profilePath = filepath.Join(homeDir, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
	}

	// Generate completion script using Cobra's completion command
	cmd := exec.Command(binaryPath, "completion", "powershell")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("generate powershell completion: %s", string(exitErr.Stderr))
		}
		return fmt.Errorf("generate powershell completion: %w", err)
	}

	// Check if profile exists and contains our completion
	profileContent := ""
	if data, err := os.ReadFile(profilePath); err == nil {
		profileContent = string(data)
		if strings.Contains(profileContent, "cipdip") && !force {
			return fmt.Errorf("completion already in profile (use --force to overwrite)")
		}
	}

	// Append completion to profile
	completionBlock := fmt.Sprintf("\n# cipdip completion\n%s\n", string(output))
	profileContent += completionBlock

	// Create profile directory if needed
	if err := os.MkdirAll(filepath.Dir(profilePath), 0755); err != nil {
		return fmt.Errorf("create profile directory: %w", err)
	}

	// Write profile
	if err := os.WriteFile(profilePath, []byte(profileContent), 0644); err != nil {
		return fmt.Errorf("write profile: %w", err)
	}

	fmt.Fprintf(os.Stdout, "PowerShell completion added to %s\n", profilePath)
	return nil
}

func getCompletionSourceFile(shell string) string {
	homeDir, _ := os.UserHomeDir()
	switch shell {
	case "zsh":
		return filepath.Join(homeDir, ".zshrc")
	case "bash":
		return filepath.Join(homeDir, ".bashrc")
	case "fish":
		return filepath.Join(homeDir, ".config", "fish", "config.fish")
	default:
		return ""
	}
}

func copyFile(src, dst string) error {
	// Read source file
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	// Write destination file
	return os.WriteFile(dst, data, 0644)
}

