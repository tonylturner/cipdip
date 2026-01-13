package tui

import (
	"context"
	"fmt"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tturner/cipdip/internal/ui"
)

// PCAPRunConfig contains the configuration for a PCAP operation.
type PCAPRunConfig struct {
	Mode        string // summary, report, coverage, replay, rewrite, dump, diff
	InputFile   string
	InputFile2  string // For diff mode
	OutputDir   string
	Directory   string // For report/coverage directory mode
	UseDir      bool
	ServiceCode string // For dump mode

	// Replay options
	TargetIP      string
	RewriteIP     bool
	RewriteMAC    bool
	PreserveTiming bool
	AppLayerOnly  bool
}

// startPCAPRunMsg signals the model to start a PCAP operation.
type startPCAPRunMsg struct {
	config PCAPRunConfig
}

// pcapRunResultMsg is the bubbletea message for PCAP run completion.
type pcapRunResultMsg struct {
	output   string
	exitCode int
	err      error
}

// BuildCommandArgs builds CLI arguments from the config.
func (cfg PCAPRunConfig) BuildCommandArgs() []string {
	switch cfg.Mode {
	case "summary":
		return []string{"cipdip", "pcap-summary", "--input", cfg.InputFile}

	case "report":
		if cfg.UseDir {
			return []string{"cipdip", "pcap-report", "--directory", cfg.Directory}
		}
		return []string{"cipdip", "pcap-report", "--input", cfg.InputFile}

	case "coverage":
		if cfg.UseDir {
			return []string{"cipdip", "pcap-coverage", "--directory", cfg.Directory}
		}
		return []string{"cipdip", "pcap-coverage", "--input", cfg.InputFile}

	case "replay":
		args := []string{"cipdip", "pcap-replay", "--input", cfg.InputFile}
		if cfg.TargetIP != "" {
			args = append(args, "--target", cfg.TargetIP)
		}
		if cfg.RewriteIP {
			args = append(args, "--rewrite-ip")
		}
		if cfg.RewriteMAC {
			args = append(args, "--rewrite-mac")
		}
		if cfg.PreserveTiming {
			args = append(args, "--timing")
		}
		if cfg.AppLayerOnly {
			args = append(args, "--app-only")
		}
		return args

	case "rewrite":
		args := []string{"cipdip", "pcap-rewrite", "--input", cfg.InputFile}
		if cfg.OutputDir != "" {
			args = append(args, "--output-dir", cfg.OutputDir)
		}
		return args

	case "dump":
		args := []string{"cipdip", "pcap-dump", "--input", cfg.InputFile}
		if cfg.ServiceCode != "" {
			// Parse service code (could be hex like 0x0E or decimal)
			args = append(args, "--service", cfg.ServiceCode)
		}
		return args

	case "diff":
		return []string{"cipdip", "pcap-diff", "--baseline", cfg.InputFile, "--compare", cfg.InputFile2}

	default:
		return []string{"cipdip", "pcap-summary", "--input", cfg.InputFile}
	}
}

// StartPCAPRunCmd returns a tea.Cmd that starts the PCAP operation.
func StartPCAPRunCmd(ctx context.Context, cfg PCAPRunConfig) tea.Cmd {
	return func() tea.Msg {
		args := cfg.BuildCommandArgs()
		command := ui.CommandSpec{Args: args}

		// PCAP operations are typically quick, so we use simple execution
		stdout, exitCode, err := ui.ExecuteCommand(ctx, command)

		return pcapRunResultMsg{
			output:   stdout,
			exitCode: exitCode,
			err:      err,
		}
	}
}

// BuildPCAPRunConfig creates a PCAPRunConfig from the panel state.
func (p *PCAPPanel) BuildPCAPRunConfig(workspaceRoot string) PCAPRunConfig {
	cfg := PCAPRunConfig{
		OutputDir: workspaceRoot,
	}

	// Set mode based on modeIndex
	modes := []string{"summary", "report", "coverage", "replay", "rewrite", "dump", "diff"}
	if p.modeIndex < len(modes) {
		cfg.Mode = modes[p.modeIndex]
	} else {
		cfg.Mode = "summary"
	}

	// Set input file
	if len(p.files) > 0 && p.selectedFile < len(p.files) {
		cfg.InputFile = p.files[p.selectedFile]
	}

	// Handle mode-specific options
	switch cfg.Mode {
	case "diff":
		if len(p.files) > p.diffFile1 {
			cfg.InputFile = p.files[p.diffFile1]
		}
		if len(p.files) > p.diffFile2 {
			cfg.InputFile2 = p.files[p.diffFile2]
		}

	case "replay":
		cfg.TargetIP = p.replayTargetIP
		cfg.RewriteIP = p.replayRewriteIP
		cfg.RewriteMAC = p.replayRewriteMAC
		cfg.PreserveTiming = p.replayTiming
		cfg.AppLayerOnly = p.replayAppOnly

	case "dump":
		cfg.ServiceCode = p.dumpServiceCode

	case "report", "coverage":
		cfg.UseDir = p.useDirectory
		cfg.Directory = p.directory
	}

	return cfg
}

// Helper to parse service code from string (handles 0x prefix)
func parseServiceCode(s string) (int, error) {
	s = string([]byte(s)) // ensure clean string
	if len(s) > 2 && s[:2] == "0x" {
		val, err := strconv.ParseInt(s[2:], 16, 32)
		return int(val), err
	}
	return strconv.Atoi(s)
}

// FormatPCAPOutput formats PCAP command output for display.
func FormatPCAPOutput(output string, mode string) string {
	// Filter out any JSON lines that might be in the output
	return filterOutputForDisplay(output)
}

// GeneratePCAPOutputFilename generates an output filename for PCAP operations.
func GeneratePCAPOutputFilename(cfg PCAPRunConfig, workspaceRoot string) string {
	if workspaceRoot == "" {
		return ""
	}

	switch cfg.Mode {
	case "rewrite":
		// Rewrite generates a new PCAP file
		return fmt.Sprintf("%s/pcaps/%s_rewritten.pcap", workspaceRoot, cfg.InputFile)
	default:
		return ""
	}
}
