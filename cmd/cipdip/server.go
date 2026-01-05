package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/capture"
	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/server"
)

type serverFlags struct {
	listenIP     string
	listenPort   int
	personality  string
	serverConfig string
	enableUDPIO  bool
	pcapFile     string
	cipProfile   string
	mode         string
	target       string
	logFormat    string
	logLevel     string
	logEvery     int
}

func newServerCmd() *cobra.Command {
	flags := &serverFlags{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server/emulator commands",
		Long: `Run CIPDIP as an EtherNet/IP / CIP endpoint (emulator) that other CIP clients can connect to.

This command starts a CIP server that responds to CIP requests, allowing you to test
client behavior or act as a target for DPI testing. The server supports two personalities:

  adapter      - Assembly-style object model (like CLICK PLCs)
                 Responds to Get/Set Attribute Single requests on configured assemblies
                 
  logix_like    - Tag-based interface (like Allen-Bradley Logix controllers)
                 Responds to tag read/write requests

The server listens on TCP port 44818 for explicit messaging. Optionally, you can enable
UDP port 2222 for Class 1 I/O (implicit messaging) using --enable-udp-io.

Configuration is loaded from cipdip_server.yaml (or --server-config). The config file
defines which assemblies or tags are available and how they behave.

Press Ctrl+C to stop the server gracefully.`,
		Example: `  # Start adapter personality server (default)
  cipdip server

  # Start logix_like personality server
  cipdip server --personality logix_like

  # Start server with UDP I/O enabled
  cipdip server --enable-udp-io

  # Start server on specific IP and port
  cipdip server --listen-ip 192.168.1.100 --listen-port 44818

  # Use custom config file
  cipdip server --server-config ./my_server.yaml

  # Capture packets to PCAP file
  cipdip server --pcap server_capture.pcap`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			err := runServer(flags)
			if err != nil {
				// Runtime errors should exit with code 2
				os.Exit(2)
			}
			return nil
		},
	}

	registerServerFlags(cmd, flags)

	cmd.AddCommand(newServerStartCmd(flags))
	cmd.AddCommand(newServerTargetsCmd())
	cmd.AddCommand(newServerModesCmd())
	cmd.AddCommand(newServerValidateCmd())
	cmd.AddCommand(newServerPrintDefaultCmd())

	return cmd
}

func newServerStartCmd(flags *serverFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			return runServer(flags)
		},
	}
	registerServerFlags(cmd, flags)
	return cmd
}

func newServerTargetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "targets",
		Short: "List available server targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			targets := server.AvailableServerTargets()
			fmt.Fprintln(os.Stdout, "Available targets:")
			for _, target := range targets {
				fmt.Fprintf(os.Stdout, "  %s: %s\n", target.Name, target.Description)
			}
			return nil
		},
	}
}

func newServerModesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modes",
		Short: "List available server modes",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stdout, "Available modes:")
			fmt.Fprintln(os.Stdout, "  baseline     - strict parsing, no faults")
			fmt.Fprintln(os.Stdout, "  realistic    - baseline with discovery enabled")
			fmt.Fprintln(os.Stdout, "  dpi-torture  - jitter, spikes, chunked TCP, drops")
			fmt.Fprintln(os.Stdout, "  perf         - minimal logging, deterministic behavior")
			return nil
		},
	}
}

func newServerValidateCmd() *cobra.Command {
	var cfgPath string
	cmd := &cobra.Command{
		Use:   "validate-config",
		Short: "Validate a server config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgPath == "" {
				cfgPath = "cipdip_server.yaml"
			}
			if _, err := config.LoadServerConfig(cfgPath); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "Config OK: %s\n", cfgPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "Server config file path")
	return cmd
}

func newServerPrintDefaultCmd() *cobra.Command {
	var mode string
	var target string
	cmd := &cobra.Command{
		Use:   "print-default-config",
		Short: "Print a default server config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.CreateDefaultServerConfig()
			if target != "" {
				if err := server.ApplyServerTarget(cfg, target); err != nil {
					return err
				}
			}
			if mode != "" {
				if err := applyServerMode(cfg, mode); err != nil {
					return err
				}
			}
			out, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("marshal config: %w", err)
			}
			fmt.Fprintln(os.Stdout, string(out))
			return nil
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "", "Mode preset: baseline|realistic|dpi-torture|perf")
	cmd.Flags().StringVar(&target, "target", "", "Target preset name")
	return cmd
}

func registerServerFlags(cmd *cobra.Command, flags *serverFlags) {
	cmd.Flags().StringVar(&flags.listenIP, "listen-ip", "0.0.0.0", "Listen IP address (default \"0.0.0.0\")")
	cmd.Flags().IntVar(&flags.listenPort, "listen-port", 44818, "Listen port (default 44818)")
	cmd.Flags().StringVar(&flags.personality, "personality", "adapter", "Server personality: adapter|logix_like (default \"adapter\")")
	cmd.Flags().StringVar(&flags.serverConfig, "server-config", "cipdip_server.yaml", "Server config file path (default \"cipdip_server.yaml\")")
	cmd.Flags().BoolVar(&flags.enableUDPIO, "enable-udp-io", false, "Enable UDP I/O on port 2222 (default false)")
	cmd.Flags().StringVar(&flags.pcapFile, "pcap", "", "Capture packets to PCAP file (e.g., server_capture.pcap)")
	cmd.Flags().StringVar(&flags.cipProfile, "cip-profile", "", "CIP application profile(s): energy|safety|motion|all (comma-separated)")
	cmd.Flags().StringVar(&flags.mode, "mode", "", "Mode preset: baseline|realistic|dpi-torture|perf")
	cmd.Flags().StringVar(&flags.target, "target", "", "Target preset name")
	cmd.Flags().StringVar(&flags.logFormat, "log-format", "", "Log format override: text|json")
	cmd.Flags().StringVar(&flags.logLevel, "log-level", "", "Log level override: error|info|verbose|debug")
	cmd.Flags().IntVar(&flags.logEvery, "log-every-n", 0, "Log every N events (override)")
}

func runServer(flags *serverFlags) error {
	// Start packet capture if requested
	var pcapCapture *capture.Capture
	if flags.pcapFile != "" {
		fmt.Fprintf(os.Stdout, "Starting packet capture: %s\n", flags.pcapFile)
		var err error
		pcapCapture, err = capture.StartCaptureLoopback(flags.pcapFile)
		if err != nil {
			return fmt.Errorf("start packet capture: %w", err)
		}
		defer pcapCapture.Stop()
	}

	// Print startup message to stdout FIRST (so user sees it immediately)
	fmt.Fprintf(os.Stdout, "CIPDIP Server starting...\n")
	fmt.Fprintf(os.Stdout, "  Personality: %s\n", flags.personality)
	fmt.Fprintf(os.Stdout, "  Config: %s\n", flags.serverConfig)
	fmt.Fprintf(os.Stdout, "  Listening on: %s:%d\n", flags.listenIP, flags.listenPort)
	if flags.enableUDPIO {
		fmt.Fprintf(os.Stdout, "  UDP I/O enabled on port 2222\n")
	}
	if flags.pcapFile != "" {
		fmt.Fprintf(os.Stdout, "  PCAP: %s\n", flags.pcapFile)
	}
	fmt.Fprintf(os.Stdout, "  Press Ctrl+C to stop\n\n")
	os.Stdout.Sync() // Flush output immediately

	// Validate personality
	if flags.personality != "adapter" && flags.personality != "logix_like" {
		return fmt.Errorf("invalid personality '%s'; must be 'adapter' or 'logix_like'", flags.personality)
	}

	// Load server config
	cfg, err := config.LoadServerConfig(flags.serverConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load server config: %v\n", err)
		return fmt.Errorf("load server config: %w", err)
	}
	if flags.target != "" {
		if err := server.ApplyServerTarget(cfg, flags.target); err != nil {
			return err
		}
	}
	if flags.mode != "" {
		if err := applyServerMode(cfg, flags.mode); err != nil {
			return err
		}
	}
	if flags.cipProfile != "" {
		profiles := cipclient.NormalizeCIPProfiles(parseProfileFlag(flags.cipProfile))
		cfg.CIPProfiles = mergeProfiles(cfg.CIPProfiles, profiles)
	}

	profile := cipclient.ResolveProtocolProfile(
		cfg.Protocol.Mode,
		cfg.Protocol.Variant,
		cfg.Protocol.Overrides.ENIPEndianness,
		cfg.Protocol.Overrides.CIPEndianness,
		cfg.Protocol.Overrides.CIPPathSize,
		cfg.Protocol.Overrides.CIPResponseReserved,
		cfg.Protocol.Overrides.UseCPF,
		cfg.Protocol.Overrides.IOSequenceMode,
	)
	cipclient.SetProtocolProfile(profile)

	// Override config with CLI flags
	if flags.listenIP != "" {
		cfg.Server.ListenIP = flags.listenIP
	}
	if flags.listenPort != 0 {
		cfg.Server.TCPPort = flags.listenPort
	}
	if flags.personality != "" {
		cfg.Server.Personality = flags.personality
	}
	if flags.enableUDPIO {
		cfg.Server.EnableUDPIO = true
	}
	if flags.logFormat != "" {
		cfg.Logging.Format = flags.logFormat
	}
	if flags.logLevel != "" {
		cfg.Logging.Level = flags.logLevel
	}
	if flags.logEvery > 0 {
		cfg.Logging.LogEveryN = flags.logEvery
	}

	// Create logger
	logger, err := logging.NewLoggerWithOptions(logging.LogLevelInfo, cfg.Logging.LogFile, cfg.Logging.Format, cfg.Logging.LogEveryN)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	logger.SetLevel(parseLogLevel(cfg.Logging.Level))

	// Create server
	srv, err := server.NewServer(cfg, logger)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	// Start server
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to start server: %v\n", err)
		return fmt.Errorf("start server: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Server started successfully\n")

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for signal
	<-sigChan

	fmt.Fprintf(os.Stdout, "\nShutting down server...\n")

	// Stop server
	if err := srv.Stop(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	// Stop capture and report
	if pcapCapture != nil {
		pcapCapture.Stop()
		packetCount := pcapCapture.GetPacketCount()
		fmt.Fprintf(os.Stdout, "Packets captured: %d (%s)\n", packetCount, flags.pcapFile)
	}

	return nil
}

func parseLogLevel(value string) logging.LogLevel {
	switch value {
	case "error":
		return logging.LogLevelError
	case "verbose":
		return logging.LogLevelVerbose
	case "debug":
		return logging.LogLevelDebug
	default:
		return logging.LogLevelInfo
	}
}

func applyServerMode(cfg *config.ServerConfig, mode string) error {
	switch mode {
	case "baseline":
		cfg.Faults.Enable = false
		cfg.Logging.Level = "info"
		cfg.Logging.LogEveryN = 1
	case "realistic":
		cfg.Faults.Enable = false
		cfg.Logging.Level = "info"
		cfg.Logging.LogEveryN = 1
	case "dpi-torture":
		cfg.Faults.Enable = true
		cfg.Faults.Latency.BaseDelayMs = 5
		cfg.Faults.Latency.JitterMs = 10
		cfg.Faults.Latency.SpikeEveryN = 10
		cfg.Faults.Latency.SpikeDelayMs = 25
		cfg.Faults.Reliability.DropResponseEveryN = 25
		cfg.Faults.Reliability.CloseConnectionEveryN = 50
		cfg.Faults.TCP.ChunkWrites = true
		cfg.Faults.TCP.ChunkMin = 2
		cfg.Faults.TCP.ChunkMax = 4
	case "perf":
		cfg.Faults.Enable = false
		cfg.Logging.Level = "error"
		cfg.Logging.LogEveryN = 100
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	return nil
}


