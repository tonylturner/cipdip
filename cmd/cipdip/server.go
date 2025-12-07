package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/capture"
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
}

func newServerCmd() *cobra.Command {
	flags := &serverFlags{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run in server/emulator mode",
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
			err := runServer(flags)
			if err != nil {
				// Runtime errors should exit with code 2
				os.Exit(2)
			}
			return nil
		},
	}

	// Optional flags
	cmd.Flags().StringVar(&flags.listenIP, "listen-ip", "0.0.0.0", "Listen IP address (default \"0.0.0.0\")")
	cmd.Flags().IntVar(&flags.listenPort, "listen-port", 44818, "Listen port (default 44818)")
	cmd.Flags().StringVar(&flags.personality, "personality", "adapter", "Server personality: adapter|logix_like (default \"adapter\")")
	cmd.Flags().StringVar(&flags.serverConfig, "server-config", "cipdip_server.yaml", "Server config file path (default \"cipdip_server.yaml\")")
	cmd.Flags().BoolVar(&flags.enableUDPIO, "enable-udp-io", false, "Enable UDP I/O on port 2222 (default false)")
	cmd.Flags().StringVar(&flags.pcapFile, "pcap", "", "Capture packets to PCAP file (e.g., server_capture.pcap)")

	return cmd
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

	// Create logger
	logger, err := logging.NewLogger(logging.LogLevelInfo, "")
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}

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
