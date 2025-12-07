package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
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
}

func newServerCmd() *cobra.Command {
	flags := &serverFlags{}

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run in server/emulator mode",
		Long: `Act as an EtherNet/IP / CIP endpoint (emulator) that clients can connect to.
Supports adapter and logix_like personalities.`,
		Example: `  cipdip server --personality adapter
  cipdip server --personality logix_like --listen-ip 0.0.0.0 --enable-udp-io`,
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

	return cmd
}

func runServer(flags *serverFlags) error {
	// Validate personality
	if flags.personality != "adapter" && flags.personality != "logix_like" {
		return fmt.Errorf("invalid personality '%s'; must be 'adapter' or 'logix_like'", flags.personality)
	}

	// Load server config
	cfg, err := config.LoadServerConfig(flags.serverConfig)
	if err != nil {
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
		return fmt.Errorf("start server: %w", err)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for signal
	<-sigChan

	// Stop server
	if err := srv.Stop(); err != nil {
		return fmt.Errorf("stop server: %w", err)
	}

	return nil
}

