package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
			return runServer(flags)
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

	// TODO: Load server config
	// TODO: Initialize server
	// TODO: Start listening

	fmt.Fprintf(os.Stderr, "error: server mode not yet fully implemented\n")
	return fmt.Errorf("server mode not yet fully implemented")
}

