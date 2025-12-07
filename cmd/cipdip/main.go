package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "0.1"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cipdip",
		Short: "CIP/EtherNet-IP Scanner for DPI Testing",
		Long: `CIPDIP is a command-line tool to generate repeatable, controllable
CIP/EtherNet-IP traffic for firewall DPI research testing.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Add subcommands
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newClientCmd())
	rootCmd.AddCommand(newServerCmd())
	rootCmd.AddCommand(newDiscoverCmd())
	rootCmd.AddCommand(newInstallCmd())
	rootCmd.AddCommand(newPcapCmd())
	rootCmd.AddCommand(newTestCmd())

	// Let Cobra handle help automatically - it will show flags and detailed descriptions

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		// Exit code 1 for CLI/usage errors (invalid flags, missing args, etc.)
		// Exit code 2 is handled by individual commands for runtime errors
		os.Exit(1)
	}
}
