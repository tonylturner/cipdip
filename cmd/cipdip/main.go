package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
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

	// Custom help command
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		// Print short top-level usage
		fmt.Fprintf(os.Stdout, "Usage:\n  %s <command> [arguments] [options]\n\n", cmd.Name())
		fmt.Fprintf(os.Stdout, "Available Commands:\n")
		for _, subCmd := range cmd.Commands() {
			if !subCmd.Hidden {
				fmt.Fprintf(os.Stdout, "  %-15s %s\n", subCmd.Name(), subCmd.Short)
			}
		}
		fmt.Fprintf(os.Stdout, "\nUse \"%s help <command>\" for more information about a command.\n", cmd.Name())
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
